<?php

declare(strict_types=1);

namespace Manager2\Credit;

use Manager2\Audit\AuditLog;
use Manager2\Crypto\FieldCipher;
use Manager2\Notify\Notification;
use Manager2\Notify\OpsNotifier;
use Manager2\Support\Db;
use Manager2\Support\Uuid;
use PDO;

/**
 * Credit scoring and payment-terms decisions.
 *
 * Assessing whether a trade customer pays on time is ordinary, legitimate
 * commercial risk management. Two things make it lawful rather than a
 * blacklist, and both are structural here rather than left to policy:
 *
 * 1. ART. 22 — automated decisions with significant effect.
 *    Refusing credit terms materially affects a business, so where the decision
 *    is made without human involvement the customer is entitled to be told,
 *    to receive meaningful information about the logic, to express a view, to
 *    obtain human intervention, and to contest the outcome. Hence:
 *      - `factors_json` records the actual inputs and their weights, so the
 *        explanation given to the customer is generated from the decision, not
 *        written afterwards by someone guessing.
 *      - `requestReview()` and `recordHumanReview()` implement the right to
 *        human intervention as a workflow with a deadline, not a mailbox.
 *      - The customer is notified. An automated decision nobody is told about
 *        cannot be contested.
 *
 * 2. IT SCORES BEHAVIOUR, NOT PEOPLE.
 *    Inputs are the account's own payment record with us: days-sales-
 *    outstanding, overdue balance, dishonoured payments, order history. No
 *    third-party profiling, no data about the individual buyer, no proxies for
 *    protected characteristics, no inference from location or sector. The
 *    subject of the decision is the company, and the evidence is its conduct.
 *
 * The distinction from a dealer's "reliability blacklist" is not cosmetic. This
 * is explainable, contestable, reviewable, scoped to payment conduct, and
 * disclosed to the customer. A blacklist is none of those things.
 */
final class CreditDecisionService
{
    /** Below this score, terms are withdrawn and prepayment required. */
    private const PREPAY_THRESHOLD = 40;

    /** Below this score, the limit is reduced rather than withdrawn. */
    private const REDUCE_THRESHOLD = 65;

    /** Human review promise, in days. Set it, publish it, meet it. */
    private const REVIEW_SLA_DAYS = 14;

    public function __construct(
        private readonly PDO $pdo,
        private readonly FieldCipher $cipher,
        private readonly AuditLog $audit,
        private readonly OpsNotifier $notifier
    ) {
    }

    /**
     * Score an account's payment conduct.
     *
     * Returns the score with the factors that produced it. Every factor carries
     * its observed value, its weight and a plain-language explanation — that
     * text is what the customer is shown, so it has to make sense to someone
     * who is not looking at this code.
     *
     * @return array{score:int, factors:list<array<string, mixed>>, observations:array<string, mixed>}
     */
    public function score(string $orgId): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT
                COUNT(DISTINCT i.id) AS invoice_count,
                COALESCE(SUM(CASE WHEN i.status = 'overdue' THEN i.gross_cents END), 0)
                    AS overdue_cents,
                COUNT(DISTINCT CASE WHEN i.status = 'overdue' THEN i.id END)
                    AS overdue_count,
                COUNT(DISTINCT CASE WHEN i.settled_at IS NOT NULL THEN i.id END)
                    AS settled_count,
                COALESCE(MAX(CASE WHEN i.settled_at IS NULL AND i.status = 'overdue'
                    THEN DATEDIFF(CURDATE(), i.due_date) END), 0) AS days_outstanding,
                COALESCE(AVG(CASE WHEN i.settled_at IS NOT NULL
                    THEN DATEDIFF(i.settled_at, i.due_date) END), 0) AS avg_days_late,
                COALESCE(MAX(CASE WHEN i.settled_at IS NOT NULL
                    THEN DATEDIFF(i.settled_at, i.due_date) END), 0) AS worst_days_late,
                COALESCE(SUM(i.gross_cents), 0) AS billed_cents,
                MIN(i.issue_date) AS first_invoice_at
               FROM invoices i
              WHERE i.org_id = ? AND i.doc_type = 'invoice' AND i.status <> 'void'"
        );
        $stmt->execute([$orgId]);
        $inv = $stmt->fetch() ?: [];

        $failed = $this->pdo->prepare(
            "SELECT COUNT(*) FROM payments
              WHERE org_id = ? AND status = 'failed'
                AND received_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 365 DAY)"
        );
        $failed->execute([$orgId]);
        $failedPayments = (int) $failed->fetchColumn();

        $observations = [
            'invoices_issued' => (int) ($inv['invoice_count'] ?? 0),
            'invoices_settled' => (int) ($inv['settled_count'] ?? 0),
            'invoices_overdue' => (int) ($inv['overdue_count'] ?? 0),
            'days_outstanding' => (int) ($inv['days_outstanding'] ?? 0),
            'overdue_cents' => (int) ($inv['overdue_cents'] ?? 0),
            'average_days_late' => round((float) ($inv['avg_days_late'] ?? 0), 1),
            'worst_days_late' => (int) ($inv['worst_days_late'] ?? 0),
            'total_billed_cents' => (int) ($inv['billed_cents'] ?? 0),
            'failed_payments_12m' => $failedPayments,
            'relationship_since' => $inv['first_invoice_at'] ?? null,
        ];

        // Start from neutral rather than perfect: a brand-new account has no
        // record, and treating "no evidence of late payment" as "excellent
        // payer" is how unsecured credit gets extended to strangers.
        $score = 70;
        $factors = [];

        $addFactor = static function (
            array &$factors,
            int &$score,
            string $name,
            mixed $value,
            int $weight,
            string $explanation
        ): void {
            $score += $weight;
            $factors[] = [
                'factor' => $name,
                'observed' => $value,
                'weight' => $weight,
                'explanation' => $explanation,
            ];
        };

        if ($observations['invoices_issued'] === 0) {
            $addFactor(
                $factors,
                $score,
                'no_trading_history',
                true,
                -10,
                'No invoices have been issued to this account yet, so there is no '
                . 'payment record to assess. Terms open up as history builds.'
            );
        }

        $avgLate = (float) $observations['average_days_late'];

        // The bonus requires SETTLED invoices, not merely issued ones. AVG over
        // an empty set is 0, so gating on avg_days_late alone scored an account
        // that had never paid anything as a model payer — absence of evidence
        // read as evidence of good conduct, in the direction that extends
        // credit. Getting this backwards is how unsecured exposure accumulates
        // on exactly the accounts that warrant caution.
        if ($observations['invoices_settled'] === 0 && $observations['invoices_issued'] > 0) {
            $addFactor(
                $factors,
                $score,
                'nothing_settled_yet',
                $observations['invoices_issued'],
                -10,
                sprintf(
                    '%d invoice(s) have been issued and none has been settled yet, so '
                    . 'there is no payment record to draw on.',
                    $observations['invoices_issued']
                )
            );
        } elseif ($avgLate <= 0 && $observations['invoices_settled'] > 0) {
            $addFactor(
                $factors,
                $score,
                'pays_on_time',
                $avgLate,
                20,
                'Invoices are settled on or before the due date.'
            );
        } elseif ($avgLate > 0 && $avgLate <= 7) {
            $addFactor($factors, $score, 'pays_slightly_late', $avgLate, 5,
                sprintf('Invoices are settled on average %.1f days after the due date, '
                    . 'which is within normal commercial tolerance.', $avgLate));
        } elseif ($avgLate > 7 && $avgLate <= 30) {
            $addFactor($factors, $score, 'pays_late', $avgLate, -15,
                sprintf('Invoices are settled on average %.1f days late.', $avgLate));
        } elseif ($avgLate > 30) {
            $addFactor($factors, $score, 'pays_very_late', $avgLate, -30,
                sprintf('Invoices are settled on average %.1f days late, which is well '
                    . 'beyond agreed terms.', $avgLate));
        }

        if ($observations['invoices_overdue'] > 0) {
            $weight = -min(30, 8 * $observations['invoices_overdue']);
            $addFactor($factors, $score, 'currently_overdue',
                $observations['invoices_overdue'], $weight,
                sprintf('%d invoice(s) totalling %s EUR are currently past due.',
                    $observations['invoices_overdue'],
                    number_format($observations['overdue_cents'] / 100, 2)));

            $daysOut = $observations['days_outstanding'];

            if ($daysOut > 30) {
                $addFactor($factors, $score, 'long_outstanding', $daysOut,
                    -min(25, (int) floor($daysOut / 15) * 5),
                    sprintf('The oldest unpaid invoice is %d days past its due date.', $daysOut));
            }
        }

        if ($failedPayments > 0) {
            $addFactor($factors, $score, 'failed_payments',
                $failedPayments, -min(20, 7 * $failedPayments),
                sprintf('%d payment attempt(s) failed in the last 12 months.', $failedPayments));
        }

        if ($observations['invoices_settled'] >= 12 && $observations['invoices_overdue'] === 0) {
            $addFactor($factors, $score, 'established_relationship',
                $observations['invoices_settled'], 15,
                sprintf('A settled record across %d invoices with nothing outstanding.',
                    $observations['invoices_settled']));
        }

        return [
            'score' => max(0, min(100, $score)),
            'factors' => $factors,
            'observations' => $observations,
        ];
    }

    /**
     * Assess an account and record the resulting decision.
     *
     * @param bool $automated false when a person is making the call, which takes
     *                        the decision outside Art. 22 entirely
     * @return array{decision:string, score:int, new_limit_cents:int,
     *               requires_notification:bool, explanation:list<string>}
     */
    public function assess(
        string $orgId,
        bool $automated = true,
        ?string $actorId = null
    ): array {
        $assessment = $this->score($orgId);
        $score = $assessment['score'];

        $stmt = $this->pdo->prepare(
            'SELECT credit_limit_cents, payment_terms_days, legal_name, account_ref, status
               FROM organisations WHERE id = ?'
        );
        $stmt->execute([$orgId]);
        $org = $stmt->fetch();

        if ($org === false) {
            throw new \RuntimeException('No such organisation.');
        }

        $currentLimit = (int) $org['credit_limit_cents'];

        [$decision, $newLimit] = match (true) {
            $score < self::PREPAY_THRESHOLD => ['require_prepay', 0],
            $score < self::REDUCE_THRESHOLD => ['reduce_limit', (int) round($currentLimit * 0.5)],
            default => ['approve', $currentLimit],
        };

        $decisionId = Uuid::v7();
        $adverse = $decision !== 'approve';

        Db::transaction($this->pdo, function (PDO $pdo) use (
            $decisionId, $orgId, $decision, $automated, $score, $assessment,
            $currentLimit, $newLimit
        ): void {
            $insert = $pdo->prepare(
                'INSERT INTO credit_decisions
                    (id, org_id, decision, is_automated, score, factors_json,
                     prev_limit_cents, new_limit_cents)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $insert->execute([
                $decisionId,
                $orgId,
                $decision,
                (int) $automated,
                $score,
                json_encode(
                    [
                        'score' => $score,
                        'factors' => $assessment['factors'],
                        'observations' => $assessment['observations'],
                        'thresholds' => [
                            'require_prepay_below' => self::PREPAY_THRESHOLD,
                            'reduce_limit_below' => self::REDUCE_THRESHOLD,
                        ],
                    ],
                    JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
                ),
                $currentLimit,
                $newLimit,
            ]);

            if ($newLimit !== $currentLimit) {
                $pdo->prepare(
                    'UPDATE organisations SET credit_limit_cents = ? WHERE id = ?'
                )->execute([$newLimit, $orgId]);
            }
        });

        $this->audit->record(
            action: 'credit.decision',
            actorId: $actorId,
            entityType: 'organisations',
            entityId: $orgId,
            metadata: [
                'decision' => $decision,
                'score' => $score,
                'automated' => $automated,
                'prev_limit_cents' => $currentLimit,
                'new_limit_cents' => $newLimit,
                'art22_applies' => $automated && $adverse,
            ]
        );

        // Art. 22 bites only where the decision is BOTH automated and adverse.
        if ($automated && $adverse) {
            $this->notifier->dispatch(new Notification(
                subject: 'Automated credit decision requires customer notification',
                summary: 'An automated decision has changed a customer\'s payment terms. '
                    . 'Art. 22 GDPR requires the customer be told, given the reasoning, '
                    . 'and offered human review. Send the notice from the account page.',
                facts: [
                    'account' => (string) $org['account_ref'],
                    'decision' => $decision,
                    'score' => $score,
                    'previous_limit' => number_format($currentLimit / 100, 2),
                    'new_limit' => number_format($newLimit / 100, 2),
                ],
                linkPath: '/manager/accounts/' . rawurlencode((string) $org['account_ref']) . '/credit',
                severity: 'action_required'
            ));
        }

        return [
            'decision' => $decision,
            'score' => $score,
            'new_limit_cents' => $newLimit,
            'requires_notification' => $automated && $adverse,
            'explanation' => $this->explain($decision, $assessment),
        ];
    }

    /**
     * The customer-facing explanation (Arts. 13(2)(f), 15(1)(h), 22(3)).
     *
     * Generated from the recorded factors so it cannot drift from the decision
     * that was actually made.
     *
     * @param array{score:int, factors:list<array<string, mixed>>} $assessment
     * @return list<string>
     */
    public function explain(string $decision, array $assessment): array
    {
        $lines = [match ($decision) {
            'approve' => 'Your credit terms are unchanged.',
            'reduce_limit' => 'Your credit limit has been reduced.',
            'require_prepay' => 'Credit terms have been paused. Orders now require payment '
                . 'in advance.',
            'hold' => 'Your account is on hold pending review.',
            default => 'Your account terms have been reviewed.',
        }];

        $lines[] = 'This decision was based on your account\'s payment record with us, '
            . 'and on nothing else. We do not use credit bureaux, information about '
            . 'individuals, or data from third parties.';

        $lines[] = 'The following factors applied:';

        foreach ($assessment['factors'] as $factor) {
            $direction = ($factor['weight'] ?? 0) >= 0 ? 'in your favour' : 'against';
            $lines[] = sprintf('  - %s (%s)', $factor['explanation'], $direction);
        }

        if ($decision !== 'approve') {
            $lines[] = sprintf(
                'You can ask for this decision to be reviewed by a member of our team, '
                . 'give us your side of it, and contest the outcome. We respond within '
                . '%d days. You can also complain to your data protection authority.',
                self::REVIEW_SLA_DAYS
            );
        }

        return $lines;
    }

    /** Customer exercises the Art. 22(3) right to human intervention. */
    public function requestReview(string $decisionId, string $customerStatement): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE credit_decisions
                SET review_requested_at = UTC_TIMESTAMP(6),
                    review_notes_enc = ?
              WHERE id = ? AND reviewed_at IS NULL'
        );

        $stmt->execute([
            $this->cipher->seal(
                "Customer statement:\n" . $customerStatement,
                'credit_decisions',
                'review_notes_enc',
                $decisionId
            ),
            $decisionId,
        ]);

        if ($stmt->rowCount() !== 1) {
            throw new \RuntimeException('That decision cannot be sent for review.');
        }

        $this->audit->record(
            action: 'credit.review_requested',
            entityType: 'credit_decisions',
            entityId: $decisionId,
            metadata: ['basis' => 'Art. 22(3) GDPR — right to human intervention']
        );

        $this->notifier->dispatch(new Notification(
            subject: 'Credit decision review requested',
            summary: sprintf(
                'A customer has exercised their right to human review of an automated '
                . 'credit decision. Response due within %d days.',
                self::REVIEW_SLA_DAYS
            ),
            facts: ['decision_id' => Uuid::toString($decisionId), 'sla_days' => self::REVIEW_SLA_DAYS],
            linkPath: '/manager/credit/reviews',
            severity: 'action_required'
        ));
    }

    /** A person records their conclusion, overriding the machine if warranted. */
    public function recordHumanReview(
        string $decisionId,
        string $reviewerUserId,
        string $outcome,
        string $notes,
        ?int $revisedLimitCents = null
    ): void {
        if (!in_array($outcome, ['upheld', 'overturned', 'amended'], true)) {
            throw new \InvalidArgumentException("Invalid review outcome '{$outcome}'.");
        }

        Db::transaction($this->pdo, function (PDO $pdo) use (
            $decisionId, $reviewerUserId, $outcome, $notes, $revisedLimitCents
        ): void {
            $stmt = $pdo->prepare(
                'SELECT org_id, review_notes_enc FROM credit_decisions WHERE id = ? FOR UPDATE'
            );
            $stmt->execute([$decisionId]);
            $row = $stmt->fetch();

            if ($row === false) {
                throw new \RuntimeException('No such credit decision.');
            }

            // Append rather than overwrite: the customer's statement is part of
            // the record of how the decision was reached.
            $existing = '';
            if ($row['review_notes_enc'] !== null) {
                try {
                    $existing = $this->cipher->open(
                        (string) $row['review_notes_enc'],
                        'credit_decisions',
                        'review_notes_enc',
                        $decisionId
                    ) . "\n\n";
                } catch (\Throwable) {
                    $existing = "[earlier note could not be decrypted]\n\n";
                }
            }

            $update = $pdo->prepare(
                'UPDATE credit_decisions
                    SET reviewed_by = ?, reviewed_at = UTC_TIMESTAMP(6),
                        review_outcome = ?, review_notes_enc = ?,
                        is_automated = 0,
                        new_limit_cents = COALESCE(?, new_limit_cents)
                  WHERE id = ?'
            );

            $update->execute([
                $reviewerUserId,
                $outcome,
                $this->cipher->seal(
                    $existing . "Reviewer conclusion ({$outcome}):\n" . $notes,
                    'credit_decisions',
                    'review_notes_enc',
                    $decisionId
                ),
                $revisedLimitCents,
                $decisionId,
            ]);

            if ($revisedLimitCents !== null) {
                $pdo->prepare('UPDATE organisations SET credit_limit_cents = ? WHERE id = ?')
                    ->execute([$revisedLimitCents, $row['org_id']]);
            }
        });

        $this->audit->record(
            action: 'credit.review_completed',
            actorId: $reviewerUserId,
            entityType: 'credit_decisions',
            entityId: $decisionId,
            metadata: ['outcome' => $outcome, 'revised_limit_cents' => $revisedLimitCents]
        );
    }

    /**
     * Reviews past their SLA. Wire to a daily job.
     *
     * @return list<array<string, mixed>>
     */
    public function overdueReviews(): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT c.id, g.account_ref, c.decision, c.review_requested_at,
                    TIMESTAMPDIFF(DAY, c.review_requested_at, UTC_TIMESTAMP()) AS days_waiting
               FROM credit_decisions c
               JOIN organisations g ON g.id = c.org_id
              WHERE c.review_requested_at IS NOT NULL
                AND c.reviewed_at IS NULL
                AND c.review_requested_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
              ORDER BY c.review_requested_at ASC'
        );
        $stmt->execute([self::REVIEW_SLA_DAYS]);

        return $stmt->fetchAll();
    }
}
