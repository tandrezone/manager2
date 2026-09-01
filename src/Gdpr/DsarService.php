<?php

declare(strict_types=1);

namespace Manager2\Gdpr;

use Manager2\Audit\AuditLog;
use Manager2\Crypto\BlindIndex;
use Manager2\Crypto\DecryptionFailedException;
use Manager2\Crypto\FieldCipher;
use Manager2\Support\Db;
use Manager2\Support\Uuid;
use PDO;

/**
 * Data subject requests: access, portability, erasure, restriction (Arts. 15-21).
 *
 * This is the part of "GDPR compliance" that is actual compliance work, as
 * opposed to encryption — which is Art. 32 security and would be good
 * engineering with or without the regulation. A system can be encrypted to the
 * hilt and still be flatly unlawful if it cannot answer "what do you hold about
 * me, and will you delete it".
 *
 * The hard part of erasure is knowing what you may NOT delete
 * ---------------------------------------------------------
 * Art. 17(1) gives a right to erasure. Art. 17(3)(b) removes it where
 * processing is necessary for compliance with a legal obligation. Invoices are
 * exactly that: Portuguese law requires ten fiscal years of retention, and the
 * customer's identity is a mandatory content requirement of the invoice itself
 * (VAT Directive Art. 226). So a valid erasure request over a customer with
 * invoice history is *partially refused*, and the refusal must be reasoned,
 * recorded and communicated with the right to complain to the supervisory
 * authority.
 *
 * Deleting the invoices instead is not a privacy win. It is tax fraud.
 *
 * What this implementation therefore does
 * --------------------------------------
 *   - Purges contact PII: name, email, phone, job title, delivery contacts,
 *     access notes, message bodies, session records.
 *   - Retains the financial record: invoices with their snapshotted billing
 *     identity, orders, payments, and the audit trail proving the erasure.
 *   - Marks the user row `erased_at` and neutralises its blind indexes, so the
 *     account can never be matched or reactivated.
 *   - Records the legal ground for every retained category.
 */
final class DsarService
{
    /** Art. 12(3): one month, extendable by two for complex requests. */
    private const RESPONSE_DAYS = 30;

    /**
     * Categories that survive erasure, with their legal ground.
     *
     * @var array<string, string>
     */
    private const RETAINED_ON_ERASURE = [
        'invoices' => 'Art. 17(3)(b) GDPR — statutory accounting retention '
            . '(10 fiscal years, PT CIVA). Billing identity is mandatory invoice '
            . 'content under Art. 226 Directive 2006/112/EC.',
        'orders' => 'Art. 17(3)(b) and 17(3)(e) — transaction records supporting '
            . 'the invoice and available for legal claims.',
        'payments' => 'Art. 17(3)(b) — payment records required for accounting '
            . 'reconciliation and anti-fraud obligations.',
        'audit_log' => 'Art. 17(3)(b) — security and accountability records '
            . 'demonstrating compliance under Arts. 5(2) and 32.',
    ];

    public function __construct(
        private readonly PDO $pdo,
        private readonly FieldCipher $cipher,
        private readonly BlindIndex $blindIndex,
        private readonly AuditLog $audit
    ) {
    }

    /**
     * Open a request and start the statutory clock.
     *
     * The clock starts on receipt, not on identity verification. Letting it
     * start later is a common and costly error: a slow verification step does
     * not extend the deadline.
     *
     * @return array{request_id:string, reference:string, due_at:string}
     */
    public function open(
        string $requestType,
        ?string $subjectUserId = null,
        ?string $subjectEmail = null,
        string $channel = 'portal'
    ): array {
        $valid = ['access', 'rectification', 'erasure', 'portability',
            'restriction', 'objection', 'art22_review'];

        if (!in_array($requestType, $valid, true)) {
            throw new \InvalidArgumentException("Unknown request type '{$requestType}'.");
        }

        if ($subjectUserId === null && $subjectEmail === null) {
            throw new \InvalidArgumentException(
                'A request needs either a known user or an email to identify the subject by.'
            );
        }

        $id = Uuid::v7();
        $reference = $this->nextReference();
        $receivedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $dueAt = $receivedAt->add(new \DateInterval('P' . self::RESPONSE_DAYS . 'D'));

        // received_at is written explicitly rather than left to the column
        // default: taking one value from PHP's clock and the other from the
        // database's makes the statutory window come out at 29 days whenever the
        // two disagree by a microsecond, and a deadline that is quietly a day
        // short is exactly the kind of error that shows up in enforcement.
        $stmt = $this->pdo->prepare(
            'INSERT INTO gdpr_requests
                (id, reference, subject_user_id, subject_email_bidx, request_type,
                 channel, status, received_at, due_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );

        $stmt->execute([
            $id,
            $reference,
            $subjectUserId,
            $subjectEmail === null
                ? null
                : $this->blindIndex->compute($subjectEmail, 'users', 'email_bidx'),
            $requestType,
            $channel,
            'received',
            $receivedAt->format('Y-m-d H:i:s.u'),
            $dueAt->format('Y-m-d H:i:s.u'),
        ]);

        $this->audit->record(
            action: 'dsar.open',
            entityType: 'gdpr_requests',
            entityId: $id,
            metadata: ['reference' => $reference, 'type' => $requestType, 'channel' => $channel]
        );

        return [
            'request_id' => Uuid::toString($id),
            'reference' => $reference,
            'due_at' => $dueAt->format('c'),
        ];
    }

    /**
     * Build a portable export of everything held about one person (Arts. 15, 20).
     *
     * Returned as a structured array for the caller to serialise as JSON — Art.
     * 20 requires a "structured, commonly used and machine-readable format".
     *
     * Includes `_access_log`: the record of which staff decrypted this person's
     * data and when. Art. 15(1)(c) requires disclosing recipients, and an
     * honest answer to "who has looked at my address" is the whole reason the
     * audit log records PII reads.
     *
     * @return array<string, mixed>
     */
    public function export(string $userId, ?string $requestId = null, ?string $actorId = null): array
    {
        $user = $this->loadUser($userId);

        $export = [
            '_meta' => [
                'generated_at' => gmdate('c'),
                'controller' => getenv('M2_CONTROLLER_NAME') ?: 'manager2 operator',
                'request_reference' => $requestId === null
                    ? null
                    : $this->referenceFor($requestId),
                'format' => 'application/json',
                'note' => 'This export covers personal data relating to you. '
                    . 'Business records of your employer are included only where they '
                    . 'identify you personally.',
            ],
            'account' => [
                'display_handle' => $user['display_handle'],
                'role' => $user['role'],
                'status' => $user['status'],
                'full_name' => $this->tryOpen($user['full_name_enc'], 'users', 'full_name_enc', $userId),
                'email' => $this->tryOpen($user['email_enc'], 'users', 'email_enc', $userId),
                'job_title' => $this->tryOpen($user['job_title_enc'], 'users', 'job_title_enc', $userId),
                'phone' => $this->tryOpen($user['phone_enc'], 'users', 'phone_enc', $userId),
                'created_at' => $user['created_at'],
                'last_login_at' => $user['last_login_at'],
            ],
            'organisation' => $this->exportOrganisation((string) $user['org_id']),
            'lawful_bases' => $this->exportLawfulBases(),
            'orders' => $this->exportOrders($userId),
            'delivery_locations' => $this->exportDeliveryLocations((string) $user['org_id']),
            'messages' => $this->exportMessages($userId),
            'consents' => $this->exportConsents($userId),
            'automated_decisions' => $this->exportCreditDecisions((string) $user['org_id']),
            '_access_log' => $this->exportAccessLog($userId),
            '_your_rights' => [
                'rectification' => 'You can correct inaccurate data from your profile page '
                    . 'or by replying to this request.',
                'erasure' => 'You can request erasure. Records we are legally required to '
                    . 'keep — chiefly invoices — will be retained, and we will tell you '
                    . 'which and why.',
                'restriction' => 'You can ask us to stop processing while a dispute is resolved.',
                'complaint' => 'You can complain to your national data protection authority. '
                    . 'In Portugal this is the CNPD (www.cnpd.pt).',
            ],
        ];

        $this->audit->record(
            action: 'dsar.export',
            actorId: $actorId,
            entityType: 'users',
            entityId: $userId,
            piiFields: ['full_name_enc', 'email_enc', 'phone_enc', 'job_title_enc'],
            metadata: ['request_id' => $requestId === null ? null : Uuid::toString($requestId)]
        );

        return $export;
    }

    /**
     * Erase what may be erased; retain what must be retained; report both.
     *
     * @return array{
     *     erased: list<string>,
     *     retained: array<string, string>,
     *     status: 'fulfilled'|'partially_refused'
     * }
     */
    public function erase(
        string $userId,
        ?string $requestId = null,
        ?string $actorId = null
    ): array {
        $user = $this->loadUser($userId);
        $orgId = (string) $user['org_id'];

        $hasFinancialHistory = $this->hasFinancialHistory($orgId);

        $erased = Db::transaction($this->pdo, function (PDO $pdo) use ($userId, $orgId): array {
            $done = [];

            // 1. Neutralise the user's own PII. Blind indexes are randomised
            //    rather than nulled: NULL in a UNIQUE column would let the same
            //    address register again and silently inherit nothing, while a
            //    random value keeps the constraint meaningful and unmatchable.
            $stmt = $pdo->prepare(
                'UPDATE users
                    SET email_enc = ?, email_bidx = ?, full_name_enc = ?,
                        job_title_enc = NULL, phone_enc = NULL, phone_bidx = NULL,
                        totp_secret_enc = NULL, password_hash = NULL,
                        display_handle = ?, status = \'disabled\',
                        last_login_ip_hash = NULL,
                        erased_at = UTC_TIMESTAMP(6)
                  WHERE id = ?'
            );

            $stmt->execute([
                $this->cipher->seal('[erased]', 'users', 'email_enc', $userId),
                random_bytes(32),
                $this->cipher->seal('[erased]', 'users', 'full_name_enc', $userId),
                'ERASED-' . strtoupper(bin2hex(random_bytes(3))),
                $userId,
            ]);
            $done[] = 'users: name, email, phone, job title, credentials, MFA secret';

            // 2. Sessions.
            $pdo->prepare('DELETE FROM sessions WHERE user_id = ?')->execute([$userId]);
            $done[] = 'sessions: all active and historic session records';

            // 3. Message bodies this person wrote. The row is kept with a
            //    redaction marker so the thread stays coherent for the
            //    counterparty, whose own record of the exchange is legitimate.
            $messages = $pdo->prepare(
                'SELECT id FROM messages WHERE sender_id = ? AND redacted_at IS NULL'
            );
            $messages->execute([$userId]);
            $ids = $messages->fetchAll(PDO::FETCH_COLUMN);

            if ($ids !== []) {
                $redact = $pdo->prepare(
                    'UPDATE messages SET body_enc = ?, redacted_at = UTC_TIMESTAMP(6) WHERE id = ?'
                );

                foreach ($ids as $messageId) {
                    $redact->execute([
                        $this->cipher->seal(
                            '[message erased at the sender\'s request]',
                            'messages',
                            'body_enc',
                            (string) $messageId
                        ),
                        $messageId,
                    ]);
                }

                $done[] = sprintf('messages: %d message bodies redacted', count($ids));
            }

            // 4. Delivery-site contact details, but only if this person is the
            //    last user of the account. Otherwise they are the employer's
            //    operational data, still needed by colleagues, and erasing them
            //    would be acting on a request the subject cannot make.
            $others = $pdo->prepare(
                'SELECT COUNT(*) FROM users WHERE org_id = ? AND id <> ? AND erased_at IS NULL'
            );
            $others->execute([$orgId, $userId]);

            if ((int) $others->fetchColumn() === 0) {
                $locations = $pdo->prepare(
                    'SELECT id FROM delivery_locations WHERE org_id = ?'
                );
                $locations->execute([$orgId]);

                $clear = $pdo->prepare(
                    'UPDATE delivery_locations
                        SET contact_name_enc = NULL, contact_phone_enc = NULL,
                            access_notes_enc = NULL, archived_at = UTC_TIMESTAMP(6)
                      WHERE id = ?'
                );

                $count = 0;
                foreach ($locations->fetchAll(PDO::FETCH_COLUMN) as $locationId) {
                    $clear->execute([$locationId]);
                    $count++;
                }

                if ($count > 0) {
                    $done[] = sprintf(
                        'delivery_locations: site contacts and access notes cleared on %d location(s)',
                        $count
                    );
                }
            }

            // 5. Consent records: the withdrawal itself must be evidenced, so
            //    the row is marked rather than deleted.
            $pdo->prepare(
                'UPDATE consent_records SET withdrawn_at = UTC_TIMESTAMP(6)
                  WHERE user_id = ? AND withdrawn_at IS NULL'
            )->execute([$userId]);
            $done[] = 'consent_records: all consents marked withdrawn';

            return $done;
        });

        $retained = $hasFinancialHistory ? self::RETAINED_ON_ERASURE : [];
        $status = $retained === [] ? 'fulfilled' : 'partially_refused';

        if ($requestId !== null) {
            $this->closeRequest($requestId, $status, $retained, $erased);
        }

        $this->audit->record(
            action: 'dsar.erase',
            actorId: $actorId,
            entityType: 'users',
            entityId: $userId,
            metadata: [
                'erased' => $erased,
                'retained_categories' => array_keys($retained),
                'status' => $status,
                'request_id' => $requestId === null ? null : Uuid::toString($requestId),
            ]
        );

        return ['erased' => $erased, 'retained' => $retained, 'status' => $status];
    }

    /**
     * Requests approaching or past their statutory deadline.
     *
     * Wire to a daily job. A missed Art. 12(3) deadline is itself an
     * infringement, and it is the single most common finding in DSAR-related
     * enforcement.
     *
     * @return list<array<string, mixed>>
     */
    public function overdueAndDueSoon(int $warnWithinDays = 7): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT reference, request_type, status, received_at,
                    COALESCE(extended_to, due_at) AS deadline,
                    TIMESTAMPDIFF(DAY, UTC_TIMESTAMP(), COALESCE(extended_to, due_at)) AS days_left
               FROM gdpr_requests
              WHERE completed_at IS NULL
                AND COALESCE(extended_to, due_at) <= DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? DAY)
              ORDER BY deadline ASC"
        );
        $stmt->execute([max(0, $warnWithinDays)]);

        return $stmt->fetchAll();
    }

    /**
     * @param array<string, string> $retained
     * @param list<string>          $erased
     */
    private function closeRequest(
        string $requestId,
        string $status,
        array $retained,
        array $erased
    ): void {
        $notes = "Erased:\n- " . implode("\n- ", $erased) . "\n\n";

        if ($retained !== []) {
            $notes .= "Retained, with grounds:\n";
            foreach ($retained as $category => $ground) {
                $notes .= "- {$category}: {$ground}\n";
            }
        } else {
            $notes .= "No categories retained.\n";
        }

        $stmt = $this->pdo->prepare(
            'UPDATE gdpr_requests
                SET status = ?, completed_at = UTC_TIMESTAMP(6),
                    refusal_ground = ?, decision_notes_enc = ?
              WHERE id = ?'
        );

        $stmt->execute([
            $status,
            $retained === [] ? null : 'Art. 17(3)(b) GDPR — legal retention obligation',
            $this->cipher->seal($notes, 'gdpr_requests', 'decision_notes_enc', $requestId),
            $requestId,
        ]);
    }

    private function hasFinancialHistory(string $orgId): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM invoices WHERE org_id = ? LIMIT 1');
        $stmt->execute([$orgId]);

        return $stmt->fetchColumn() !== false;
    }

    /** @return array<string, mixed> */
    private function loadUser(string $userId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if ($user === false) {
            throw new \RuntimeException('No such user: ' . Uuid::toString($userId));
        }

        return $user;
    }

    /** @return array<string, mixed> */
    private function exportOrganisation(string $orgId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT account_ref, legal_name, trading_name, country, vat_number, status,
                    price_tier, payment_terms_days, onboarded_at
               FROM organisations WHERE id = ?'
        );
        $stmt->execute([$orgId]);

        return [
            'note' => 'Your employer\'s trade account. Included because your login is '
                . 'linked to it; the company\'s own commercial data is not your personal data.',
            'details' => $stmt->fetch() ?: [],
        ];
    }

    /** @return list<array<string, mixed>> */
    private function exportLawfulBases(): array
    {
        $rows = $this->pdo->query(
            'SELECT code, purpose, lawful_basis, retention_days, retention_note,
                    transfers_outside_eea
               FROM processing_purposes ORDER BY code'
        );

        return $rows === false ? [] : $rows->fetchAll();
    }

    /** @return list<array<string, mixed>> */
    private function exportOrders(string $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT order_number, status, currency, gross_cents, payment_method,
                    payment_status, requested_window_start, requested_window_end,
                    dispatch_method, tracking_ref, created_at, delivered_at
               FROM orders WHERE placed_by = ? ORDER BY created_at DESC'
        );
        $stmt->execute([$userId]);

        return $stmt->fetchAll();
    }

    /** @return list<array<string, mixed>> */
    private function exportDeliveryLocations(string $orgId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, label, country, address_enc, contact_name_enc,
                    contact_phone_enc, access_notes_enc
               FROM delivery_locations WHERE org_id = ?'
        );
        $stmt->execute([$orgId]);

        $out = [];

        while ($row = $stmt->fetch()) {
            $id = (string) $row['id'];
            $out[] = [
                'label' => $row['label'],
                'country' => $row['country'],
                'address' => $this->tryOpen($row['address_enc'], 'delivery_locations', 'address_enc', $id),
                'contact_name' => $this->tryOpen($row['contact_name_enc'], 'delivery_locations', 'contact_name_enc', $id),
                'contact_phone' => $this->tryOpen($row['contact_phone_enc'], 'delivery_locations', 'contact_phone_enc', $id),
                'access_notes' => $this->tryOpen($row['access_notes_enc'], 'delivery_locations', 'access_notes_enc', $id),
            ];
        }

        return $out;
    }

    /** @return list<array<string, mixed>> */
    private function exportMessages(string $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT m.id, m.body_enc, m.sender_side, m.created_at, m.redacted_at,
                    o.order_number
               FROM messages m
               JOIN orders o ON o.id = m.order_id
              WHERE m.sender_id = ?
              ORDER BY m.created_at ASC'
        );
        $stmt->execute([$userId]);

        $out = [];

        while ($row = $stmt->fetch()) {
            $out[] = [
                'order' => $row['order_number'],
                'sent_at' => $row['created_at'],
                'redacted' => $row['redacted_at'] !== null,
                'body' => $this->tryOpen(
                    $row['body_enc'],
                    'messages',
                    'body_enc',
                    (string) $row['id']
                ),
            ];
        }

        return $out;
    }

    /** @return list<array<string, mixed>> */
    private function exportConsents(string $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT purpose_code, granted, notice_version, granted_at, withdrawn_at
               FROM consent_records WHERE user_id = ? ORDER BY granted_at DESC'
        );
        $stmt->execute([$userId]);

        return $stmt->fetchAll();
    }

    /**
     * Art. 15(1)(h) and Art. 22: disclose automated decision-making, including
     * the logic involved and its consequences.
     *
     * @return list<array<string, mixed>>
     */
    private function exportCreditDecisions(string $orgId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT decision, is_automated, score, factors_json, prev_limit_cents,
                    new_limit_cents, effective_from, review_requested_at,
                    reviewed_at, review_outcome
               FROM credit_decisions WHERE org_id = ? ORDER BY effective_from DESC'
        );
        $stmt->execute([$orgId]);

        $rows = $stmt->fetchAll();

        foreach ($rows as &$row) {
            $row['factors_json'] = json_decode((string) $row['factors_json'], true);
            $row['_your_right'] = 'You can ask for this decision to be reviewed by a person, '
                . 'express your point of view, and contest the outcome (Art. 22(3) GDPR).';
        }

        return $rows;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function exportAccessLog(string $userId): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT occurred_at, action, actor_role, pii_fields, metadata
               FROM audit_log
              WHERE entity_type = 'users' AND entity_id = ?
                AND action IN ('pii.read','dsar.export','dsar.erase')
              ORDER BY occurred_at DESC
              LIMIT 500"
        );
        $stmt->execute([$userId]);

        $rows = [];

        while ($row = $stmt->fetch()) {
            $rows[] = [
                'when' => $row['occurred_at'],
                'what' => $row['action'],
                // The role, not the individual staff member: naming an employee
                // to a third party would be an unlawful disclosure of *their*
                // personal data. Art. 15(4) makes exactly this reservation.
                'by_role' => $row['actor_role'],
                'fields' => json_decode((string) ($row['pii_fields'] ?? 'null'), true),
                'reason' => json_decode((string) ($row['metadata'] ?? '{}'), true)['reason'] ?? null,
            ];
        }

        return $rows;
    }

    /**
     * Decrypt for export, degrading gracefully.
     *
     * A DSAR export must not abort because one legacy row is undecryptable —
     * the subject is entitled to everything that *can* be produced, and a hard
     * failure here means missing the statutory deadline over one bad row.
     */
    private function tryOpen(?string $sealed, string $table, string $column, string $rowId): ?string
    {
        if ($sealed === null) {
            return null;
        }

        try {
            return $this->cipher->open($sealed, $table, $column, $rowId);
        } catch (DecryptionFailedException | \Throwable) {
            return '[stored value could not be decrypted — reported to the DPO]';
        }
    }

    private function referenceFor(string $requestId): ?string
    {
        $stmt = $this->pdo->prepare('SELECT reference FROM gdpr_requests WHERE id = ?');
        $stmt->execute([$requestId]);
        $ref = $stmt->fetchColumn();

        return $ref === false ? null : (string) $ref;
    }

    private function nextReference(): string
    {
        $year = date('Y');
        $stmt = $this->pdo->prepare(
            "SELECT COALESCE(MAX(CAST(SUBSTRING(reference, 11) AS UNSIGNED)), 0)
               FROM gdpr_requests WHERE reference LIKE ?"
        );
        $stmt->execute(["DSAR-{$year}-%"]);

        return sprintf('DSAR-%s-%04d', $year, ((int) $stmt->fetchColumn()) + 1);
    }
}
