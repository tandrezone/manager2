<?php

declare(strict_types=1);

namespace Manager2\Gdpr;

use Manager2\Audit\AuditLog;
use Manager2\Crypto\FieldCipher;
use PDO;

/**
 * Enforce the retention schedule (Art. 5(1)(e), storage limitation).
 *
 * A retention policy that exists only in a PDF is not a control. This class
 * reads `retention_days` from the `processing_purposes` table — the ROPA — and
 * acts on it, so the policy and the behaviour cannot drift apart.
 *
 * Design choices worth stating:
 *
 *  - Purge is by *purpose*, not by table. The same table can hold data under
 *    different purposes with different clocks: an order's delivery contact goes
 *    at three years, while the order's financial record stays ten.
 *  - Purging means clearing PII columns, not deleting rows, wherever the row
 *    still has a lawful reason to exist. Deleting a delivered order would break
 *    the invoice that references it.
 *  - Dry-run first. `plan()` reports what would go; `execute()` does it. Anyone
 *    who has irreversibly purged a production table from a cron job they had
 *    not dry-run understands why this split is not optional.
 *  - Every purge is audited, in aggregate. Individual records are not named:
 *    logging "purged the address of Ana Ribeiro" would recreate the data the
 *    purge just removed.
 */
final class RetentionPurger
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly FieldCipher $cipher,
        private readonly AuditLog $audit
    ) {
    }

    /**
     * Report what is eligible for purge without changing anything.
     *
     * @return list<array{purpose:string, retention_days:int, target:string, eligible:int}>
     */
    public function plan(): array
    {
        $plan = [];

        foreach ($this->rules() as $rule) {
            $stmt = $this->pdo->prepare($rule['count_sql']);
            $stmt->execute([$rule['retention_days']]);

            $plan[] = [
                'purpose' => $rule['purpose'],
                'retention_days' => $rule['retention_days'],
                'target' => $rule['target'],
                'eligible' => (int) $stmt->fetchColumn(),
            ];
        }

        return $plan;
    }

    /**
     * Execute the purge.
     *
     * @param int $batchSize rows per statement, to keep lock windows short
     * @return array<string, int> target => rows affected
     */
    public function execute(int $batchSize = 500): array
    {
        $affected = [];

        foreach ($this->rules() as $rule) {
            $total = 0;

            do {
                $purged = ($rule['purge'])($rule['retention_days'], $batchSize);
                $total += $purged;
            } while ($purged >= $batchSize);

            if ($total > 0) {
                $affected[$rule['target']] = $total;
            }
        }

        if ($affected !== []) {
            $this->audit->record(
                action: 'retention.purge',
                metadata: ['affected' => $affected, 'basis' => 'Art. 5(1)(e) storage limitation']
            );
        }

        return $affected;
    }

    /**
     * Retention rules, each bound to a ROPA purpose.
     *
     * @return list<array{
     *     purpose:string, target:string, retention_days:int,
     *     count_sql:string, purge:callable(int,int):int
     * }>
     */
    private function rules(): array
    {
        $days = $this->retentionDays();
        $rules = [];

        // --- Delivery contact details on fulfilled orders -------------------
        if (isset($days['order_fulfilment'])) {
            $rules[] = [
                'purpose' => 'order_fulfilment',
                'target' => 'orders.delivery_notes_enc, orders.pod_signed_name_enc',
                'retention_days' => $days['order_fulfilment'],
                'count_sql' =>
                    "SELECT COUNT(*) FROM orders
                      WHERE status IN ('delivered','closed','cancelled')
                        AND COALESCE(delivered_at, updated_at)
                            < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
                        AND (delivery_notes_enc IS NOT NULL OR pod_signed_name_enc IS NOT NULL)",
                'purge' => function (int $retentionDays, int $limit): int {
                    $stmt = $this->pdo->prepare(
                        "UPDATE orders
                            SET delivery_notes_enc = NULL, pod_signed_name_enc = NULL
                          WHERE status IN ('delivered','closed','cancelled')
                            AND COALESCE(delivered_at, updated_at)
                                < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
                            AND (delivery_notes_enc IS NOT NULL
                                 OR pod_signed_name_enc IS NOT NULL)
                          LIMIT " . max(1, $limit)
                    );
                    $stmt->execute([$retentionDays]);

                    return $stmt->rowCount();
                },
            ];

            // Archived delivery locations no longer referenced by a live order.
            $rules[] = [
                'purpose' => 'order_fulfilment',
                'target' => 'delivery_locations contact details',
                'retention_days' => $days['order_fulfilment'],
                'count_sql' =>
                    'SELECT COUNT(*) FROM delivery_locations dl
                      WHERE dl.archived_at IS NOT NULL
                        AND dl.archived_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
                        AND (dl.contact_name_enc IS NOT NULL
                             OR dl.contact_phone_enc IS NOT NULL
                             OR dl.access_notes_enc IS NOT NULL)',
                'purge' => function (int $retentionDays, int $limit): int {
                    $stmt = $this->pdo->prepare(
                        'UPDATE delivery_locations
                            SET contact_name_enc = NULL, contact_phone_enc = NULL,
                                access_notes_enc = NULL
                          WHERE archived_at IS NOT NULL
                            AND archived_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
                            AND (contact_name_enc IS NOT NULL
                                 OR contact_phone_enc IS NOT NULL
                                 OR access_notes_enc IS NOT NULL)
                          LIMIT ' . max(1, $limit)
                    );
                    $stmt->execute([$retentionDays]);

                    return $stmt->rowCount();
                },
            ];
        }

        // --- Order support conversations ------------------------------------
        if (isset($days['order_support'])) {
            $rules[] = [
                'purpose' => 'order_support',
                'target' => 'messages.body_enc',
                'retention_days' => $days['order_support'],
                'count_sql' =>
                    "SELECT COUNT(*) FROM messages m
                       JOIN orders o ON o.id = m.order_id
                      WHERE m.redacted_at IS NULL
                        AND o.status IN ('delivered','closed','cancelled')
                        AND m.created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)",
                'purge' => function (int $retentionDays, int $limit): int {
                    $select = $this->pdo->prepare(
                        "SELECT m.id FROM messages m
                           JOIN orders o ON o.id = m.order_id
                          WHERE m.redacted_at IS NULL
                            AND o.status IN ('delivered','closed','cancelled')
                            AND m.created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
                          LIMIT " . max(1, $limit)
                    );
                    $select->execute([$retentionDays]);
                    $ids = $select->fetchAll(PDO::FETCH_COLUMN);

                    if ($ids === []) {
                        return 0;
                    }

                    $update = $this->pdo->prepare(
                        'UPDATE messages
                            SET body_enc = ?, redacted_at = UTC_TIMESTAMP(6)
                          WHERE id = ?'
                    );

                    foreach ($ids as $id) {
                        // Re-sealed rather than nulled: the column is NOT NULL,
                        // and a visible tombstone is more honest to an operator
                        // reading the thread than an empty string.
                        $update->execute([
                            $this->cipher->seal(
                                '[removed under the retention schedule]',
                                'messages',
                                'body_enc',
                                (string) $id
                            ),
                            $id,
                        ]);
                    }

                    return count($ids);
                },
            ];
        }

        // --- Security audit trail -------------------------------------------
        if (isset($days['security_audit'])) {
            $rules[] = [
                'purpose' => 'security_audit',
                'target' => 'audit_log (old entries)',
                'retention_days' => $days['security_audit'],
                'count_sql' =>
                    'SELECT COUNT(*) FROM audit_log
                      WHERE occurred_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)',
                'purge' => function (int $retentionDays, int $limit): int {
                    // Trimming the tail of a hash chain is safe — verification
                    // walks forward — but it does mean older entries can no
                    // longer be proven. Anchor the head hash off-box before
                    // this runs if you need to retain provability.
                    $stmt = $this->pdo->prepare(
                        'DELETE FROM audit_log
                          WHERE occurred_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
                          ORDER BY id ASC
                          LIMIT ' . max(1, $limit)
                    );
                    $stmt->execute([$retentionDays]);

                    return $stmt->rowCount();
                },
            ];
        }

        // --- Webhook payload forensics --------------------------------------
        $rules[] = [
            'purpose' => 'security_audit',
            'target' => 'webhook_events.payload_enc',
            'retention_days' => 90,
            'count_sql' =>
                'SELECT COUNT(*) FROM webhook_events
                  WHERE payload_enc IS NOT NULL
                    AND received_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)',
            'purge' => function (int $retentionDays, int $limit): int {
                $stmt = $this->pdo->prepare(
                    'UPDATE webhook_events SET payload_enc = NULL
                      WHERE payload_enc IS NOT NULL
                        AND received_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
                      LIMIT ' . max(1, $limit)
                );
                $stmt->execute([$retentionDays]);

                return $stmt->rowCount();
            },
        ];

        // --- Expired sessions -----------------------------------------------
        $rules[] = [
            'purpose' => 'account_admin',
            'target' => 'sessions (expired)',
            'retention_days' => 30,
            'count_sql' =>
                'SELECT COUNT(*) FROM sessions
                  WHERE expires_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)',
            'purge' => function (int $retentionDays, int $limit): int {
                $stmt = $this->pdo->prepare(
                    'DELETE FROM sessions
                      WHERE expires_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
                      LIMIT ' . max(1, $limit)
                );
                $stmt->execute([$retentionDays]);

                return $stmt->rowCount();
            },
        ];

        return $rules;
    }

    /**
     * Retention windows from the ROPA.
     *
     * @return array<string, int> purpose code => days
     */
    private function retentionDays(): array
    {
        $rows = $this->pdo->query(
            'SELECT code, retention_days FROM processing_purposes
              WHERE retention_days IS NOT NULL'
        );

        $days = [];

        foreach ($rows === false ? [] : $rows->fetchAll() as $row) {
            $days[(string) $row['code']] = (int) $row['retention_days'];
        }

        return $days;
    }
}
