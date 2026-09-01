<?php

declare(strict_types=1);

namespace Manager2\Audit;

use Manager2\Support\Db;
use PDO;

/**
 * Append-only, hash-chained audit trail.
 *
 * This class is the deliberate counterweight to the encryption layer. Field
 * encryption limits who *can* read PII; the audit log records who *did*. A
 * system that encrypts aggressively but keeps no access record is not
 * privacy-preserving — it is merely opaque, including to the people whose data
 * it holds and to the DPO who has to answer for it.
 *
 * Each entry commits to its predecessor:
 *
 *   entry_hash = SHA256(prev_hash || canonical_json(entry))
 *
 * That makes deletion and back-dating detectable: removing or altering entry N
 * breaks verification for every entry after it. It does not make tampering
 * *impossible* — an attacker with UPDATE rights and the recomputation code can
 * rewrite the whole chain. To close that gap, ship the head hash off-box
 * periodically (`chainHead()` into an append-only object store or a log
 * service), so the local chain can be checked against an external anchor.
 *
 * `pii.read` entries are the ones that matter under Art. 15: a data subject
 * asking "who has looked at my delivery address" should get an answer.
 */
final class AuditLog
{
    private const LOCK_NAME = 'manager2_audit_chain';
    private const LOCK_TIMEOUT_SECONDS = 5;

    public function __construct(private readonly PDO $pdo) {}

    /**
     * Append an entry.
     *
     * @param string               $action     dotted verb, e.g. 'pii.read', 'order.accept'
     * @param list<string>|null    $piiFields  which encrypted fields were decrypted
     * @param array<string, mixed> $metadata   context; must contain no plaintext PII
     */
    public function record(
        string $action,
        ?string $actorId = null,
        ?string $actorRole = null,
        ?string $entityType = null,
        ?string $entityId = null,
        ?array $piiFields = null,
        array $metadata = [],
        ?string $actorIpHash = null
    ): void {
        // Serialise appends so two concurrent writers cannot both chain off the
        // same predecessor and fork the chain. This caps audit throughput to
        // one append at a time; at high volume, batch entries per request or
        // shard the chain by month and anchor each shard separately.
        $lock = $this->pdo->prepare('SELECT GET_LOCK(?, ?)');
        $lock->execute([self::LOCK_NAME, self::LOCK_TIMEOUT_SECONDS]);

        if ((int) $lock->fetchColumn() !== 1) {
            throw new \RuntimeException('Could not acquire the audit chain lock.');
        }

        try {
            $prevHash = $this->chainHead();

            $entry = [
                'occurred_at' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
                    ->format('Y-m-d H:i:s.u'),
                'actor_id' => $actorId === null ? null : bin2hex($actorId),
                'actor_role' => $actorRole,
                'action' => $action,
                'entity_type' => $entityType,
                'entity_id' => $entityId === null ? null : bin2hex($entityId),
                'pii_fields' => $piiFields,
                'metadata' => $metadata,
            ];

            $entryHash = hash('sha256', ($prevHash ?? '') . self::canonicalise($entry), true);

            $stmt = $this->pdo->prepare(
                'INSERT INTO audit_log
                    (occurred_at, actor_id, actor_role, actor_ip_hash, action,
                     entity_type, entity_id, pii_fields, metadata, prev_hash, entry_hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $entry['occurred_at'],
                $actorId,
                $actorRole,
                $actorIpHash,
                $action,
                $entityType,
                $entityId,
                $piiFields === null ? null : self::canonicalise($piiFields),
                $metadata === [] ? null : self::canonicalise($metadata),
                $prevHash,
                $entryHash,
            ]);
        } finally {
            $release = $this->pdo->prepare('SELECT RELEASE_LOCK(?)');
            $release->execute([self::LOCK_NAME]);
        }
    }

    /**
     * Convenience wrapper for the case the log exists for.
     *
     * Call it at the point of decryption, not at the point of rendering, so an
     * aborted request that still touched the plaintext is recorded.
     *
     * @param list<string> $fields
     */
    public function recordPiiAccess(
        string $actorId,
        string $actorRole,
        string $entityType,
        string $entityId,
        array $fields,
        string $reason,
        ?string $actorIpHash = null
    ): void {
        $this->record(
            action: 'pii.read',
            actorId: $actorId,
            actorRole: $actorRole,
            entityType: $entityType,
            entityId: $entityId,
            piiFields: $fields,
            metadata: ['reason' => $reason],
            actorIpHash: $actorIpHash
        );
    }

    /** The most recent entry's hash, or null for an empty log. */
    public function chainHead(): ?string
    {
        $head = $this->pdo
            ->query('SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1')
            ?->fetchColumn();

        return $head === false || $head === null ? null : (string) $head;
    }

    /**
     * Re-walk the chain and report the first entry that does not verify.
     *
     * Run nightly and alert on any result other than `['ok' => true]`. A break
     * means either tampering or a bug in this class; both warrant a page.
     *
     * @return array{ok:bool, checked:int, broken_at?:int, reason?:string}
     */
    public function verify(int $fromId = 0, ?int $limit = null): array
    {
        $sql = 'SELECT id, occurred_at, actor_id, actor_role, action, entity_type,
                       entity_id, pii_fields, metadata, prev_hash, entry_hash
                  FROM audit_log
                 WHERE id > ?
                 ORDER BY id ASC';

        if ($limit !== null) {
            $sql .= ' LIMIT ' . max(1, $limit);
        }

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$fromId]);

        $expectedPrev = null;
        $checked = 0;
        $first = true;

        while ($row = $stmt->fetch()) {
            $checked++;

            // On a partial verification the first row's predecessor is whatever
            // is recorded, since the caller chose not to start from the origin.
            if ($first && $fromId > 0) {
                $expectedPrev = $row['prev_hash'];
                $first = false;
            }

            if ($expectedPrev !== $row['prev_hash']) {
                return [
                    'ok' => false,
                    'checked' => $checked,
                    'broken_at' => (int) $row['id'],
                    'reason' => 'prev_hash does not match the preceding entry — '
                        . 'an entry was deleted, reordered or inserted.',
                ];
            }

            $entry = [
                'occurred_at' => $row['occurred_at'],
                'actor_id' => $row['actor_id'] === null ? null : bin2hex($row['actor_id']),
                'actor_role' => $row['actor_role'],
                'action' => $row['action'],
                'entity_type' => $row['entity_type'],
                'entity_id' => $row['entity_id'] === null ? null : bin2hex($row['entity_id']),
                'pii_fields' => $row['pii_fields'] === null
                    ? null
                    : json_decode((string) $row['pii_fields'], true),
                'metadata' => $row['metadata'] === null
                    ? []
                    : json_decode((string) $row['metadata'], true),
            ];

            $recomputed = hash(
                'sha256',
                ($row['prev_hash'] ?? '') . self::canonicalise($entry),
                true
            );

            if (!hash_equals($row['entry_hash'], $recomputed)) {
                return [
                    'ok' => false,
                    'checked' => $checked,
                    'broken_at' => (int) $row['id'],
                    'reason' => 'entry_hash does not match the entry contents — '
                        . 'the row was modified after it was written.',
                ];
            }

            $expectedPrev = $row['entry_hash'];
            $first = false;
        }

        return ['ok' => true, 'checked' => $checked];
    }

    /**
     * Deterministic JSON for hashing.
     *
     * Keys are sorted recursively. Without that, PHP's associative-array order
     * leaks into the digest and an entry rebuilt from the database in a
     * different key order fails to verify even though nothing changed.
     * Slashes and Unicode are left unescaped so the byte sequence does not
     * depend on PHP's escaping defaults.
     */
    private static function canonicalise(mixed $value): string
    {
        $sort = static function (mixed $v) use (&$sort): mixed {
            if (!is_array($v)) {
                return $v;
            }

            $isList = array_is_list($v);
            $out = [];

            foreach ($v as $k => $child) {
                $out[$k] = $sort($child);
            }

            if (!$isList) {
                ksort($out, SORT_STRING);
            }

            return $out;
        };

        return json_encode(
            $sort($value),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
                | JSON_PRESERVE_ZERO_FRACTION
        );
    }
}
