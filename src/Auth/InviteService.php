<?php

declare(strict_types=1);

namespace Manager2\Auth;

use Manager2\Audit\AuditLog;
use Manager2\Crypto\BlindIndex;
use Manager2\Support\Db;
use Manager2\Support\Uuid;
use PDO;

/**
 * Issue and redeem trade-portal invitations.
 *
 * What an invite is here: an *onboarding* control. It records who issued it and
 * which business it is for, and it obliges the recipient to complete business
 * verification. It gates who may begin registration; it is not, and must not be
 * treated as, a substitute for knowing the counterparty.
 *
 * What it is not: an anonymity shield. Every invite is attributable to the staff
 * member who issued it and to the account it was issued for.
 *
 * Code handling
 * -------------
 * The plaintext code is returned once, at issue, and never stored. Only
 * HMAC-SHA256(pepper, code) is persisted, so a database read yields no working
 * invitations. `code_prefix` is stored separately so support can find an invite
 * a customer quotes over the phone without the column being a redemption
 * credential.
 *
 * The HMAC pepper lives in the environment, not the database — the whole point
 * is that database access alone is insufficient. A plain SHA-256 would be
 * enough given 128 bits of entropy in the code, but the pepper costs nothing
 * and defends the case where someone shortens the alphabet later.
 */
final class InviteService
{
    /** Crockford base32, minus I, L, O and U: no visual ambiguity, no accidental words. */
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    /** 20 chars over a 32-symbol alphabet = 100 bits. Unguessable at any rate limit. */
    private const CODE_LENGTH = 20;

    private const DEFAULT_TTL_DAYS = 14;

    public function __construct(
        private readonly PDO $pdo,
        private readonly BlindIndex $blindIndex,
        private readonly AuditLog $audit,
        private readonly string $codePepper
    ) {
        if (strlen($this->codePepper) < 32) {
            throw new \InvalidArgumentException(
                'Invite code pepper must be at least 32 bytes.'
            );
        }
    }

    /**
     * Issue an invitation.
     *
     * Exactly one of $orgId (join an existing account) or $intendedLegalName
     * (onboard a new account) must be given. Allowing neither would create an
     * invite that onboards an unidentified party, which is the shape this
     * system is specifically built not to have.
     *
     * @return array{invite_id: string, code: string, expires_at: string}
     */
    public function issue(
        string $issuedByUserId,
        ?string $orgId = null,
        ?string $intendedLegalName = null,
        ?string $intendedVatNumber = null,
        ?string $intendedCountry = null,
        ?string $recipientEmail = null,
        string $grantsRole = 'buyer',
        int $ttlDays = self::DEFAULT_TTL_DAYS,
        ?string $reason = null,
        int $maxUses = 1
    ): array {
        if (($orgId === null) === ($intendedLegalName === null)) {
            throw new \InvalidArgumentException(
                'Provide either an existing org_id or the intended legal name of a new account.'
            );
        }

        if (!in_array($grantsRole, ['buyer', 'approver', 'org_admin'], true)) {
            throw new \InvalidArgumentException("Invalid invite role '{$grantsRole}'.");
        }

        if ($intendedVatNumber !== null
            && !VatNumber::isPlausible($intendedVatNumber, $intendedCountry)) {
            throw new \InvalidArgumentException(
                'Intended VAT number fails syntax or checksum validation.'
            );
        }

        $code = self::generateCode();
        $inviteId = Uuid::v7();
        $expiresAt = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->add(new \DateInterval('P' . max(1, $ttlDays) . 'D'));

        $emailBidx = $recipientEmail === null
            ? null
            : $this->blindIndex->compute($recipientEmail, 'invites', 'email_bidx');

        Db::transaction($this->pdo, function (PDO $pdo) use (
            $inviteId, $code, $orgId, $intendedLegalName, $intendedVatNumber,
            $intendedCountry, $emailBidx, $grantsRole, $issuedByUserId, $reason,
            $maxUses, $expiresAt
        ): void {
            $stmt = $pdo->prepare(
                'INSERT INTO invites
                    (id, code_hash, code_prefix, org_id, intended_legal_name,
                     intended_vat_number, intended_country, email_bidx, grants_role,
                     issued_by, issued_reason, max_uses, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $inviteId,
                $this->hashCode($code),
                substr($code, 0, 6),
                $orgId,
                $intendedLegalName,
                $intendedVatNumber === null
                    ? null
                    : VatNumber::format($intendedVatNumber, $intendedCountry),
                $intendedCountry,
                $emailBidx,
                $grantsRole,
                $issuedByUserId,
                $reason,
                max(1, $maxUses),
                $expiresAt->format('Y-m-d H:i:s.u'),
            ]);
        });

        $this->audit->record(
            action: 'invite.issue',
            actorId: $issuedByUserId,
            entityType: 'invites',
            entityId: $inviteId,
            metadata: [
                'grants_role' => $grantsRole,
                'for_existing_org' => $orgId !== null,
                'intended_legal_name' => $intendedLegalName,
                'max_uses' => $maxUses,
                'reason' => $reason,
            ]
        );

        return [
            'invite_id' => Uuid::toString($inviteId),
            'code' => self::hyphenate($code),
            'expires_at' => $expiresAt->format('c'),
        ];
    }

    /**
     * Look up and validate a code without consuming it.
     *
     * Deliberately does not distinguish "no such code" from "expired" or
     * "already used" in the exception message the caller shows to the user:
     * those distinctions let someone with a list of harvested codes work out
     * which ones ever existed. The specific reason is recorded in the audit log
     * for support to read.
     *
     * @return array<string, mixed> the invite row
     * @throws InviteRejectedException
     */
    public function resolve(string $submittedCode, ?string $submittedEmail = null): array
    {
        $code = self::canonicaliseCode($submittedCode);

        if ($code === '' || strlen($code) !== self::CODE_LENGTH) {
            $this->rejectInvite('malformed', null);
        }

        $stmt = $this->pdo->prepare(
            'SELECT * FROM invites WHERE code_hash = ? LIMIT 1'
        );
        $stmt->execute([$this->hashCode($code)]);
        $invite = $stmt->fetch();

        if ($invite === false) {
            $this->rejectInvite('not_found', null);
        }

        /** @var array<string, mixed> $invite */
        $inviteId = (string) $invite['id'];

        if ($invite['revoked_at'] !== null) {
            $this->rejectInvite('revoked', $inviteId);
        }

        if (new \DateTimeImmutable((string) $invite['expires_at']) < new \DateTimeImmutable()) {
            $this->rejectInvite('expired', $inviteId);
        }

        if ((int) $invite['uses'] >= (int) $invite['max_uses']) {
            $this->rejectInvite('exhausted', $inviteId);
        }

        // An invite locked to one recipient must be redeemed by that recipient.
        if ($invite['email_bidx'] !== null) {
            if ($submittedEmail === null) {
                $this->rejectInvite('email_required', $inviteId);
            }

            $expected = $this->blindIndex->computeAllVersions(
                $submittedEmail,
                'invites',
                'email_bidx'
            );

            $matched = false;
            foreach ($expected as $candidate) {
                if (hash_equals((string) $invite['email_bidx'], $candidate)) {
                    $matched = true;
                    break;
                }
            }

            if (!$matched) {
                $this->rejectInvite('email_mismatch', $inviteId);
            }
        }

        return $invite;
    }

    /**
     * Consume one use of an invite. Must be called inside the registration
     * transaction so a failed registration does not burn the invite.
     *
     * The `uses < max_uses` predicate in the UPDATE is what makes this safe
     * against two concurrent redemptions of a single-use code: the second
     * statement matches zero rows.
     */
    public function consume(string $inviteId, string $userId, ?string $ipHash = null): void
    {
        if (!$this->pdo->inTransaction()) {
            throw new \LogicException(
                'consume() must run inside the registration transaction.'
            );
        }

        $stmt = $this->pdo->prepare(
            'UPDATE invites
                SET uses = uses + 1,
                    first_accepted_at = COALESCE(first_accepted_at, UTC_TIMESTAMP(6))
              WHERE id = ?
                AND revoked_at IS NULL
                AND expires_at > UTC_TIMESTAMP(6)
                AND uses < max_uses'
        );
        $stmt->execute([$inviteId]);

        if ($stmt->rowCount() !== 1) {
            throw new InviteRejectedException(
                'This invitation is no longer valid. Please request a new one.'
            );
        }

        $redemption = $this->pdo->prepare(
            'INSERT INTO invite_redemptions (id, invite_id, user_id, ip_hash)
             VALUES (?, ?, ?, ?)'
        );
        $redemption->execute([Uuid::v7(), $inviteId, $userId, $ipHash]);
    }

    public function revoke(string $inviteId, string $revokedByUserId, string $reason): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE invites
                SET revoked_at = UTC_TIMESTAMP(6), revoked_by = ?
              WHERE id = ? AND revoked_at IS NULL'
        );
        $stmt->execute([$revokedByUserId, $inviteId]);

        $this->audit->record(
            action: 'invite.revoke',
            actorId: $revokedByUserId,
            entityType: 'invites',
            entityId: $inviteId,
            metadata: ['reason' => $reason, 'affected' => $stmt->rowCount()]
        );
    }

    /** HMAC the code under the environment pepper. */
    private function hashCode(string $canonicalCode): string
    {
        return hash_hmac('sha256', $canonicalCode, $this->codePepper, true);
    }

    /** @throws InviteRejectedException */
    private function rejectInvite(string $reason, ?string $inviteId): never
    {
        $this->audit->record(
            action: 'invite.reject',
            entityType: 'invites',
            entityId: $inviteId,
            metadata: ['reason' => $reason]
        );

        throw new InviteRejectedException(
            'That invitation code is not valid. Please check it or contact your account manager.'
        );
    }

    private static function generateCode(): string
    {
        $alphabetSize = strlen(self::ALPHABET);
        $code = '';

        for ($i = 0; $i < self::CODE_LENGTH; $i++) {
            $code .= self::ALPHABET[random_int(0, $alphabetSize - 1)];
        }

        return $code;
    }

    /** Present as XXXXX-XXXXX-XXXXX-XXXXX for transcription over the phone. */
    private static function hyphenate(string $code): string
    {
        return implode('-', str_split($code, 5));
    }

    /**
     * Undo presentation formatting and fold the characters users habitually
     * mistype: O for 0, I and L for 1. Crockford base32 excludes those symbols
     * precisely so the substitution is unambiguous.
     */
    private static function canonicaliseCode(string $input): string
    {
        $upper = strtoupper((string) preg_replace('/[^A-Za-z0-9]/', '', $input));

        return strtr($upper, ['O' => '0', 'I' => '1', 'L' => '1', 'U' => 'V']);
    }
}
