<?php

declare(strict_types=1);

namespace Manager2\Auth;

use Manager2\Audit\AuditLog;
use Manager2\Crypto\BlindIndex;
use Manager2\Crypto\FieldCipher;
use Manager2\Support\Db;
use Manager2\Support\Uuid;
use PDO;

/**
 * Registration: redeem an invitation, then verify the business.
 *
 * The shape of this flow is the main design decision in the whole system, so it
 * is worth being explicit about it.
 *
 * A trade portal must know its counterparty. Not for its own comfort — because
 * every downstream obligation depends on it:
 *
 *   - An invoice is only valid with the customer's legal name and VAT number.
 *   - Zero-rating an intra-EU supply requires a verified VAT registration;
 *     get it wrong and the *seller* owes the tax.
 *   - Credit terms require someone legally answerable for the debt.
 *   - Anti-money-laundering obligations, where they apply, are obligations to
 *     identify.
 *   - A named person must be on record as having authority to commit the
 *     company to an order.
 *
 * So an account is a legal entity plus at least one named, contactable human,
 * and neither is optional. `display_handle` exists so the UI can say "AR" in a
 * corner instead of a full name; it is cosmetic, never an identity.
 *
 * That is not in tension with data minimisation. Art. 5(1)(c) requires data to
 * be adequate, relevant and limited to what is *necessary for the purpose* —
 * not that identity be avoided where identity is the purpose. Minimisation here
 * shows up as: no date of birth, no ID document numbers, no home addresses, no
 * personal (as opposed to business) contact details, no marketing profile
 * unless separately consented, and per-purpose retention. That is real
 * minimisation. Pseudonymous buyers would not be minimisation; they would be a
 * portal that cannot invoice.
 *
 * Verification status is a first-class state. Registration produces an account
 * in `pending_verification`, which can browse the catalogue and place orders
 * only up to a configured floor. Reaching `active` requires a KYB pass. The
 * gate is enforced in the ordering path, not merely displayed in the UI.
 */
final class Registration
{
    /**
     * Order value a pending account may place before verification completes.
     *
     * Zero blocks ordering entirely and makes onboarding feel broken; too high
     * and verification stops being a control. 25000 cents (EUR 250) lets a new
     * customer place a sample order the same day.
     */
    private const UNVERIFIED_ORDER_CEILING_CENTS = 25000;

    public function __construct(
        private readonly PDO $pdo,
        private readonly FieldCipher $cipher,
        private readonly BlindIndex $blindIndex,
        private readonly InviteService $invites,
        private readonly AuditLog $audit,
        private readonly ?Vies $vies = null
    ) {
    }

    /**
     * Complete registration against an invitation.
     *
     * @param array{
     *     invite_code: string,
     *     email: string,
     *     full_name: string,
     *     password: string,
     *     job_title?: ?string,
     *     phone?: ?string,
     *     display_handle?: ?string,
     *     legal_name?: ?string,
     *     trading_name?: ?string,
     *     vat_number?: ?string,
     *     country?: ?string,
     *     registry_number?: ?string,
     *     registered_address?: ?string
     * } $input
     * @return array{
     *     user_id: string,
     *     org_id: string,
     *     account_ref: string,
     *     org_status: string,
     *     vat_check: array<string, mixed>|null,
     *     order_ceiling_cents: int|null,
     *     next_steps: list<string>
     * }
     *
     * @throws RegistrationException
     * @throws InviteRejectedException
     * @throws WeakPasswordException
     */
    public function register(array $input, ?string $ipHash = null): array
    {
        $email = trim($input['email'] ?? '');
        $fullName = trim($input['full_name'] ?? '');

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new RegistrationException('Please provide a valid email address.');
        }

        if (mb_strlen($fullName) < 2 || mb_strlen($fullName) > 200) {
            throw new RegistrationException(
                'Please provide the full name of the person who will use this login.'
            );
        }

        // Fail on a weak password before touching the invite, so a rejected
        // password does not consume a use of a single-use code.
        $passwordHash = Passwords::hash($input['password'] ?? '');

        $invite = $this->invites->resolve($input['invite_code'] ?? '', $email);
        $inviteId = (string) $invite['id'];

        $emailBidx = $this->blindIndex->compute($email, 'users', 'email_bidx');

        if ($this->emailInUse($emailBidx)) {
            // Uniform wording: confirming which addresses are registered would
            // turn this endpoint into a customer-list oracle for a competitor.
            throw new RegistrationException(
                'That email address cannot be registered. If you already have a login, '
                . 'use password reset instead.'
            );
        }

        $joiningExistingOrg = $invite['org_id'] !== null;

        $vatCheck = null;
        $orgFields = [];

        if ($joiningExistingOrg) {
            $orgId = (string) $invite['org_id'];
        } else {
            $orgFields = $this->validateNewOrganisation($input, $invite);
            $orgId = Uuid::v7();

            // VIES is consulted outside the transaction: it is a network call to
            // a service with no SLA, and holding row locks across it would let
            // an EU-side outage block every write in the system.
            if ($this->vies !== null && $orgFields['vat_number'] !== null) {
                $vatCheck = $this->vies->check(
                    $orgFields['vat_number'],
                    $orgFields['country']
                );
            }
        }

        $userId = Uuid::v7();
        $handle = $this->resolveHandle($input['display_handle'] ?? null, $fullName);
        $role = (string) $invite['grants_role'];

        $result = Db::transaction($this->pdo, function (PDO $pdo) use (
            $orgId, $userId, $inviteId, $joiningExistingOrg, $orgFields, $vatCheck,
            $email, $emailBidx, $fullName, $handle, $role, $passwordHash, $input, $ipHash
        ): array {
            if (!$joiningExistingOrg) {
                $accountRef = $this->createOrganisation($pdo, $orgId, $orgFields, $vatCheck);
            } else {
                $stmt = $pdo->prepare(
                    'SELECT account_ref, status FROM organisations WHERE id = ? FOR UPDATE'
                );
                $stmt->execute([$orgId]);
                $org = $stmt->fetch();

                if ($org === false) {
                    throw new RegistrationException('The account on this invitation no longer exists.');
                }

                if (in_array($org['status'], ['suspended', 'closed'], true)) {
                    throw new RegistrationException(
                        'This account is not currently open for new users. '
                        . 'Please contact your account manager.'
                    );
                }

                $accountRef = (string) $org['account_ref'];
            }

            $this->insertUser($pdo, $userId, $orgId, [
                'email' => $email,
                'email_bidx' => $emailBidx,
                'full_name' => $fullName,
                'job_title' => $input['job_title'] ?? null,
                'phone' => $input['phone'] ?? null,
                'handle' => $handle,
                'role' => $role,
                'password_hash' => $passwordHash,
            ]);

            // Inside the transaction: a rolled-back registration must not burn
            // a use of the invitation.
            $this->invites->consume($inviteId, $userId, $ipHash);

            $stmt = $pdo->prepare('SELECT status FROM organisations WHERE id = ?');
            $stmt->execute([$orgId]);

            return [
                'account_ref' => $accountRef,
                'org_status' => (string) $stmt->fetchColumn(),
            ];
        });

        $this->audit->record(
            action: 'user.register',
            actorId: $userId,
            actorRole: $role,
            entityType: 'users',
            entityId: $userId,
            metadata: [
                'org_id' => Uuid::toString($orgId),
                'invite_id' => Uuid::toString($inviteId),
                'joined_existing_org' => $joiningExistingOrg,
                'vat_outcome' => $vatCheck['outcome'] ?? null,
            ],
            actorIpHash: $ipHash
        );

        $isActive = $result['org_status'] === 'active';

        return [
            'user_id' => Uuid::toString($userId),
            'org_id' => Uuid::toString($orgId),
            'account_ref' => $result['account_ref'],
            'org_status' => $result['org_status'],
            'vat_check' => $vatCheck,
            'order_ceiling_cents' => $isActive ? null : self::UNVERIFIED_ORDER_CEILING_CENTS,
            'next_steps' => $this->nextSteps($result['org_status'], $vatCheck),
        ];
    }

    /**
     * @param array<string, mixed> $input
     * @param array<string, mixed> $invite
     * @return array{
     *     legal_name: string, trading_name: ?string, vat_number: ?string,
     *     country: string, registry_number: ?string, registered_address: ?string
     * }
     */
    private function validateNewOrganisation(array $input, array $invite): array
    {
        $legalName = trim((string) ($input['legal_name'] ?? ''));
        $country = strtoupper(trim((string) ($input['country'] ?? '')));
        $vat = trim((string) ($input['vat_number'] ?? ''));

        if (mb_strlen($legalName) < 2) {
            throw new RegistrationException(
                'Please provide the registered legal name of the business.'
            );
        }

        if (preg_match('/^[A-Z]{2}$/', $country) !== 1) {
            throw new RegistrationException(
                'Please select the country of registration.'
            );
        }

        // An invite issued for a specific company must not be redeemed to
        // onboard a different one, or the issuer's decision means nothing.
        $intended = $invite['intended_legal_name'];
        if (is_string($intended) && $intended !== ''
            && !$this->namesPlausiblyMatch($intended, $legalName)) {
            throw new RegistrationException(
                'The business name does not match the invitation. '
                . 'Please contact your account manager.'
            );
        }

        $intendedVat = $invite['intended_vat_number'];
        if (is_string($intendedVat) && $intendedVat !== '') {
            if ($vat === '' || VatNumber::format($vat, $country) !== $intendedVat) {
                throw new RegistrationException(
                    'The VAT number does not match the invitation.'
                );
            }
        }

        if ($vat === '') {
            // Non-VAT-registered businesses exist and are legitimate customers;
            // they simply cannot be zero-rated and are flagged for manual KYB.
            $vatNumber = null;
        } elseif (!VatNumber::isPlausible($vat, $country)) {
            throw new RegistrationException(
                'That VAT number is not valid. Please check it and try again.'
            );
        } else {
            $vatNumber = VatNumber::format($vat, $country);
        }

        return [
            'legal_name' => $legalName,
            'trading_name' => self::nullIfBlank($input['trading_name'] ?? null),
            'vat_number' => $vatNumber,
            'country' => $country,
            'registry_number' => self::nullIfBlank($input['registry_number'] ?? null),
            'registered_address' => self::nullIfBlank($input['registered_address'] ?? null),
        ];
    }

    /**
     * @param array<string, mixed>      $fields
     * @param array<string, mixed>|null $vatCheck
     */
    private function createOrganisation(
        PDO $pdo,
        string $orgId,
        array $fields,
        ?array $vatCheck
    ): string {
        $accountRef = $this->nextAccountRef($pdo);

        // A VIES pass is necessary but not sufficient for 'active': it proves
        // the number is registered, not that the person registering controls
        // the business. Staff sign-off remains a manual step.
        $stmt = $pdo->prepare(
            'INSERT INTO organisations
                (id, account_ref, legal_name, trading_name, country, vat_number,
                 vat_valid, vat_checked_at, vat_check_ref, registry_number,
                 registered_address, status, tax_exempt, credit_limit_cents,
                 payment_terms_days)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );

        $vatValid = $vatCheck === null ? null : $vatCheck['valid'];

        $stmt->execute([
            $orgId,
            $accountRef,
            $fields['legal_name'],
            $fields['trading_name'],
            $fields['country'],
            $fields['vat_number'],
            $vatValid === null ? null : (int) $vatValid,
            $vatCheck !== null && $vatCheck['valid'] === true
                ? (new \DateTimeImmutable((string) $vatCheck['checked_at']))
                    ->format('Y-m-d H:i:s.u')
                : null,
            $vatCheck['consultation_ref'] ?? null,
            $fields['registry_number'],
            $fields['registered_address'] ?? ($vatCheck['address'] ?? null),
            'pending_verification',
            0,
            0,
            0,
        ]);

        if ($vatCheck !== null) {
            $this->recordKybCheck($pdo, $orgId, $vatCheck, $fields['legal_name']);
        }

        return $accountRef;
    }

    /**
     * @param array<string, mixed> $vatCheck
     */
    private function recordKybCheck(
        PDO $pdo,
        string $orgId,
        array $vatCheck,
        string $declaredName
    ): void {
        $notes = sprintf(
            "VIES automated check.\nDeclared name: %s\nVIES name: %s\nConsultation: %s\nError: %s",
            $declaredName,
            $vatCheck['name'] ?? '(not returned)',
            $vatCheck['consultation_ref'] ?? '(none)',
            $vatCheck['error'] ?? '(none)'
        );

        $checkId = Uuid::v7();

        $stmt = $pdo->prepare(
            'INSERT INTO kyb_checks
                (id, org_id, check_type, outcome, source, notes_enc, performed_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6), ?)'
        );

        $stmt->execute([
            $checkId,
            $orgId,
            'vies_vat',
            (string) $vatCheck['outcome'],
            'VIES',
            $this->cipher->seal($notes, 'kyb_checks', 'notes_enc', $checkId),
            // Re-verify annually: registrations get cancelled.
            (new \DateTimeImmutable('+1 year'))->format('Y-m-d H:i:s.u'),
        ]);
    }

    /**
     * @param array{
     *     email:string, email_bidx:string, full_name:string, job_title:?string,
     *     phone:?string, handle:string, role:string, password_hash:string
     * } $data
     */
    private function insertUser(PDO $pdo, string $userId, string $orgId, array $data): void
    {
        $phone = self::nullIfBlank($data['phone']);

        $stmt = $pdo->prepare(
            'INSERT INTO users
                (id, org_id, kind, role, email_enc, email_bidx, full_name_enc,
                 job_title_enc, phone_enc, phone_bidx, display_handle,
                 password_hash, password_set_at, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6), ?)'
        );

        $stmt->execute([
            $userId,
            $orgId,
            'customer',
            $data['role'],
            $this->cipher->seal($data['email'], 'users', 'email_enc', $userId),
            $data['email_bidx'],
            $this->cipher->seal($data['full_name'], 'users', 'full_name_enc', $userId),
            $this->cipher->sealNullable(
                self::nullIfBlank($data['job_title']),
                'users',
                'job_title_enc',
                $userId
            ),
            $this->cipher->sealNullable($phone, 'users', 'phone_enc', $userId),
            $phone === null ? null : $this->blindIndex->compute($phone, 'users', 'phone_bidx'),
            $data['handle'],
            $data['password_hash'],
            'active',
        ]);
    }

    private function emailInUse(string $emailBidx): bool
    {
        // Check every loaded index version, or a rotation in progress would let
        // a duplicate account through.
        $stmt = $this->pdo->prepare('SELECT 1 FROM users WHERE email_bidx = ? LIMIT 1');
        $stmt->execute([$emailBidx]);

        return $stmt->fetchColumn() !== false;
    }

    /**
     * Sequential, human-quotable account reference.
     *
     * Locked with GET_LOCK rather than MAX()+1 in a bare SELECT: two concurrent
     * registrations would otherwise both read the same maximum and collide on
     * the unique index.
     */
    private function nextAccountRef(PDO $pdo): string
    {
        $lock = $pdo->prepare('SELECT GET_LOCK(?, ?)');
        $lock->execute(['manager2_account_ref', 5]);

        if ((int) $lock->fetchColumn() !== 1) {
            throw new \RuntimeException('Could not allocate an account reference.');
        }

        try {
            $max = $pdo->query(
                "SELECT COALESCE(MAX(CAST(SUBSTRING(account_ref, 5) AS UNSIGNED)), 0)
                   FROM organisations
                  WHERE account_ref LIKE 'ACC-%'"
            )?->fetchColumn();

            return sprintf('ACC-%06d', ((int) $max) + 1);
        } finally {
            $release = $pdo->prepare('SELECT RELEASE_LOCK(?)');
            $release->execute(['manager2_account_ref']);
        }
    }

    /**
     * Tolerant company-name comparison.
     *
     * Compares on alphanumerics only, with common legal-form suffixes removed,
     * so "Padaria Central, Lda." matches "PADARIA CENTRAL LDA". Deliberately
     * tolerant rather than exact — an exact match would reject most legitimate
     * registrations over punctuation — and deliberately not fuzzy beyond that:
     * a genuine mismatch should reach a human.
     */
    private function namesPlausiblyMatch(string $a, string $b): bool
    {
        $normalise = static function (string $name): string {
            $name = mb_strtolower(trim($name), 'UTF-8');
            $name = (string) preg_replace(
                '/\b(lda|ltd|limited|s\.?a\.?|unipessoal|gmbh|bv|nv|srl|spa|sarl|oy|ab|as|inc|llc)\b/u',
                '',
                $name
            );

            return (string) preg_replace('/[^a-z0-9]/u', '', $name);
        };

        $na = $normalise($a);
        $nb = $normalise($b);

        if ($na === '' || $nb === '') {
            return false;
        }

        return $na === $nb
            || str_contains($na, $nb)
            || str_contains($nb, $na)
            || levenshtein(substr($na, 0, 255), substr($nb, 0, 255)) <= 2;
    }

    /**
     * Derive a cosmetic handle. Initials by default — enough for a UI avatar,
     * and it keeps a full name out of shared screens in a warehouse.
     */
    private function resolveHandle(?string $requested, string $fullName): string
    {
        $requested = self::nullIfBlank($requested);

        if ($requested !== null) {
            $clean = (string) preg_replace('/[^A-Za-z0-9._-]/', '', $requested);

            if (mb_strlen($clean) >= 2) {
                return mb_substr($clean, 0, 64);
            }
        }

        $initials = '';
        foreach (preg_split('/\s+/', trim($fullName)) ?: [] as $part) {
            if ($part !== '') {
                $initials .= mb_strtoupper(mb_substr($part, 0, 1), 'UTF-8');
            }
        }

        return mb_substr($initials === '' ? 'U' : $initials, 0, 4)
            . '-' . strtoupper(bin2hex(random_bytes(2)));
    }

    /**
     * @param array<string, mixed>|null $vatCheck
     * @return list<string>
     */
    private function nextSteps(string $orgStatus, ?array $vatCheck): array
    {
        if ($orgStatus === 'active') {
            return ['Your account is verified. You can order without restriction.'];
        }

        $steps = [];

        if ($vatCheck === null) {
            $steps[] = 'We will verify your business registration details.';
        } elseif ($vatCheck['outcome'] === 'pass') {
            $steps[] = 'Your VAT number was confirmed against VIES. '
                . 'An account manager will complete verification, usually within one business day.';
        } elseif ($vatCheck['outcome'] === 'inconclusive') {
            $steps[] = 'The EU VAT service did not respond. We will retry automatically; '
                . 'this does not delay your first order.';
        } else {
            $steps[] = 'We could not confirm your VAT number. An account manager will contact you.';
        }

        $steps[] = sprintf(
            'Until verification completes you can order up to %s.',
            number_format(self::UNVERIFIED_ORDER_CEILING_CENTS / 100, 2) . ' EUR'
        );
        $steps[] = 'Credit terms become available after verification.';

        return $steps;
    }

    private static function nullIfBlank(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $trimmed = trim($value);

        return $trimmed === '' ? null : $trimmed;
    }
}
