<?php

declare(strict_types=1);

namespace Manager2\Crypto;

/**
 * Searchable index over an encrypted column.
 *
 * The problem: `users.email_enc` is randomised AES-GCM, so
 * `WHERE email_enc = ?` can never match. But login has to find a user by email.
 *
 * The solution: store `HMAC-SHA256(column_subkey, normalise(value))` alongside
 * the ciphertext and query on that. The index key is derived from a root that
 * is independent of the encryption root, so leaking the index does not leak
 * plaintext.
 *
 * What this leaks, stated plainly
 * -------------------------------
 * Equality. Two rows with the same normalised value produce the same index, so
 * an attacker with the table can see *that* two accounts share an email or
 * phone number, and can confirm a guessed value if they also hold the index key.
 * They cannot recover a value from the index alone — HMAC is preimage
 * resistant — but a low-entropy domain (a country dialling code, a postcode)
 * is brute-forceable *if the key is also compromised*. So:
 *
 *   - Only index columns that genuinely need exact-match lookup.
 *   - Never index a low-entropy field where correlation would be sensitive.
 *   - Do not expect range or prefix search; this is equality only.
 *
 * Normalisation must be lossless-for-identity and stable forever: change the
 * rule and every stored index silently stops matching. Any change therefore
 * requires a rebuild migration, exactly like a key rotation.
 */
final class BlindIndex
{
    public function __construct(private readonly KeyRing $keyRing) {}

    /** Compute the 32-byte index for a value. */
    public function compute(string $value, string $table, string $column): string
    {
        $version = $this->keyRing->activeVersion(KeyRing::PURPOSE_BLIND_INDEX);

        return $this->computeForVersion($value, $table, $column, $version);
    }

    /**
     * Compute under a specific key version — needed during a rotation, when
     * lookups must try both the old and the new index.
     */
    public function computeForVersion(
        string $value,
        string $table,
        string $column,
        int $version
    ): string {
        $key = $this->keyRing->subkey(
            KeyRing::PURPOSE_BLIND_INDEX,
            $version,
            $table,
            $column
        );

        return hash_hmac('sha256', $this->normalise($column, $value), $key, true);
    }

    /**
     * Every loaded version's index for a value, newest first.
     *
     * Use with `WHERE email_bidx IN (?, ?)` so a rotation does not lock anyone
     * out mid-migration.
     *
     * @return list<string>
     */
    public function computeAllVersions(string $value, string $table, string $column): array
    {
        $versions = $this->keyRing->loadedVersions(KeyRing::PURPOSE_BLIND_INDEX);
        rsort($versions);

        return array_map(
            fn (int $v): string => $this->computeForVersion($value, $table, $column, $v),
            $versions
        );
    }

    /**
     * Canonicalise a value so that equivalent inputs index identically.
     *
     * Locked to the column so the rule is explicit and reviewable rather than
     * guessed from the value's shape at the call site.
     */
    public function normalise(string $column, string $value): string
    {
        $value = trim($value);

        return match (true) {
            str_contains($column, 'email') => $this->normaliseEmail($value),
            str_contains($column, 'phone') => $this->normalisePhone($value),
            str_contains($column, 'postcode') => strtoupper(
                (string) preg_replace('/\s+/', '', $value)
            ),
            str_contains($column, 'vat') => strtoupper(
                (string) preg_replace('/[^A-Z0-9]/i', '', $value)
            ),
            default => mb_strtolower($value, 'UTF-8'),
        };
    }

    /**
     * Lowercase the whole address.
     *
     * The local part of an email is case-sensitive per RFC 5321, but every mail
     * provider in practice treats it case-insensitively, and treating
     * `A@x.com` and `a@x.com` as different accounts creates a duplicate-account
     * and account-takeover-confusion problem far worse than the spec deviation.
     * Gmail's dot and +tag aliases are deliberately NOT collapsed: doing so
     * would silently merge addresses the user considers distinct.
     */
    private function normaliseEmail(string $email): string
    {
        $at = strrpos($email, '@');

        if ($at === false) {
            return mb_strtolower($email, 'UTF-8');
        }

        return mb_strtolower(substr($email, 0, $at), 'UTF-8')
            . '@'
            . mb_strtolower(substr($email, $at + 1), 'UTF-8');
    }

    /**
     * Reduce a phone number to digits, keeping a leading '+'.
     *
     * Callers should store E.164 to begin with. This is a safety net for
     * '+351 912 345 678' vs '+351912345678', not a substitute for validation:
     * it cannot know that '912345678' and '+351912345678' are the same line.
     */
    private function normalisePhone(string $phone): string
    {
        $digits = preg_replace('/[^0-9]/', '', $phone) ?? '';

        return str_starts_with(trim($phone), '+') ? '+' . $digits : $digits;
    }
}
