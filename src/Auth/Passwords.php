<?php

declare(strict_types=1);

namespace Manager2\Auth;

/**
 * Argon2id password hashing.
 *
 * Why Argon2id: it is memory-hard, so an attacker with GPUs or ASICs gains far
 * less advantage than against bcrypt or PBKDF2. The `id` variant combines
 * Argon2i's side-channel resistance on the first pass with Argon2d's
 * GPU-resistance on later passes, and is the variant RFC 9106 recommends for
 * password storage.
 *
 * Parameters below follow OWASP's current floor with headroom:
 *
 *   memory_cost 65536 KiB (64 MiB)   the dominant cost to an attacker
 *   time_cost   3 passes
 *   threads     2 lanes
 *
 * Tuning
 * ------
 * Target 250-500 ms per hash on production hardware. Faster wastes available
 * security; much slower turns your own login endpoint into a denial-of-service
 * amplifier, since each attempt costs the server 64 MiB and hundreds of
 * milliseconds. Measure with `bin/bench-argon.php`, and remember the memory
 * cost is per concurrent hash: 64 MiB x 50 simultaneous logins is 3.2 GiB.
 * Size php-fpm's worker count against that, or the first credential-stuffing
 * wave will OOM the box rather than crack anything.
 *
 * A note on pepper
 * ----------------
 * A server-side pepper (a secret HMAC applied before hashing) is deliberately
 * not used here. It protects only against an attacker who has the database but
 * not the application secrets — the same threat model as the field encryption
 * already in place — while permanently coupling every stored hash to a secret
 * that cannot be rotated without every user resetting their password. The
 * complexity is not worth it. If you disagree, HMAC-SHA256 the password with a
 * versioned pepper before `password_hash`, and store the pepper version.
 */
final class Passwords
{
    private const ALGORITHM = PASSWORD_ARGON2ID;

    /** @var array{memory_cost:int, time_cost:int, threads:int} */
    private const OPTIONS = [
        'memory_cost' => 65536,
        'time_cost' => 3,
        'threads' => 2,
    ];

    /**
     * Upper bound on accepted password length.
     *
     * Argon2 has no short input limit the way bcrypt truncates at 72 bytes, so
     * long passphrases are fine and should be encouraged. The cap exists purely
     * so nobody can post a 10 MB body and make the server hash it.
     */
    private const MAX_LENGTH_BYTES = 4096;

    /** Minimum length. Length beats composition rules; NIST SP 800-63B agrees. */
    private const MIN_LENGTH_BYTES = 12;

    public static function hash(string $password): string
    {
        self::assertAcceptable($password);

        $hash = password_hash($password, self::ALGORITHM, self::OPTIONS);

        // Defensive: password_hash throws on failure in PHP 8, but a
        // misconfigured build without libargon2 would be a silent disaster.
        if ($hash === false || $hash === '') {
            throw new \RuntimeException('Argon2id hashing unavailable on this PHP build.');
        }

        return $hash;
    }

    /**
     * Verify a candidate password.
     *
     * `password_verify` is constant-time with respect to the hash comparison.
     * The dummy-hash branch matters just as much: without it, a request for a
     * non-existent account returns in microseconds while a real account takes
     * ~300 ms, which turns the login endpoint into an account-enumeration
     * oracle. Callers must therefore always reach this method, even when the
     * user lookup found nothing.
     */
    public static function verify(string $password, ?string $hash): bool
    {
        if ($hash === null || $hash === '') {
            self::burnTime();

            return false;
        }

        if (strlen($password) > self::MAX_LENGTH_BYTES) {
            return false;
        }

        return password_verify($password, $hash);
    }

    /**
     * True when a valid hash was produced under weaker parameters than current
     * policy. Call on every successful login and transparently upgrade — this
     * is the only moment the plaintext is available to rehash with.
     */
    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, self::ALGORITHM, self::OPTIONS);
    }

    /**
     * Spend roughly one hash's worth of work against a throwaway value.
     *
     * Uses the same parameters so the timing profile matches a real
     * verification. Cheaper tricks like `usleep(300000)` are distinguishable
     * under statistical analysis because they have almost no variance.
     */
    public static function burnTime(): void
    {
        password_verify(
            'timing-equalisation-not-a-secret',
            password_hash(bin2hex(random_bytes(16)), self::ALGORITHM, self::OPTIONS)
        );
    }

    /** @throws WeakPasswordException */
    private static function assertAcceptable(string $password): void
    {
        $length = strlen($password);

        if ($length < self::MIN_LENGTH_BYTES) {
            throw new WeakPasswordException(sprintf(
                'Password must be at least %d characters.',
                self::MIN_LENGTH_BYTES
            ));
        }

        if ($length > self::MAX_LENGTH_BYTES) {
            throw new WeakPasswordException('Password exceeds the maximum accepted length.');
        }

        // Cheap breach check. Wire this to a k-anonymity range query against
        // Have I Been Pwned, or a local Bloom filter of a breach corpus, rather
        // than imposing composition rules that push users toward 'P@ssw0rd1!'.
        if (self::isObviouslyGuessable($password)) {
            throw new WeakPasswordException(
                'This password appears in known breach corpora. Please choose another.'
            );
        }
    }

    private static function isObviouslyGuessable(string $password): bool
    {
        $lower = mb_strtolower($password, 'UTF-8');

        $blocklist = [
            'password', 'passw0rd', '123456789012', 'qwertyuiop',
            'letmein12345', 'administrator', 'manager2', 'welcome12345',
        ];

        foreach ($blocklist as $bad) {
            if ($lower === $bad || str_contains($lower, $bad)) {
                return true;
            }
        }

        // A single repeated character, however long.
        return (bool) preg_match('/^(.)\1+$/u', $password);
    }
}
