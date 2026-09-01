<?php

declare(strict_types=1);

namespace Manager2\Payments;

/**
 * HMAC signature verification for inbound payment webhooks.
 *
 * A payment webhook endpoint is, by construction, an unauthenticated public URL
 * that moves money in your database. Everything below exists because each of
 * these mistakes has cost somebody real money:
 *
 * 1. VERIFY AGAINST THE RAW BODY.
 *    Signatures cover the exact bytes sent. `json_decode` then `json_encode`
 *    changes key order, whitespace, unicode escaping and float formatting, so a
 *    re-serialised body will not verify — and the usual "fix" is to stop
 *    verifying. Read `php://input` once, verify, then parse.
 *
 * 2. COMPARE IN CONSTANT TIME.
 *    `==` on a signature leaks a byte-at-a-time timing oracle that lets an
 *    attacker forge a signature in a few thousand requests. `hash_equals` only.
 *
 * 3. BIND A TIMESTAMP.
 *    A signature alone is replayable forever: capture one "payment settled"
 *    callback and resend it. Sign `timestamp.body` and reject anything outside
 *    a tolerance window.
 *
 * 4. BE IDEMPOTENT ANYWAY.
 *    PSPs legitimately retry, sometimes for days, sometimes concurrently. The
 *    UNIQUE constraint on (provider, event_id) is the real defence; the
 *    timestamp window only bounds the replay horizon.
 *
 * 5. FAIL CLOSED, AND SAY LITTLE.
 *    Any verification failure is a 400 with no detail. Explaining *why* a
 *    signature was rejected is a forgery tutorial.
 *
 * 6. NEVER TRUST THE AMOUNT IN THE PAYLOAD.
 *    Even a correctly signed callback states what the PSP says was paid.
 *    Reconcile it against the order total before marking anything as settled;
 *    the caller does this in PaymentWebhookController.
 */
final class WebhookVerifier
{
    /** Reject anything older or further in the future than this. */
    private const DEFAULT_TOLERANCE_SECONDS = 300;

    /** Refuse to hash unbounded input. */
    private const MAX_BODY_BYTES = 1_048_576;

    public function __construct(
        private readonly string $secret,
        private readonly string $algorithm = 'sha256',
        private readonly int $toleranceSeconds = self::DEFAULT_TOLERANCE_SECONDS
    ) {
        if (strlen($this->secret) < 16) {
            throw new \InvalidArgumentException('Webhook secret is too short.');
        }

        if (!in_array($this->algorithm, hash_hmac_algos(), true)) {
            throw new \InvalidArgumentException("Unsupported HMAC algorithm '{$this->algorithm}'.");
        }
    }

    /**
     * Verify a signature over `timestamp . '.' . rawBody`.
     *
     * @param string $rawBody          bytes exactly as received
     * @param string $signatureHeader  hex or base64 digest, optionally prefixed
     *                                 (`sha256=...`) or in a multi-value scheme
     *                                 (`t=...,v1=...`)
     * @param string $timestampHeader  unix seconds, or ISO-8601
     *
     * @throws WebhookVerificationException
     */
    public function verify(string $rawBody, string $signatureHeader, string $timestampHeader): void
    {
        if ($rawBody === '') {
            throw new WebhookVerificationException('Empty request body.');
        }

        if (strlen($rawBody) > self::MAX_BODY_BYTES) {
            throw new WebhookVerificationException('Request body exceeds the accepted size.');
        }

        $timestamp = $this->parseTimestamp($timestampHeader ?: $this->extractField($signatureHeader, 't'));
        $drift = abs(time() - $timestamp);

        if ($drift > $this->toleranceSeconds) {
            throw new WebhookVerificationException(sprintf(
                'Timestamp outside the %d second tolerance (drift %ds).',
                $this->toleranceSeconds,
                $drift
            ));
        }

        $expected = hash_hmac($this->algorithm, $timestamp . '.' . $rawBody, $this->secret, true);

        foreach ($this->candidateDigests($signatureHeader) as $candidate) {
            if (hash_equals($expected, $candidate)) {
                return;
            }
        }

        throw new WebhookVerificationException('Signature mismatch.');
    }

    /**
     * Verify a signature computed over the body alone, no timestamp.
     *
     * Some providers still work this way. Such an endpoint is replayable, so
     * idempotency at the database level is not optional there — it is the only
     * thing standing between a retry and a double credit.
     *
     * @throws WebhookVerificationException
     */
    public function verifyBodyOnly(string $rawBody, string $signatureHeader): void
    {
        if ($rawBody === '' || strlen($rawBody) > self::MAX_BODY_BYTES) {
            throw new WebhookVerificationException('Body missing or too large.');
        }

        $expected = hash_hmac($this->algorithm, $rawBody, $this->secret, true);

        foreach ($this->candidateDigests($signatureHeader) as $candidate) {
            if (hash_equals($expected, $candidate)) {
                return;
            }
        }

        throw new WebhookVerificationException('Signature mismatch.');
    }

    /**
     * Decode a signature header into every plausible raw digest.
     *
     * Providers variously send bare hex, bare base64, `sha256=<hex>`,
     * `v1=<hex>`, or comma-separated multi-signature headers during a secret
     * rotation. All candidates are compared in constant time and the header
     * itself is never used to select a code path, so a malformed header cannot
     * steer verification.
     *
     * @return list<string> raw binary digests
     */
    private function candidateDigests(string $header): array
    {
        $header = trim($header);

        if ($header === '') {
            throw new WebhookVerificationException('Missing signature header.');
        }

        $tokens = [];

        foreach (preg_split('/[,\s]+/', $header) ?: [] as $part) {
            if ($part === '') {
                continue;
            }

            // Strip a scheme prefix such as 'sha256=' or 'v1='.
            $value = str_contains($part, '=') && !str_ends_with($part, '=')
                ? substr($part, (int) strpos($part, '=') + 1)
                : $part;

            if ($value !== '') {
                $tokens[] = $value;
            }
        }

        $expectedLength = strlen(hash($this->algorithm, '', true));
        $digests = [];

        foreach ($tokens as $token) {
            if (preg_match('/^[0-9a-fA-F]+$/', $token) === 1 && strlen($token) % 2 === 0) {
                $raw = hex2bin($token);
                if ($raw !== false && strlen($raw) === $expectedLength) {
                    $digests[] = $raw;
                }
            }

            $raw = base64_decode($token, true);
            if ($raw !== false && strlen($raw) === $expectedLength) {
                $digests[] = $raw;
            }
        }

        if ($digests === []) {
            throw new WebhookVerificationException('No decodable signature in header.');
        }

        return $digests;
    }

    /** Pull `t=...` out of a compound signature header. */
    private function extractField(string $header, string $field): string
    {
        foreach (preg_split('/[,\s]+/', $header) ?: [] as $part) {
            if (str_starts_with($part, $field . '=')) {
                return substr($part, strlen($field) + 1);
            }
        }

        return '';
    }

    private function parseTimestamp(string $value): int
    {
        $value = trim($value);

        if ($value === '') {
            throw new WebhookVerificationException('Missing timestamp.');
        }

        if (ctype_digit($value)) {
            $seconds = (int) $value;

            // Some providers send milliseconds. Anything past ~2286 in seconds
            // is certainly a millisecond value.
            return $seconds > 10_000_000_000 ? intdiv($seconds, 1000) : $seconds;
        }

        try {
            return (new \DateTimeImmutable($value))->getTimestamp();
        } catch (\Exception) {
            throw new WebhookVerificationException('Unparseable timestamp.');
        }
    }

    /**
     * Generate a signature. Used only by tests and by the outbound notifier —
     * never call this on an inbound path.
     */
    public function sign(string $rawBody, ?int $timestamp = null): array
    {
        $timestamp ??= time();

        return [
            'timestamp' => (string) $timestamp,
            'signature' => 'sha256=' . hash_hmac(
                $this->algorithm,
                $timestamp . '.' . $rawBody,
                $this->secret
            ),
        ];
    }
}
