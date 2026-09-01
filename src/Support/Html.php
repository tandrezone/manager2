<?php

declare(strict_types=1);

namespace Manager2\Support;

/**
 * Output escaping and formatting helpers.
 *
 * `e()` is deliberately short. Escaping has to be so cheap to type that nobody
 * is tempted to skip it, and it must be the default path rather than something
 * remembered — every XSS I have seen in a PHP template was a single interpolation
 * where the author was in a hurry.
 */
final class Html
{
    /** Escape for an HTML text node or a quoted attribute value. */
    public static function e(?string $value): string
    {
        return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    /**
     * Escape for embedding inside a <script> block as JSON.
     *
     * HEX_TAG and HEX_AMP matter: without them a value containing `</script>`
     * terminates the block and everything after it is markup.
     */
    public static function json(mixed $value): string
    {
        return json_encode(
            $value,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
                | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );
    }

    /** Money from integer minor units. Never accepts a float. */
    public static function money(int $cents, string $currency = 'EUR'): string
    {
        $sign = $cents < 0 ? '-' : '';
        $abs = abs($cents);

        return sprintf(
            '%s%s %s',
            $sign,
            number_format(intdiv($abs, 100), 0, ',', ' ') . ',' . sprintf('%02d', $abs % 100),
            $currency
        );
    }

    /** A delivery window as '02 Sep, 09:00-12:00'. */
    public static function window(?string $start, ?string $end): string
    {
        if ($start === null) {
            return 'Not selected';
        }

        $from = new \DateTimeImmutable($start);
        $to = $end === null ? null : new \DateTimeImmutable($end);

        return $to === null
            ? $from->format('d M, H:i')
            : $from->format('d M, H:i') . '-' . $to->format('H:i');
    }

    /**
     * Per-session CSRF token.
     *
     * Bound to the session, compared with hash_equals. A cookie-only session
     * plus a state-changing POST is exactly the shape CSRF exploits, and
     * SameSite=Lax alone does not cover top-level POST navigation in every
     * browser, so the token is not redundant.
     */
    public static function csrfToken(): string
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new \LogicException('Start the session before issuing a CSRF token.');
        }

        if (!isset($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }

        return $_SESSION['csrf'];
    }

    public static function csrfValid(?string $submitted): bool
    {
        $expected = $_SESSION['csrf'] ?? null;

        return is_string($expected)
            && is_string($submitted)
            && hash_equals($expected, $submitted);
    }
}
