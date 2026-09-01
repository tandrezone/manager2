<?php

declare(strict_types=1);

namespace Manager2\Notify;

/**
 * An operational notification.
 *
 * Carries only identifiers and amounts. Notification transports are the easiest
 * place to leak PII out of an otherwise carefully encrypted system: a chat
 * message reading "New order from Ana Ribeiro, deliver to Rua X 12" copies
 * personal data into a third-party service with its own retention, its own
 * jurisdiction, and its own breach history, outside every control in this
 * codebase and outside the ROPA.
 *
 * So the rule is structural, not a matter of discipline at the call site:
 * notifications reference `ORD-2026-000148` and `ACC-004821`, and the recipient
 * opens the portal to see who and where.
 */
final class Notification
{
    /**
     * @param array<string, string|int|float|bool|null> $facts identifiers and amounts only
     * @param list<string>                              $channels transport names; empty = all
     */
    public function __construct(
        public readonly string $subject,
        public readonly string $summary,
        public readonly array $facts = [],
        public readonly ?string $linkPath = null,
        public readonly string $severity = 'info',
        public readonly array $channels = []
    ) {
        if (!in_array($severity, ['info', 'action_required', 'urgent'], true)) {
            throw new \InvalidArgumentException("Unknown severity '{$severity}'.");
        }

        foreach ($facts as $key => $value) {
            if (is_string($value) && preg_match('/@|\+\d{6,}/', $value) === 1) {
                // Cheap tripwire, not a guarantee. It catches the common
                // accident of dropping an email address or phone number into a
                // notification during a late-night fix.
                throw new \InvalidArgumentException(sprintf(
                    'Notification fact "%s" looks like contact PII. Send an identifier '
                    . 'and let the recipient open the portal.',
                    $key
                ));
            }
        }
    }

    public function toPlainText(string $baseUrl = ''): string
    {
        $lines = [$this->summary, ''];

        foreach ($this->facts as $key => $value) {
            $label = ucfirst(str_replace('_', ' ', $key));
            $lines[] = sprintf('%-22s %s', $label . ':', self::stringify($value));
        }

        if ($this->linkPath !== null) {
            $lines[] = '';
            $lines[] = rtrim($baseUrl, '/') . $this->linkPath;
        }

        return implode("\n", $lines) . "\n";
    }

    private static function stringify(string|int|float|bool|null $value): string
    {
        return match (true) {
            is_bool($value) => $value ? 'yes' : 'no',
            $value === null => '-',
            default => (string) $value,
        };
    }
}
