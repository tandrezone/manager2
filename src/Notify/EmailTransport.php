<?php

declare(strict_types=1);

namespace Manager2\Notify;

/**
 * Email notification — the record of what ops were told and when.
 *
 * Email is the channel of record here for unglamorous reasons: it is
 * self-hosted or contractually covered, it is retained under a policy you set,
 * and it is admissible in a dispute about whether a delivery window was ever
 * communicated. Chat transports are convenience alerts layered on top.
 *
 * Uses PHP's mail() to stay dependency-free as specified. For production,
 * replace the body of send() with an authenticated SMTP submission (or your
 * provider's API) so that failures are visible: mail() returning true means
 * only that the local MTA accepted the message, never that it was delivered.
 */
final class EmailTransport implements Transport
{
    /** @param list<string> $recipients */
    public function __construct(
        private readonly array $recipients,
        private readonly string $fromAddress,
        private readonly string $baseUrl,
        private readonly string $subjectPrefix = '[manager2]'
    ) {
        if ($recipients === []) {
            throw new \InvalidArgumentException('At least one recipient is required.');
        }

        foreach ($recipients as $recipient) {
            if (filter_var($recipient, FILTER_VALIDATE_EMAIL) === false) {
                throw new \InvalidArgumentException("Invalid recipient '{$recipient}'.");
            }
        }
    }

    public function name(): string
    {
        return 'email';
    }

    public function send(Notification $notification): void
    {
        $subject = sprintf(
            '%s%s %s',
            $this->subjectPrefix,
            $notification->severity === 'urgent' ? ' URGENT' : '',
            $notification->subject
        );

        // Strip CR/LF from anything that reaches a header: an injected newline
        // in a subject lets an attacker append arbitrary headers, including Bcc.
        $subject = str_replace(["\r", "\n"], ' ', $subject);

        $headers = implode("\r\n", [
            'From: ' . $this->fromAddress,
            'Content-Type: text/plain; charset=utf-8',
            'Content-Transfer-Encoding: 8bit',
            'X-Auto-Response-Suppress: All',
            'Auto-Submitted: auto-generated',
        ]);

        $body = $notification->toPlainText($this->baseUrl);
        $failed = [];

        foreach ($this->recipients as $recipient) {
            if (!@mail($recipient, $subject, $body, $headers)) {
                $failed[] = $recipient;
            }
        }

        if ($failed !== []) {
            throw new \RuntimeException(
                'Local MTA rejected the notification for: ' . implode(', ', $failed)
            );
        }
    }
}
