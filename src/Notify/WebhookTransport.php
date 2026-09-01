<?php

declare(strict_types=1);

namespace Manager2\Notify;

/**
 * Outbound HTTP notification for a chat or ops channel.
 *
 * Works with anything that accepts a JSON POST — Slack, Teams, Mattermost, a
 * self-hosted bot, or your own dispatcher service.
 *
 * Two deliberate properties:
 *
 *  - Outbound payloads are signed with the same HMAC scheme this system
 *    *requires* of inbound webhooks. Verifying everyone else's signatures while
 *    sending unauthenticated messages yourself is a double standard, and it
 *    means the receiving end cannot distinguish a real alert from a forged one.
 *  - The payload carries identifiers, not PII, so a misconfigured channel or a
 *    breach at the chat provider does not disclose customer data.
 *
 * Delivery is best-effort and must never block the transaction that triggered
 * it: a chat outage is not a reason to fail a payment. OpsNotifier enforces that.
 */
final class WebhookTransport implements Transport
{
    public function __construct(
        private readonly string $endpoint,
        private readonly string $signingSecret,
        private readonly string $baseUrl,
        private readonly string $channelName = 'chat',
        private readonly int $timeoutSeconds = 5
    ) {
        if (!str_starts_with($endpoint, 'https://')) {
            throw new \InvalidArgumentException(
                'Notification endpoint must be HTTPS: alerts carry order references and '
                . 'amounts, and a signature over a plaintext channel is still readable.'
            );
        }

        if (strlen($signingSecret) < 32) {
            throw new \InvalidArgumentException('Signing secret must be at least 32 bytes.');
        }
    }

    public function name(): string
    {
        return $this->channelName;
    }

    public function send(Notification $notification): void
    {
        $payload = json_encode(
            [
                'subject' => $notification->subject,
                'summary' => $notification->summary,
                'severity' => $notification->severity,
                'facts' => $notification->facts,
                'link' => $notification->linkPath === null
                    ? null
                    : rtrim($this->baseUrl, '/') . $notification->linkPath,
                'sent_at' => gmdate('c'),
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );

        $timestamp = (string) time();
        $signature = hash_hmac('sha256', $timestamp . '.' . $payload, $this->signingSecret);

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'timeout' => $this->timeoutSeconds,
                'ignore_errors' => true,
                'content' => $payload,
                'header' => implode("\r\n", [
                    'Content-Type: application/json',
                    'X-Manager2-Timestamp: ' . $timestamp,
                    'X-Manager2-Signature: sha256=' . $signature,
                    'User-Agent: manager2/1.0',
                ]),
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);

        $response = @file_get_contents($this->endpoint, false, $context);

        if ($response === false) {
            throw new \RuntimeException("Notification endpoint {$this->channelName} unreachable.");
        }

        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException(
                "Notification endpoint {$this->channelName} returned HTTP {$status}."
            );
        }
    }
}
