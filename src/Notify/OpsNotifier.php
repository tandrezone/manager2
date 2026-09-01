<?php

declare(strict_types=1);

namespace Manager2\Notify;

use Manager2\Audit\AuditLog;

/**
 * Fan a notification out across transports without ever letting a transport
 * failure propagate into the caller.
 *
 * The invariant: notification is a side effect of a committed fact, never a
 * precondition for it. A payment that settled has settled whether or not the
 * warehouse chat is reachable. So every transport failure is caught, recorded
 * in the audit log, and swallowed — and because it is recorded, a silently
 * broken channel is discoverable rather than merely silent.
 *
 * Call this AFTER the transaction commits. Calling it inside means a chat
 * timeout holds row locks for its whole duration, and a rollback after a
 * successful send leaves ops chasing an order that does not exist.
 */
final class OpsNotifier
{
    /** @var list<Transport> */
    private array $transports;

    /** @param list<Transport> $transports */
    public function __construct(
        array $transports,
        private readonly AuditLog $audit
    ) {
        $this->transports = $transports;
    }

    /**
     * @return array{delivered: list<string>, failed: array<string, string>}
     */
    public function dispatch(Notification $notification): array
    {
        $delivered = [];
        $failed = [];

        foreach ($this->transports as $transport) {
            if ($notification->channels !== []
                && !in_array($transport->name(), $notification->channels, true)) {
                continue;
            }

            try {
                $transport->send($notification);
                $delivered[] = $transport->name();
            } catch (\Throwable $e) {
                $failed[$transport->name()] = $e->getMessage();
            }
        }

        try {
            $this->audit->record(
                action: 'notification.dispatch',
                metadata: [
                    'subject' => $notification->subject,
                    'severity' => $notification->severity,
                    'delivered' => $delivered,
                    'failed' => array_keys($failed),
                    'failure_detail' => $failed,
                ]
            );
        } catch (\Throwable) {
            // The audit log itself is unavailable. Nothing useful remains to be
            // done from inside a notification helper; the DB-level monitoring
            // that watches audit_log write failures is the correct alarm here.
        }

        return ['delivered' => $delivered, 'failed' => $failed];
    }
}
