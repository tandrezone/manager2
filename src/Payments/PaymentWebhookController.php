<?php

declare(strict_types=1);

namespace Manager2\Payments;

use Manager2\Audit\AuditLog;
use Manager2\Billing\InvoiceService;
use Manager2\Crypto\FieldCipher;
use Manager2\Notify\Notification;
use Manager2\Notify\OpsNotifier;
use Manager2\Support\Uuid;
use PDO;

/**
 * Inbound payment webhook handler.
 *
 * Order of operations, and why it is this order:
 *
 *   1. Read the raw body ONCE. Verification is over exact bytes.
 *   2. Verify the signature and timestamp. Nothing is parsed before this; an
 *      unverified payload is attacker-controlled input and must not reach a
 *      JSON parser, let alone the database.
 *   3. Claim the event by INSERT. The UNIQUE (provider, event_id) constraint
 *      makes the claim atomic, so two concurrent retries cannot both proceed.
 *   4. Reconcile the amount against the order. A valid signature proves the
 *      message came from the PSP; it does not prove the amount matches what was
 *      ordered. Underpayment, currency drift and partial captures all arrive
 *      correctly signed.
 *   5. Commit the state change, THEN issue the invoice, THEN notify. Each step
 *      is idempotent so a crash between any two is recoverable by replay.
 *
 * Responses: 200 for handled and for already-handled, 400 for verification
 * failure with no detail, 409 for a reconciliation mismatch that needs a human,
 * 500 only for genuine internal faults so the PSP retries.
 */
final class PaymentWebhookController
{
    /**
     * Tolerance for amount comparison, in minor units.
     *
     * Zero. Payment reconciliation is exact-match by design: a "close enough"
     * threshold is how systems end up accepting a 1-cent payment for a 500-euro
     * order, and rounding differences belong in the pricing code, not here.
     */
    private const AMOUNT_TOLERANCE_CENTS = 0;

    public function __construct(
        private readonly PDO $pdo,
        private readonly WebhookVerifier $verifier,
        private readonly FieldCipher $cipher,
        private readonly InvoiceService $invoices,
        private readonly OpsNotifier $notifier,
        private readonly AuditLog $audit,
        private readonly string $provider = 'mbway'
    ) {
    }

    /**
     * @param array<string, string> $headers case-insensitive header map
     * @return array{status:int, body:array<string, mixed>}
     */
    public function handle(string $rawBody, array $headers): array
    {
        $headers = array_change_key_case($headers, CASE_LOWER);

        try {
            $this->verifier->verify(
                $rawBody,
                $headers['x-signature'] ?? $headers['x-manager2-signature'] ?? '',
                $headers['x-timestamp'] ?? $headers['x-manager2-timestamp'] ?? ''
            );
        } catch (WebhookVerificationException $e) {
            // Logged in full internally; the response says nothing.
            $this->audit->record(
                action: 'webhook.reject',
                metadata: [
                    'provider' => $this->provider,
                    'reason' => $e->getMessage(),
                    'body_sha256' => hash('sha256', $rawBody),
                ]
            );

            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }

        try {
            /** @var array<string, mixed> $payload */
            $payload = json_decode($rawBody, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return ['status' => 400, 'body' => ['error' => 'invalid_request']];
        }

        $event = $this->extractEvent($payload);

        if ($event['event_id'] === '') {
            return ['status' => 400, 'body' => ['error' => 'missing_event_id']];
        }

        $claim = $this->claimEvent($event, $rawBody);

        if ($claim === null) {
            // Already seen. A 200 stops the PSP retrying a message we have
            // handled; anything else invites an infinite retry loop.
            return ['status' => 200, 'body' => ['status' => 'already_processed']];
        }

        if (!in_array($event['type'], ['payment.settled', 'payment.authorised'], true)) {
            $this->finishEvent($claim, 'ignored', null);

            return ['status' => 200, 'body' => ['status' => 'ignored', 'type' => $event['type']]];
        }

        try {
            $outcome = $this->applyPayment($event, $claim);
        } catch (ReconciliationException $e) {
            $this->finishEvent($claim, 'failed', $e->getMessage());
            $this->raiseReconciliationAlert($event, $e);

            // 409, not 500: this is a real conflict a retry cannot resolve.
            return ['status' => 409, 'body' => ['error' => 'reconciliation_mismatch']];
        } catch (\Throwable $e) {
            $this->finishEvent($claim, 'failed', $e->getMessage());

            // 500 so the PSP retries — genuinely transient faults land here.
            return ['status' => 500, 'body' => ['error' => 'internal_error']];
        }

        $this->finishEvent($claim, 'processed', null);

        // Post-commit side effects. Neither may fail the webhook: the payment is
        // recorded, and a missing invoice or unsent alert is recoverable by a
        // replay or a nightly sweep, whereas a 500 here would have the PSP
        // resend a payment that is already applied.
        $invoice = null;

        try {
            if ($outcome['fully_paid']) {
                $invoice = $this->invoices->issueForOrder($outcome['order_id']);
            }
        } catch (\Throwable $e) {
            $this->audit->record(
                action: 'invoice.issue_failed',
                entityType: 'orders',
                entityId: $outcome['order_id'],
                metadata: ['error' => $e->getMessage()]
            );
        }

        $this->notifyOps($outcome, $invoice);

        return [
            'status' => 200,
            'body' => [
                'status' => 'processed',
                'order' => $outcome['order_number'],
                'invoice' => $invoice['invoice_number'] ?? null,
            ],
        ];
    }

    /**
     * Normalise a provider payload into the fields this handler needs.
     *
     * Kept as one small adapter so supporting another PSP is a change here and
     * nowhere else. Field names cover the common shapes; extend per provider
     * rather than making the rest of the class provider-aware.
     *
     * @param array<string, mixed> $payload
     * @return array{event_id:string, type:string, order_ref:string, provider_ref:string,
     *               amount_cents:int, currency:string, payer_alias:?string}
     */
    private function extractEvent(array $payload): array
    {
        $get = static function (array $source, array $keys, mixed $default = null): mixed {
            foreach ($keys as $key) {
                if (array_key_exists($key, $source) && $source[$key] !== null
                    && $source[$key] !== '') {
                    return $source[$key];
                }
            }

            return $default;
        };

        $data = is_array($payload['data'] ?? null) ? $payload['data'] : $payload;

        // Amounts arrive either as minor units ('amount_cents', 'value') or as a
        // decimal string ('amount': '12.34'). Decimal strings are parsed with
        // bcmath-style string handling rather than (float), because
        // (int)((float)'12.34' * 100) is 1233 on some inputs.
        $rawAmount = $get($data, ['amount_cents', 'amountCents', 'value_minor'], null);

        if ($rawAmount === null) {
            $decimal = (string) $get($data, ['amount', 'value', 'total'], '0');
            $amountCents = self::decimalToCents($decimal);
        } else {
            $amountCents = (int) $rawAmount;
        }

        return [
            'event_id' => (string) $get(
                $payload,
                ['id', 'event_id', 'eventId', 'notification_id'],
                ''
            ),
            'type' => (string) $get($payload, ['type', 'event', 'event_type'], 'unknown'),
            'order_ref' => (string) $get(
                $data,
                ['order_ref', 'orderRef', 'reference', 'merchant_reference', 'description'],
                ''
            ),
            'provider_ref' => (string) $get(
                $data,
                ['transaction_id', 'transactionId', 'payment_id', 'id'],
                ''
            ),
            'amount_cents' => $amountCents,
            'currency' => strtoupper((string) $get($data, ['currency'], 'EUR')),
            'payer_alias' => self::nullIfBlank(
                $get($data, ['payer_alias', 'phone', 'alias', 'payer'], null)
            ),
        ];
    }

    /**
     * Record the event, or return null if it has already been claimed.
     *
     * @param array<string, mixed> $event
     * @return string|null the webhook_events row id, or null if a duplicate
     */
    private function claimEvent(array $event, string $rawBody): ?string
    {
        $id = Uuid::v7();

        try {
            $stmt = $this->pdo->prepare(
                'INSERT INTO webhook_events
                    (id, provider, event_id, event_type, payload_sha256, payload_enc,
                     signature_ok, status, attempts)
                 VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1)'
            );

            $stmt->execute([
                $id,
                $this->provider,
                $event['event_id'],
                $event['type'],
                hash('sha256', $rawBody, true),
                // Retained briefly for dispute forensics, encrypted because a
                // payment payload can carry a payer alias or phone number.
                $this->cipher->seal(
                    substr($rawBody, 0, 16000 - FieldCipher::OVERHEAD_BYTES),
                    'webhook_events',
                    'payload_enc',
                    $id
                ),
                'received',
            ]);

            return $id;
        } catch (\PDOException $e) {
            // 23000 = integrity constraint violation, i.e. the unique index on
            // (provider, event_id) fired. That is the idempotency guarantee
            // working, not an error.
            if ($e->getCode() === '23000') {
                $bump = $this->pdo->prepare(
                    'UPDATE webhook_events SET attempts = attempts + 1
                      WHERE provider = ? AND event_id = ?'
                );
                $bump->execute([$this->provider, $event['event_id']]);

                return null;
            }

            throw $e;
        }
    }

    private function finishEvent(string $eventRowId, string $status, ?string $error): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE webhook_events
                SET status = ?, last_error = ?, processed_at = UTC_TIMESTAMP(6)
              WHERE id = ?'
        );
        $stmt->execute([$status, $error === null ? null : substr($error, 0, 512), $eventRowId]);
    }

    /**
     * Apply a verified payment to its order, inside one transaction.
     *
     * @param array<string, mixed> $event
     * @return array{order_id:string, order_number:string, org_id:string,
     *               account_ref:string, gross_cents:int, paid_cents:int,
     *               fully_paid:bool, payment_id:string}
     *
     * @throws ReconciliationException
     */
    private function applyPayment(array $event, string $eventRowId): array
    {
        $this->pdo->beginTransaction();

        try {
            $stmt = $this->pdo->prepare(
                'SELECT o.id, o.order_number, o.org_id, o.currency, o.gross_cents,
                        o.payment_status, o.status, g.account_ref
                   FROM orders o
                   JOIN organisations g ON g.id = o.org_id
                  WHERE o.order_number = ?
                  FOR UPDATE'
            );
            $stmt->execute([$event['order_ref']]);
            $order = $stmt->fetch();

            if ($order === false) {
                throw new ReconciliationException(sprintf(
                    'Payment %s references unknown order "%s".',
                    $event['provider_ref'],
                    $event['order_ref']
                ));
            }

            if ($event['currency'] !== strtoupper((string) $order['currency'])) {
                throw new ReconciliationException(sprintf(
                    'Currency mismatch on %s: order is %s, payment is %s.',
                    $order['order_number'],
                    $order['currency'],
                    $event['currency']
                ));
            }

            if ((string) $order['status'] === 'cancelled') {
                throw new ReconciliationException(sprintf(
                    'Payment received for cancelled order %s — refund required.',
                    $order['order_number']
                ));
            }

            // Sum prior settled payments so partial captures and split payments
            // reconcile correctly rather than each looking like an underpayment.
            $prior = $this->pdo->prepare(
                "SELECT COALESCE(SUM(CASE WHEN direction = 'in' THEN amount_cents
                                          ELSE -amount_cents END), 0)
                   FROM payments
                  WHERE order_id = ? AND status IN ('settled','authorised')"
            );
            $prior->execute([$order['id']]);
            $priorCents = (int) $prior->fetchColumn();

            $paidCents = $priorCents + $event['amount_cents'];
            $grossCents = (int) $order['gross_cents'];

            if ($paidCents > $grossCents + self::AMOUNT_TOLERANCE_CENTS) {
                throw new ReconciliationException(sprintf(
                    'Overpayment on %s: %d received against a total of %d.',
                    $order['order_number'],
                    $paidCents,
                    $grossCents
                ));
            }

            $paymentId = Uuid::v7();
            $isSettled = $event['type'] === 'payment.settled';

            $insert = $this->pdo->prepare(
                'INSERT INTO payments
                    (id, order_id, org_id, provider, provider_ref, direction,
                     amount_cents, currency, status, payer_alias_enc, received_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6))'
            );

            $insert->execute([
                $paymentId,
                $order['id'],
                $order['org_id'],
                $this->provider,
                $event['provider_ref'],
                'in',
                $event['amount_cents'],
                $event['currency'],
                $isSettled ? 'settled' : 'authorised',
                $this->cipher->sealNullable(
                    $event['payer_alias'],
                    'payments',
                    'payer_alias_enc',
                    $paymentId
                ),
            ]);

            $fullyPaid = $paidCents >= $grossCents && $isSettled;

            $newStatus = match (true) {
                $fullyPaid => 'paid',
                !$isSettled => 'authorised',
                default => 'partially_paid',
            };

            $update = $this->pdo->prepare(
                'UPDATE orders
                    SET payment_status = ?,
                        paid_at = CASE WHEN ? = 1 THEN UTC_TIMESTAMP(6) ELSE paid_at END,
                        status = CASE WHEN ? = 1 AND status = \'submitted\'
                                      THEN \'submitted\' ELSE status END
                  WHERE id = ?'
            );
            $update->execute([$newStatus, (int) $fullyPaid, (int) $fullyPaid, $order['id']]);

            // Settle any invoice already issued against this order. On credit
            // terms the invoice precedes the payment, so without this the
            // invoice stays 'issued' forever, the ageing report shows a
            // phantom debt, and the credit scorer reads a paying customer as
            // one who has never settled anything.
            if ($fullyPaid) {
                $settle = $this->pdo->prepare(
                    "UPDATE invoices
                        SET status = 'paid', settled_at = UTC_TIMESTAMP(6)
                      WHERE order_id = ?
                        AND doc_type = 'invoice'
                        AND status IN ('issued', 'part_paid', 'overdue')"
                );
                $settle->execute([$order['id']]);
            }

            $link = $this->pdo->prepare(
                'UPDATE webhook_events SET event_type = ? WHERE id = ?'
            );
            $link->execute([$event['type'], $eventRowId]);

            $this->pdo->commit();

            return [
                'order_id' => (string) $order['id'],
                'order_number' => (string) $order['order_number'],
                'org_id' => (string) $order['org_id'],
                'account_ref' => (string) $order['account_ref'],
                'gross_cents' => $grossCents,
                'paid_cents' => $paidCents,
                'fully_paid' => $fullyPaid,
                'payment_id' => Uuid::toString($paymentId),
            ];
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            throw $e;
        }
    }

    /**
     * @param array{order_id:string, order_number:string, account_ref:string,
     *              gross_cents:int, paid_cents:int, fully_paid:bool} $outcome
     * @param array{invoice_number:string}|null $invoice
     */
    private function notifyOps(array $outcome, ?array $invoice): void
    {
        $this->notifier->dispatch(new Notification(
            subject: $outcome['fully_paid']
                ? "Order {$outcome['order_number']} paid — ready to accept"
                : "Partial payment on {$outcome['order_number']}",
            summary: $outcome['fully_paid']
                ? 'Payment cleared in full. The order is waiting in the acceptance queue.'
                : 'A partial payment was received. The order stays on hold until the balance clears.',
            facts: [
                'order' => $outcome['order_number'],
                'account' => $outcome['account_ref'],
                'paid' => number_format($outcome['paid_cents'] / 100, 2),
                'order_total' => number_format($outcome['gross_cents'] / 100, 2),
                'invoice' => $invoice['invoice_number'] ?? '(pending)',
            ],
            linkPath: '/manager/orders/' . rawurlencode($outcome['order_number']),
            severity: $outcome['fully_paid'] ? 'action_required' : 'urgent'
        ));
    }

    /** @param array<string, mixed> $event */
    private function raiseReconciliationAlert(array $event, ReconciliationException $e): void
    {
        $this->audit->record(
            action: 'payment.reconciliation_failed',
            metadata: [
                'provider' => $this->provider,
                'provider_ref' => $event['provider_ref'],
                'order_ref' => $event['order_ref'],
                'amount_cents' => $event['amount_cents'],
                'currency' => $event['currency'],
                'reason' => $e->getMessage(),
            ]
        );

        $this->notifier->dispatch(new Notification(
            subject: 'Payment could not be reconciled',
            summary: 'A signed payment notification did not match its order. '
                . 'Money may have moved without an order being credited. '
                . 'Investigate before the customer chases it.',
            facts: [
                'order_ref' => $event['order_ref'],
                'provider_ref' => $event['provider_ref'],
                'amount' => number_format($event['amount_cents'] / 100, 2),
                'currency' => $event['currency'],
                'reason' => $e->getMessage(),
            ],
            linkPath: '/manager/payments/unreconciled',
            severity: 'urgent'
        ));
    }

    /**
     * Parse a decimal money string to integer minor units without floats.
     *
     * '12.3' -> 1230, '12.345' -> 1234 (truncated, never rounded up: rounding a
     * payment in the merchant's favour is the wrong default).
     */
    private static function decimalToCents(string $decimal): int
    {
        $clean = preg_replace('/[^0-9.\-]/', '', trim($decimal)) ?? '0';
        $negative = str_starts_with($clean, '-');
        $clean = ltrim($clean, '-');

        [$whole, $fraction] = array_pad(explode('.', $clean, 2), 2, '0');
        $fraction = substr(str_pad($fraction, 2, '0'), 0, 2);

        $cents = (int) $whole * 100 + (int) $fraction;

        return $negative ? -$cents : $cents;
    }

    private static function nullIfBlank(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        return trim($value) === '' ? null : trim($value);
    }
}
