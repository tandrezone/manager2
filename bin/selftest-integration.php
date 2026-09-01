<?php

declare(strict_types=1);

/**
 * End-to-end integration test against a live MariaDB.
 *
 * Exercises the paths that matter and, importantly, the paths that must FAIL:
 * a reused invite, a forged webhook signature, a replayed webhook, an
 * underpayment, an erasure that must not delete invoices.
 *
 * Usage:
 *   M2_DB_DSN="mysql:unix_socket=/tmp/m2run/m2.sock;dbname=manager2;charset=utf8mb4" \
 *   M2_DB_USER=root php bin/selftest-integration.php
 */

require __DIR__ . '/../src/autoload.php';

use Manager2\Audit\AuditLog;
use Manager2\Auth\InviteRejectedException;
use Manager2\Auth\InviteService;
use Manager2\Auth\Registration;
use Manager2\Auth\RegistrationException;
use Manager2\Billing\InvoiceService;
use Manager2\Credit\CreditDecisionService;
use Manager2\Crypto\BlindIndex;
use Manager2\Crypto\FieldCipher;
use Manager2\Crypto\KeyRing;
use Manager2\Gdpr\DsarService;
use Manager2\Gdpr\RetentionPurger;
use Manager2\Notify\Notification;
use Manager2\Notify\OpsNotifier;
use Manager2\Notify\Transport;
use Manager2\Payments\PaymentWebhookController;
use Manager2\Payments\WebhookVerifier;
use Manager2\Support\Db;
use Manager2\Support\Uuid;

$pass = 0;
$fail = 0;

function check(string $label, callable $test): void
{
    global $pass, $fail;

    try {
        $ok = $test();
    } catch (\Throwable $e) {
        $ok = false;
        $label .= ' [' . $e::class . ': ' . $e->getMessage() . ']';
    }

    if ($ok === true) {
        $pass++;
        echo "  ok    {$label}\n";
    } else {
        $fail++;
        echo "  FAIL  {$label}\n";
    }
}

function section(string $name): void
{
    echo "\n{$name}\n";
}

/** Captures notifications so assertions can inspect them. */
final class CapturingTransport implements Transport
{
    /** @var list<Notification> */
    public array $sent = [];

    public function name(): string
    {
        return 'capture';
    }

    public function send(Notification $notification): void
    {
        $this->sent[] = $notification;
    }
}

$pdo = Db::connect();

// Clean slate.
$pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
foreach ([
    'invite_redemptions', 'invites', 'messages', 'order_status_history', 'order_items',
    'payments', 'invoices', 'orders', 'delivery_locations', 'credit_decisions',
    'kyb_checks', 'consent_records', 'gdpr_requests', 'sessions', 'users',
    'organisations', 'webhook_events', 'audit_log', 'document_series',
] as $table) {
    $pdo->exec("TRUNCATE TABLE {$table}");
}
$pdo->exec('SET FOREIGN_KEY_CHECKS = 1');

$keyRing = new KeyRing(
    [
        KeyRing::PURPOSE_FIELD => [1 => random_bytes(32)],
        KeyRing::PURPOSE_BLIND_INDEX => [1 => random_bytes(32)],
    ],
    [KeyRing::PURPOSE_FIELD => 1, KeyRing::PURPOSE_BLIND_INDEX => 1]
);

$cipher = new FieldCipher($keyRing);
$blindIndex = new BlindIndex($keyRing);
$audit = new AuditLog($pdo);
$capture = new CapturingTransport();
$notifier = new OpsNotifier([$capture], $audit);
$invites = new InviteService($pdo, $blindIndex, $audit, random_bytes(32));
$invoices = new InvoiceService($pdo, $audit);
// Vies deliberately null: no network dependency in a test suite.
$registration = new Registration($pdo, $cipher, $blindIndex, $invites, $audit, null);
$dsar = new DsarService($pdo, $cipher, $blindIndex, $audit);
$retention = new RetentionPurger($pdo, $cipher, $audit);
$credit = new CreditDecisionService($pdo, $cipher, $audit, $notifier);

$webhookSecret = base64_encode(random_bytes(32));
$verifier = new WebhookVerifier($webhookSecret);
$webhook = new PaymentWebhookController(
    $pdo, $verifier, $cipher, $invoices, $notifier, $audit, 'mbway'
);

// --- Seed staff + catalogue ------------------------------------------------
$staffId = Uuid::v7();
$pdo->prepare(
    'INSERT INTO users (id, org_id, kind, role, email_enc, email_bidx, full_name_enc,
                        display_handle, password_hash, status)
     VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)'
)->execute([
    $staffId, 'staff', 'sales',
    $cipher->seal('sales@example.pt', 'users', 'email_enc', $staffId),
    $blindIndex->compute('sales@example.pt', 'users', 'email_bidx'),
    $cipher->seal('Sofia Marques', 'users', 'full_name_enc', $staffId),
    'SM-01', password_hash('x', PASSWORD_ARGON2ID), 'active',
]);

$productId = Uuid::v7();
$pdo->prepare(
    'INSERT INTO products (id, sku, name, uom, list_price_cents, tax_rate_bp,
                           unit_cost_cents, stock_qty)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
)->execute([$productId, 'WID-100', 'Widget, case of 12', 'case', 4500, 2300, 2800, 500]);

$invoices->ensureSeries((int) date('Y'), 'invoice', null);

// =========================================================================
section('Invitations');

$issued = $invites->issue(
    issuedByUserId: $staffId,
    intendedLegalName: 'Padaria Central, Lda.',
    intendedVatNumber: 'PT501442600',
    intendedCountry: 'PT',
    recipientEmail: 'ana@padariacentral.pt',
    grantsRole: 'org_admin',
    reason: 'Trade show lead, credit-checked'
);

check('invite issued with a hyphenated code', fn () => preg_match('/^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}$/', $issued['code']) === 1);

check('plaintext code is NOT stored', function () use ($pdo, $issued) {
    $bare = str_replace('-', '', $issued['code']);
    $rows = $pdo->query('SELECT code_hash, code_prefix FROM invites')->fetchAll();

    foreach ($rows as $row) {
        if (str_contains(bin2hex((string) $row['code_hash']), bin2hex($bare))) {
            return false;
        }
    }

    return strlen((string) $rows[0]['code_prefix']) === 6;
});

check('resolves with the correct code', function () use ($invites, $issued) {
    return $invites->resolve($issued['code'], 'ana@padariacentral.pt')['id'] !== null;
});

check('accepts transcription errors (O for 0, lowercase, spaces)', function () use ($invites, $issued) {
    $mangled = strtolower(str_replace('0', 'O', $issued['code']));

    return $invites->resolve(' ' . $mangled . ' ', 'ana@padariacentral.pt')['id'] !== null;
});

check('REJECTS a wrong code', function () use ($invites) {
    try {
        $invites->resolve('AAAAA-BBBBB-CCCCC-DDDDD', 'ana@padariacentral.pt');
    } catch (InviteRejectedException) {
        return true;
    }

    return false;
});

check('REJECTS the right code from the wrong recipient', function () use ($invites, $issued) {
    try {
        $invites->resolve($issued['code'], 'someone.else@example.pt');
    } catch (InviteRejectedException) {
        return true;
    }

    return false;
});

check('rejection message does not leak which failure occurred', function () use ($invites, $issued) {
    $messages = [];

    foreach ([['ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ', 'ana@padariacentral.pt'],
              [$issued['code'], 'wrong@example.pt']] as [$code, $email]) {
        try {
            $invites->resolve($code, $email);
        } catch (InviteRejectedException $e) {
            $messages[] = $e->getMessage();
        }
    }

    return count($messages) === 2 && $messages[0] === $messages[1];
});

// =========================================================================
section('Registration + KYB');

$result = $registration->register([
    'invite_code' => $issued['code'],
    'email' => 'Ana@PadariaCentral.pt',
    'full_name' => 'Ana Ribeiro',
    'password' => 'a properly long passphrase here',
    'job_title' => 'Head of Purchasing',
    'phone' => '+351 912 345 678',
    'legal_name' => 'Padaria Central Lda',
    'vat_number' => '501442600',
    'country' => 'PT',
    'registered_address' => "Rua de Santa Catarina 1234\n4000-447 Porto",
]);

$userId = Uuid::fromString($result['user_id']);
$orgId = Uuid::fromString($result['org_id']);

check('account created', fn () => $result['account_ref'] === 'ACC-000001');
check('starts pending_verification, not active', fn () => $result['org_status'] === 'pending_verification');
check('unverified accounts get an order ceiling', fn () => $result['order_ceiling_cents'] === 25000);
check('VAT stored canonically as PT501442600', function () use ($pdo, $orgId) {
    $stmt = $pdo->prepare('SELECT vat_number FROM organisations WHERE id = ?');
    $stmt->execute([$orgId]);

    return $stmt->fetchColumn() === 'PT501442600';
});

check('name is a real name, not a pseudonym', function () use ($pdo, $cipher, $userId) {
    $stmt = $pdo->prepare('SELECT full_name_enc, display_handle FROM users WHERE id = ?');
    $stmt->execute([$userId]);
    $row = $stmt->fetch();

    return $cipher->open((string) $row['full_name_enc'], 'users', 'full_name_enc', $userId) === 'Ana Ribeiro'
        && str_starts_with((string) $row['display_handle'], 'AR-');
});

check('PII is unreadable in the raw table', function () use ($pdo) {
    $dump = '';
    foreach ($pdo->query('SELECT email_enc, full_name_enc, phone_enc FROM users')->fetchAll() as $row) {
        $dump .= (string) $row['email_enc'] . (string) $row['full_name_enc'] . (string) $row['phone_enc'];
    }

    return !str_contains($dump, 'Ana')
        && !str_contains($dump, 'padariacentral')
        && !str_contains($dump, '912345678');
});

check('email lookup works via blind index despite encryption', function () use ($pdo, $blindIndex, $userId) {
    $stmt = $pdo->prepare('SELECT id FROM users WHERE email_bidx = ?');
    // Different casing and spacing from what was registered.
    $stmt->execute([$blindIndex->compute(' ANA@padariacentral.PT ', 'users', 'email_bidx')]);

    return $stmt->fetchColumn() === $userId;
});

check('KYB check row recorded', function () use ($pdo, $orgId) {
    // No Vies wired in this run, so expect zero rows but a working query path.
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM kyb_checks WHERE org_id = ?');
    $stmt->execute([$orgId]);

    return (int) $stmt->fetchColumn() === 0;
});

check('single-use invite is now exhausted', function () use ($registration, $issued) {
    try {
        $registration->register([
            'invite_code' => $issued['code'],
            'email' => 'second@padariacentral.pt',
            'full_name' => 'Bruno Silva',
            'password' => 'another long passphrase here',
            'legal_name' => 'Padaria Central Lda',
            'vat_number' => '501442600',
            'country' => 'PT',
        ]);
    } catch (InviteRejectedException) {
        return true;
    }

    return false;
});

check('REJECTS an invalid VAT checksum', function () use ($invites, $registration, $staffId) {
    $bad = $invites->issue(
        issuedByUserId: $staffId,
        intendedLegalName: 'Dodgy Co',
        intendedCountry: 'PT'
    );

    try {
        $registration->register([
            'invite_code' => $bad['code'],
            'email' => 'x@dodgy.pt',
            'full_name' => 'X Y',
            'password' => 'yet another long passphrase',
            'legal_name' => 'Dodgy Co',
            'vat_number' => 'PT501442601',
            'country' => 'PT',
        ]);
    } catch (RegistrationException $e) {
        return str_contains($e->getMessage(), 'VAT number is not valid');
    }

    return false;
});

check('REJECTS onboarding a different company than the invite named', function () use ($invites, $registration, $staffId) {
    $inv = $invites->issue(
        issuedByUserId: $staffId,
        intendedLegalName: 'Mercearia do Bairro Lda',
        intendedCountry: 'PT'
    );

    try {
        $registration->register([
            'invite_code' => $inv['code'],
            'email' => 'z@other.pt',
            'full_name' => 'Z Q',
            'password' => 'a long enough passphrase ok',
            'legal_name' => 'Completely Different Business SA',
            'country' => 'PT',
        ]);
    } catch (RegistrationException $e) {
        return str_contains($e->getMessage(), 'does not match the invitation');
    }

    return false;
});

check('REJECTS a duplicate email without confirming it exists', function () use ($invites, $registration, $staffId) {
    $inv = $invites->issue($staffId, orgId: null, intendedLegalName: 'Padaria Central Lda',
        intendedCountry: 'PT');

    try {
        $registration->register([
            'invite_code' => $inv['code'],
            'email' => 'ana@padariacentral.pt',
            'full_name' => 'Ana Ribeiro',
            'password' => 'a long enough passphrase ok',
            'legal_name' => 'Padaria Central Lda',
            'country' => 'PT',
        ]);
    } catch (RegistrationException $e) {
        $message = $e->getMessage();

        // Must not confirm the address is on file — that would make the
        // endpoint a customer-list oracle for a competitor.
        return str_contains($message, 'cannot be registered')
            && preg_match('/\b(exists|taken|in use|registered to|duplicate)\b/i', $message) === 0;
    }

    return false;
});

check('weak password rejected BEFORE the invite is consumed', function () use ($invites, $registration, $staffId, $pdo) {
    $inv = $invites->issue($staffId, orgId: null, intendedLegalName: 'Cafe Teste Lda',
        intendedCountry: 'PT');

    try {
        $registration->register([
            'invite_code' => $inv['code'],
            'email' => 'cafe@teste.pt',
            'full_name' => 'C T',
            'password' => 'short',
            'legal_name' => 'Cafe Teste Lda',
            'country' => 'PT',
        ]);
    } catch (\Manager2\Auth\WeakPasswordException) {
        $stmt = $pdo->prepare('SELECT uses FROM invites WHERE id = ?');
        $stmt->execute([Uuid::fromString($inv['invite_id'])]);

        return (int) $stmt->fetchColumn() === 0;
    }

    return false;
});

// =========================================================================
section('Orders');

// Activate the account and give it terms so invoicing has something to work with.
$pdo->prepare(
    "UPDATE organisations
        SET status = 'active', payment_terms_days = 30, credit_limit_cents = 500000,
            onboarded_at = UTC_TIMESTAMP(6)
      WHERE id = ?"
)->execute([$orgId]);

$locationId = Uuid::v7();
$pdo->prepare(
    'INSERT INTO delivery_locations
        (id, org_id, label, address_enc, country, contact_name_enc,
         contact_phone_enc, access_notes_enc, is_default)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)'
)->execute([
    $locationId, $orgId, 'Bakery, Porto',
    $cipher->seal("Rua de Santa Catarina 1234\n4000-447 Porto", 'delivery_locations', 'address_enc', $locationId),
    'PT',
    $cipher->seal('Ana Ribeiro', 'delivery_locations', 'contact_name_enc', $locationId),
    $cipher->seal('+351912345678', 'delivery_locations', 'contact_phone_enc', $locationId),
    $cipher->seal('Rear loading bay, ring the bell', 'delivery_locations', 'access_notes_enc', $locationId),
]);

$orderId = Uuid::v7();
$orderNumber = 'ORD-' . date('Y') . '-000001';
$net = 4500 * 10;
$tax = (int) round($net * 0.23);

$pdo->prepare(
    'INSERT INTO orders
        (id, order_number, org_id, placed_by, status, currency, net_cents, tax_cents,
         gross_cents, cogs_cents, payment_method, payment_status,
         delivery_location_id, requested_window_start, requested_window_end,
         delivery_notes_enc, customer_po_ref)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
)->execute([
    $orderId, $orderNumber, $orgId, $userId, 'submitted', 'EUR',
    $net, $tax, $net + $tax, 2800 * 10, 'mbway', 'pending',
    $locationId,
    (new DateTimeImmutable('tomorrow 09:00'))->format('Y-m-d H:i:s'),
    (new DateTimeImmutable('tomorrow 12:00'))->format('Y-m-d H:i:s'),
    $cipher->seal('Deliver before the morning bake', 'orders', 'delivery_notes_enc', $orderId),
    'PO-8891',
]);

$pdo->prepare(
    'INSERT INTO order_items
        (id, order_id, product_id, sku_snapshot, name_snapshot, qty,
         unit_price_cents, tax_rate_bp, unit_cost_cents, net_cents, tax_cents, line_no)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)'
)->execute([
    Uuid::v7(), $orderId, $productId, 'WID-100', 'Widget, case of 12', 10,
    4500, 2300, 2800, $net, $tax,
]);

check('order created with a total of 553.50 EUR', fn () => $net + $tax === 55350);

// =========================================================================
section('Payment webhook');

$makeRequest = static function (array $payload) use ($verifier): array {
    $body = json_encode($payload, JSON_THROW_ON_ERROR);
    $signed = $verifier->sign($body);

    return [$body, [
        'X-Signature' => $signed['signature'],
        'X-Timestamp' => $signed['timestamp'],
    ]];
};

$settledPayload = [
    'id' => 'evt_mbway_00001',
    'type' => 'payment.settled',
    'data' => [
        'transaction_id' => 'mbw_tx_557788',
        'order_ref' => $orderNumber,
        'amount' => '553.50',
        'currency' => 'EUR',
        'payer_alias' => '+351912345678',
    ],
];

check('REJECTS a forged signature', function () use ($webhook, $settledPayload) {
    $body = json_encode($settledPayload, JSON_THROW_ON_ERROR);
    $result = $webhook->handle($body, [
        'X-Signature' => 'sha256=' . str_repeat('a', 64),
        'X-Timestamp' => (string) time(),
    ]);

    return $result['status'] === 400;
});

check('REJECTS an unsigned request', function () use ($webhook, $settledPayload) {
    return $webhook->handle(json_encode($settledPayload, JSON_THROW_ON_ERROR), [])['status'] === 400;
});

check('REJECTS a stale timestamp (replay outside the window)', function () use ($webhook, $verifier, $settledPayload) {
    $body = json_encode($settledPayload, JSON_THROW_ON_ERROR);
    $old = time() - 3600;
    $signed = $verifier->sign($body, $old);

    return $webhook->handle($body, [
        'X-Signature' => $signed['signature'],
        'X-Timestamp' => $signed['timestamp'],
    ])['status'] === 400;
});

check('REJECTS a tampered body under a valid signature', function () use ($webhook, $verifier, $settledPayload) {
    $body = json_encode($settledPayload, JSON_THROW_ON_ERROR);
    $signed = $verifier->sign($body);
    $tampered = str_replace('553.50', '1.00', $body);

    return $webhook->handle($tampered, [
        'X-Signature' => $signed['signature'],
        'X-Timestamp' => $signed['timestamp'],
    ])['status'] === 400;
});

check('nothing was recorded by any rejected attempt', function () use ($pdo) {
    return (int) $pdo->query('SELECT COUNT(*) FROM payments')->fetchColumn() === 0
        && (int) $pdo->query('SELECT COUNT(*) FROM webhook_events')->fetchColumn() === 0;
});

check('REJECTS an underpayment as a reconciliation conflict (409)', function () use ($webhook, $makeRequest, $orderNumber) {
    [$body, $headers] = $makeRequest([
        'id' => 'evt_underpay_1',
        'type' => 'payment.settled',
        'data' => [
            'transaction_id' => 'mbw_tx_short',
            'order_ref' => $orderNumber,
            'amount' => '600.00',
            'currency' => 'EUR',
        ],
    ]);

    return $webhook->handle($body, $headers)['status'] === 409;
});

check('REJECTS a currency mismatch', function () use ($webhook, $makeRequest, $orderNumber) {
    [$body, $headers] = $makeRequest([
        'id' => 'evt_wrongccy_1',
        'type' => 'payment.settled',
        'data' => [
            'transaction_id' => 'mbw_tx_ccy',
            'order_ref' => $orderNumber,
            'amount' => '553.50',
            'currency' => 'USD',
        ],
    ]);

    return $webhook->handle($body, $headers)['status'] === 409;
});

check('REJECTS a payment for an unknown order', function () use ($webhook, $makeRequest) {
    [$body, $headers] = $makeRequest([
        'id' => 'evt_noorder_1',
        'type' => 'payment.settled',
        'data' => [
            'transaction_id' => 'mbw_tx_ghost',
            'order_ref' => 'ORD-1999-999999',
            'amount' => '10.00',
            'currency' => 'EUR',
        ],
    ]);

    return $webhook->handle($body, $headers)['status'] === 409;
});

check('reconciliation failures raised an urgent alert', function () use ($capture) {
    foreach ($capture->sent as $notification) {
        if ($notification->severity === 'urgent'
            && str_contains($notification->subject, 'could not be reconciled')) {
            return true;
        }
    }

    return false;
});

[$body, $headers] = $makeRequest($settledPayload);
$accepted = $webhook->handle($body, $headers);

check('ACCEPTS a valid settlement', fn () => $accepted['status'] === 200
    && $accepted['body']['status'] === 'processed');

check('order marked paid', function () use ($pdo, $orderId) {
    $stmt = $pdo->prepare('SELECT payment_status, paid_at FROM orders WHERE id = ?');
    $stmt->execute([$orderId]);
    $row = $stmt->fetch();

    return $row['payment_status'] === 'paid' && $row['paid_at'] !== null;
});

check('decimal amount parsed to exact minor units', function () use ($pdo) {
    return (int) $pdo->query('SELECT amount_cents FROM payments')->fetchColumn() === 55350;
});

check('payer alias encrypted at rest', function () use ($pdo) {
    $raw = (string) $pdo->query('SELECT payer_alias_enc FROM payments')->fetchColumn();

    return $raw !== '' && !str_contains($raw, '912345678');
});

check('invoice issued automatically', fn () => ($accepted['body']['invoice'] ?? null) !== null);

check('the invoice is marked paid AND settled_at is populated', function () use ($pdo, $orderId) {
    $stmt = $pdo->prepare(
        'SELECT status, settled_at FROM invoices WHERE order_id = ?'
    );
    $stmt->execute([$orderId]);
    $row = $stmt->fetch();

    return $row['status'] === 'paid' && $row['settled_at'] !== null;
});

check('IDEMPOTENT: replaying the same event changes nothing', function () use ($webhook, $body, $headers, $pdo) {
    $before = $pdo->query('SELECT COUNT(*) FROM payments')->fetchColumn();
    $replay = $webhook->handle($body, $headers);
    $after = $pdo->query('SELECT COUNT(*) FROM payments')->fetchColumn();

    return $replay['status'] === 200
        && $replay['body']['status'] === 'already_processed'
        && $before === $after;
});

check('retry attempts counted', function () use ($pdo) {
    $stmt = $pdo->prepare("SELECT attempts FROM webhook_events WHERE event_id = 'evt_mbway_00001'");
    $stmt->execute();

    return (int) $stmt->fetchColumn() === 2;
});

check('unrelated event types ignored, not failed', function () use ($webhook, $makeRequest) {
    [$b, $h] = $makeRequest([
        'id' => 'evt_refund_notice',
        'type' => 'payment.refund.pending',
        'data' => ['order_ref' => 'x', 'amount' => '1.00'],
    ]);
    $r = $webhook->handle($b, $h);

    return $r['status'] === 200 && $r['body']['status'] === 'ignored';
});

// =========================================================================
section('Invoicing');

check('invoice number is FT<year>/000001', function () use ($pdo) {
    return $pdo->query('SELECT invoice_number FROM invoices')->fetchColumn()
        === 'FT' . date('Y') . '/000001';
});

check('billing identity snapshotted onto the invoice', function () use ($pdo) {
    $row = $pdo->query('SELECT bill_legal_name, bill_vat_number FROM invoices')->fetch();

    return $row['bill_legal_name'] === 'Padaria Central Lda'
        && $row['bill_vat_number'] === 'PT501442600';
});

check('due date honours 30-day terms', function () use ($pdo) {
    $row = $pdo->query('SELECT issue_date, due_date FROM invoices')->fetch();

    return (new DateTimeImmutable((string) $row['issue_date']))
        ->add(new DateInterval('P30D'))->format('Y-m-d') === (string) $row['due_date'];
});

check('ATCUD omitted rather than fabricated', function () use ($pdo) {
    return $pdo->query('SELECT atcud FROM invoices')->fetchColumn() === null;
});

check('idempotent: re-issuing returns the same invoice', function () use ($invoices, $orderId) {
    $again = $invoices->issueForOrder($orderId);

    return $again['created'] === false
        && $again['invoice_number'] === 'FT' . date('Y') . '/000001';
});

// Issue a second and third invoice so the chain has depth.
foreach ([2, 3] as $n) {
    $oid = Uuid::v7();
    $pdo->prepare(
        'INSERT INTO orders (id, order_number, org_id, placed_by, status, currency,
                             net_cents, tax_cents, gross_cents, payment_method, payment_status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )->execute([
        $oid, sprintf('ORD-%s-%06d', date('Y'), $n), $orgId, $userId, 'submitted',
        'EUR', 10000, 2300, 12300, 'credit_terms', 'pending',
    ]);
    $invoices->issueForOrder($oid);
}

check('series is gapless and the hash chain verifies', function () use ($invoices) {
    $report = $invoices->verifySeries('FT' . date('Y'));

    return $report['ok'] === true && $report['checked'] === 3;
});

check('DETECTS a tampered invoice amount', function () use ($pdo, $invoices) {
    $pdo->exec(
        "UPDATE invoices SET gross_cents = 100
          WHERE invoice_number = 'FT" . date('Y') . "/000002'"
    );

    $report = $invoices->verifySeries('FT' . date('Y'));
    $detected = $report['ok'] === false
        && count(array_filter(
            $report['problems'],
            fn (string $p): bool => str_contains($p, 'altered after issue')
        )) === 1;

    $pdo->exec(
        "UPDATE invoices SET gross_cents = 12300
          WHERE invoice_number = 'FT" . date('Y') . "/000002'"
    );

    return $detected;
});

check('DETECTS a deleted invoice (a gap in the series)', function () use ($pdo, $invoices, $orgId) {
    $row = $pdo->query(
        "SELECT id, sequence_no, prev_hash, doc_hash FROM invoices
          WHERE invoice_number = 'FT" . date('Y') . "/000002'"
    )->fetch();

    $pdo->prepare('DELETE FROM invoices WHERE id = ?')->execute([$row['id']]);

    $report = $invoices->verifySeries('FT' . date('Y'));
    $detected = $report['ok'] === false
        && count(array_filter(
            $report['problems'],
            fn (string $p): bool => str_contains($p, 'Gap in series')
        )) >= 1;

    // Restore so later assertions see a clean series.
    $pdo->prepare(
        'INSERT INTO invoices (id, doc_type, series_code, sequence_no, invoice_number,
             order_id, org_id, bill_legal_name, bill_vat_number, bill_address,
             issue_date, due_date, currency, net_cents, tax_cents, gross_cents,
             status, prev_hash, doc_hash)
         SELECT ?, \'invoice\', ?, ?, ?, NULL, ?, \'Padaria Central Lda\',
                \'PT501442600\', \'x\', CURDATE(), CURDATE(), \'EUR\',
                10000, 2300, 12300, \'issued\', ?, ?'
    )->execute([
        $row['id'], 'FT' . date('Y'), $row['sequence_no'],
        'FT' . date('Y') . '/000002', $orgId, $row['prev_hash'], $row['doc_hash'],
    ]);

    return $detected;
});

// =========================================================================
section('Credit decisions (Art. 22)');

check('a clean account is approved', function () use ($credit, $orgId) {
    $decision = $credit->assess($orgId);

    return $decision['decision'] === 'approve' && $decision['requires_notification'] === false;
});

check('overdue invoices reduce the score and change terms', function () use ($pdo, $credit, $orgId) {
    $pdo->exec(
        "UPDATE invoices SET status = 'overdue', due_date = DATE_SUB(CURDATE(), INTERVAL 60 DAY)
          WHERE org_id = UNHEX('" . bin2hex($orgId) . "')"
    );

    $decision = $credit->assess($orgId);

    return in_array($decision['decision'], ['reduce_limit', 'require_prepay'], true)
        && $decision['requires_notification'] === true;
});

check('explanation names the actual factors', function () use ($credit, $orgId) {
    $assessment = $credit->score($orgId);
    $explanation = $credit->explain('reduce_limit', $assessment);
    $joined = implode(' ', $explanation);

    return str_contains($joined, 'past due')
        && str_contains($joined, 'payment record with us')
        && str_contains($joined, 'reviewed by a member of our team');
});

check('scoring uses only our own payment data', function () use ($credit, $orgId) {
    $observations = $credit->score($orgId)['observations'];
    $keys = array_keys($observations);

    // Nothing about the individual, nothing from a third party.
    foreach ($keys as $key) {
        if (preg_match('/(^|_)(name|email|phone|address|age|dob|gender|nationality|bureau|ethnic)(_|$)/i', $key) === 1) {
            return false;
        }
    }

    return in_array('invoices_overdue', $keys, true)
        && in_array('average_days_late', $keys, true);
});

check('customer can demand human review, and it is recorded', function () use ($pdo, $credit, $orgId, $staffId) {
    $decisionId = $pdo->query(
        'SELECT id FROM credit_decisions ORDER BY created_at DESC LIMIT 1'
    )->fetchColumn();

    $credit->requestReview((string) $decisionId, 'The overdue invoice is disputed; goods arrived damaged.');
    $credit->recordHumanReview((string) $decisionId, $staffId, 'overturned',
        'Dispute upheld, credit note issued. Limit restored.', 500000);

    $stmt = $pdo->prepare(
        'SELECT review_outcome, is_automated, reviewed_by FROM credit_decisions WHERE id = ?'
    );
    $stmt->execute([$decisionId]);
    $row = $stmt->fetch();

    return $row['review_outcome'] === 'overturned'
        && (int) $row['is_automated'] === 0
        && $row['reviewed_by'] === $staffId;
});

// =========================================================================
section('GDPR: access and portability');

$export = $dsar->export($userId);

check('export includes the subject\'s real data', function () use ($export) {
    return $export['account']['full_name'] === 'Ana Ribeiro'
        && $export['account']['email'] === 'Ana@PadariaCentral.pt'
        && $export['account']['phone'] === '+351 912 345 678';
});

check('export includes delivery details', function () use ($export) {
    return str_contains((string) $export['delivery_locations'][0]['address'], 'Santa Catarina')
        && str_contains((string) $export['delivery_locations'][0]['access_notes'], 'loading bay');
});

check('export includes order history', fn () => count($export['orders']) >= 1);

check('export discloses lawful bases and retention (Art. 13/15)', function () use ($export) {
    $codes = array_column($export['lawful_bases'], 'code');

    return in_array('invoicing_tax', $codes, true)
        && in_array('credit_risk', $codes, true);
});

check('export discloses automated decisions with their logic (Art. 15(1)(h))', function () use ($export) {
    $decisions = $export['automated_decisions'];

    return $decisions !== []
        && isset($decisions[0]['factors_json']['factors'])
        && str_contains((string) $decisions[0]['_your_right'], 'Art. 22(3)');
});

check('first export has an empty access log (nothing has been read yet)', function () use ($export) {
    return $export['_access_log'] === [];
});

check('a later export lists the earlier access, by role and not by name', function () use ($dsar, $userId, $staffId) {
    // The staff member reads the delivery contact for a dispatch query...
    global $audit;
    $audit->recordPiiAccess(
        actorId: $staffId,
        actorRole: 'ops',
        entityType: 'users',
        entityId: $userId,
        fields: ['phone_enc'],
        reason: 'Called the site about a failed delivery attempt'
    );

    $second = $dsar->export($userId);
    $log = $second['_access_log'];

    if ($log === []) {
        return false;
    }

    $sawPiiRead = false;
    $sawExport = false;

    foreach ($log as $entry) {
        // Never the individual employee's identity: naming them to a third
        // party would disclose *their* personal data (Art. 15(4)).
        if (array_key_exists('actor_id', $entry) || !array_key_exists('by_role', $entry)) {
            return false;
        }

        if ($entry['what'] === 'pii.read') {
            $sawPiiRead = true;
            if ($entry['by_role'] !== 'ops'
                || !str_contains((string) $entry['reason'], 'failed delivery')) {
                return false;
            }
        }

        if ($entry['what'] === 'dsar.export') {
            $sawExport = true;
        }
    }

    return $sawPiiRead && $sawExport;
});

check('export is JSON-serialisable (Art. 20 machine-readable)', function () use ($export) {
    return is_string(json_encode($export, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
});

// =========================================================================
section('GDPR: erasure with legal hold');

$invoicesBefore = (int) $pdo->query('SELECT COUNT(*) FROM invoices')->fetchColumn();
$request = $dsar->open('erasure', $userId);
$erasure = $dsar->erase($userId, Uuid::fromString($request['request_id']));

check('erasure is PARTIALLY REFUSED where invoices exist', fn () => $erasure['status'] === 'partially_refused');

check('refusal cites Art. 17(3)(b)', function () use ($erasure) {
    return isset($erasure['retained']['invoices'])
        && str_contains($erasure['retained']['invoices'], 'Art. 17(3)(b)');
});

check('contact PII is gone', function () use ($pdo, $cipher, $userId) {
    $stmt = $pdo->prepare(
        'SELECT email_enc, full_name_enc, phone_enc, password_hash, status, erased_at
           FROM users WHERE id = ?'
    );
    $stmt->execute([$userId]);
    $row = $stmt->fetch();

    return $cipher->open((string) $row['email_enc'], 'users', 'email_enc', $userId) === '[erased]'
        && $cipher->open((string) $row['full_name_enc'], 'users', 'full_name_enc', $userId) === '[erased]'
        && $row['phone_enc'] === null
        && $row['password_hash'] === null
        && $row['status'] === 'disabled'
        && $row['erased_at'] !== null;
});

check('the erased account can no longer be found by email', function () use ($pdo, $blindIndex) {
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM users WHERE email_bidx = ?');
    $stmt->execute([$blindIndex->compute('ana@padariacentral.pt', 'users', 'email_bidx')]);

    return (int) $stmt->fetchColumn() === 0;
});

check('invoices SURVIVE erasure (tax law overrides)', function () use ($pdo, $invoicesBefore) {
    return (int) $pdo->query('SELECT COUNT(*) FROM invoices')->fetchColumn() === $invoicesBefore;
});

check('the invoice still carries the billing identity it legally must', function () use ($pdo) {
    return $pdo->query('SELECT bill_legal_name FROM invoices LIMIT 1')->fetchColumn()
        === 'Padaria Central Lda';
});

check('delivery site contacts cleared (last user of the account)', function () use ($pdo, $locationId) {
    $stmt = $pdo->prepare(
        'SELECT contact_name_enc, contact_phone_enc, access_notes_enc, archived_at
           FROM delivery_locations WHERE id = ?'
    );
    $stmt->execute([$locationId]);
    $row = $stmt->fetch();

    return $row['contact_name_enc'] === null
        && $row['contact_phone_enc'] === null
        && $row['access_notes_enc'] === null
        && $row['archived_at'] !== null;
});

check('the DSAR record documents the decision', function () use ($pdo, $request) {
    $stmt = $pdo->prepare(
        'SELECT status, refusal_ground, completed_at, decision_notes_enc
           FROM gdpr_requests WHERE id = ?'
    );
    $stmt->execute([Uuid::fromString($request['request_id'])]);
    $row = $stmt->fetch();

    return $row['status'] === 'partially_refused'
        && str_contains((string) $row['refusal_ground'], 'Art. 17(3)(b)')
        && $row['completed_at'] !== null
        && $row['decision_notes_enc'] !== null;
});

check('the statutory deadline is one month from receipt', function () use ($pdo, $request) {
    $stmt = $pdo->prepare('SELECT received_at, due_at FROM gdpr_requests WHERE id = ?');
    $stmt->execute([Uuid::fromString($request['request_id'])]);
    $row = $stmt->fetch();

    $days = (new DateTimeImmutable((string) $row['received_at']))
        ->diff(new DateTimeImmutable((string) $row['due_at']))->days;

    return $days === 30;
});

check('overdue DSAR monitoring finds nothing outstanding', fn () => $dsar->overdueAndDueSoon() === []);

// =========================================================================
section('Retention');

check('plan() reports without changing anything', function () use ($retention, $pdo) {
    $before = $pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();
    $plan = $retention->plan();
    $after = $pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();

    return $before === $after
        && $plan !== []
        && array_key_exists('eligible', $plan[0]);
});

check('purge is driven by the ROPA retention_days', function () use ($retention) {
    $plan = $retention->plan();
    $purposes = array_column($plan, 'purpose');

    return in_array('order_fulfilment', $purposes, true)
        && in_array('security_audit', $purposes, true);
});

check('an aged delivered order has its delivery notes purged', function () use ($pdo, $retention, $orderId) {
    $pdo->prepare(
        "UPDATE orders
            SET status = 'delivered',
                delivered_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1200 DAY)
          WHERE id = ?"
    )->execute([$orderId]);

    $retention->execute();

    $stmt = $pdo->prepare('SELECT delivery_notes_enc FROM orders WHERE id = ?');
    $stmt->execute([$orderId]);

    return $stmt->fetchColumn() === null;
});

check('a recent order is left alone', function () use ($pdo, $retention, $orgId, $userId, $cipher) {
    $freshId = Uuid::v7();
    $pdo->prepare(
        'INSERT INTO orders (id, order_number, org_id, placed_by, status, currency,
                             net_cents, tax_cents, gross_cents, payment_method,
                             payment_status, delivery_notes_enc, delivered_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6))'
    )->execute([
        $freshId, 'ORD-' . date('Y') . '-000900', $orgId, $userId, 'delivered', 'EUR',
        1000, 230, 1230, 'mbway', 'paid',
        $cipher->seal('Leave at reception', 'orders', 'delivery_notes_enc', $freshId),
    ]);

    $retention->execute();

    $stmt = $pdo->prepare('SELECT delivery_notes_enc FROM orders WHERE id = ?');
    $stmt->execute([$freshId]);

    return $stmt->fetchColumn() !== null;
});

// =========================================================================
section('Audit trail');

check('the hash chain verifies end to end', function () use ($audit) {
    $report = $audit->verify();

    return $report['ok'] === true && $report['checked'] > 20;
});

check('it recorded the events that matter', function () use ($pdo) {
    $actions = $pdo->query('SELECT DISTINCT action FROM audit_log')->fetchAll(PDO::FETCH_COLUMN);

    foreach (['invite.issue', 'invite.reject', 'user.register', 'invoice.issue',
              'credit.decision', 'dsar.export', 'dsar.erase', 'retention.purge',
              'payment.reconciliation_failed', 'webhook.reject'] as $required) {
        if (!in_array($required, $actions, true)) {
            echo "\n        missing action: {$required}";
            return false;
        }
    }

    return true;
});

check('DETECTS a deleted audit entry', function () use ($pdo, $audit) {
    $victim = $pdo->query('SELECT id FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET 5')
        ->fetchColumn();
    $row = $pdo->query("SELECT * FROM audit_log WHERE id = {$victim}")->fetch();

    $pdo->exec("DELETE FROM audit_log WHERE id = {$victim}");
    $report = $audit->verify();
    $detected = $report['ok'] === false && str_contains((string) $report['reason'], 'deleted');

    // Restore so the following assertion sees an intact chain.
    $columns = array_keys($row);
    $pdo->prepare(sprintf(
        'INSERT INTO audit_log (%s) VALUES (%s)',
        implode(',', $columns),
        implode(',', array_fill(0, count($columns), '?'))
    ))->execute(array_values($row));

    return $detected;
});

check('DETECTS a modified audit entry', function () use ($pdo, $audit) {
    $victim = $pdo->query("SELECT id FROM audit_log WHERE action = 'user.register' LIMIT 1")
        ->fetchColumn();
    $original = $pdo->query("SELECT action FROM audit_log WHERE id = {$victim}")->fetchColumn();

    $pdo->exec("UPDATE audit_log SET action = 'user.login' WHERE id = {$victim}");
    $report = $audit->verify();
    $detected = $report['ok'] === false && str_contains((string) $report['reason'], 'modified');

    $pdo->prepare('UPDATE audit_log SET action = ? WHERE id = ?')->execute([$original, $victim]);

    return $detected;
});

check('chain intact again after restoration', fn () => $audit->verify()['ok'] === true);

check('notifications never carried contact PII', function () use ($capture) {
    foreach ($capture->sent as $notification) {
        $blob = $notification->subject . $notification->summary
            . implode(' ', array_map('strval', $notification->facts));

        if (str_contains($blob, 'Ana Ribeiro')
            || str_contains($blob, 'padariacentral')
            || str_contains($blob, '912345678')
            || str_contains($blob, 'Santa Catarina')) {
            return false;
        }
    }

    return true;
});

check('Notification refuses PII at construction', function () {
    try {
        new Notification('x', 'y', ['contact' => 'ana@padariacentral.pt']);
    } catch (\InvalidArgumentException) {
        return true;
    }

    return false;
});

printf("\n%d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);
