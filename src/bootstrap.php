<?php

declare(strict_types=1);

/**
 * Composition root.
 *
 * Everything is wired in one place so the dependency graph is readable and the
 * security-relevant objects (key ring, verifier secrets) are constructed exactly
 * once, from the environment, with no service-locator indirection hiding where a
 * secret came from.
 */

require __DIR__ . '/autoload.php';

use Manager2\Audit\AuditLog;
use Manager2\Auth\InviteService;
use Manager2\Auth\Registration;
use Manager2\Auth\Vies;
use Manager2\Billing\InvoiceService;
use Manager2\Credit\CreditDecisionService;
use Manager2\Crypto\BlindIndex;
use Manager2\Crypto\FieldCipher;
use Manager2\Crypto\KeyRing;
use Manager2\Gdpr\DsarService;
use Manager2\Gdpr\RetentionPurger;
use Manager2\Notify\EmailTransport;
use Manager2\Notify\OpsNotifier;
use Manager2\Notify\WebhookTransport;
use Manager2\Payments\PaymentWebhookController;
use Manager2\Payments\WebhookVerifier;
use Manager2\Support\Db;

/**
 * Read a required secret, failing loudly at boot.
 *
 * Fail-fast beats a default: a webhook verifier silently constructed with an
 * empty secret accepts forged callbacks, and nothing in the happy path would
 * ever reveal it.
 */
function m2_env(string $name, ?string $default = null): string
{
    $value = getenv($name);

    if ($value === false || $value === '') {
        if ($default !== null) {
            return $default;
        }

        throw new RuntimeException(
            "Required environment variable {$name} is not set. See .env.example."
        );
    }

    return $value;
}

function m2_env_bytes(string $name, int $minBytes = 32): string
{
    $decoded = base64_decode(m2_env($name), true);

    if ($decoded === false || strlen($decoded) < $minBytes) {
        throw new RuntimeException(
            "{$name} must be base64 for at least {$minBytes} bytes. "
            . "Generate one with: openssl rand -base64 {$minBytes}"
        );
    }

    return $decoded;
}

/**
 * @return array{
 *     pdo: PDO, keyring: KeyRing, cipher: FieldCipher, blind_index: BlindIndex,
 *     audit: AuditLog, notifier: OpsNotifier, invites: InviteService,
 *     registration: Registration, invoices: InvoiceService, dsar: DsarService,
 *     retention: RetentionPurger, credit: CreditDecisionService,
 *     payment_webhook: PaymentWebhookController, ip_hash_key: string
 * }
 */
function m2_container(): array
{
    static $container = null;

    if ($container !== null) {
        return $container;
    }

    $pdo = Db::connect();
    $keyRing = KeyRing::fromEnvironment();
    $cipher = new FieldCipher($keyRing);
    $blindIndex = new BlindIndex($keyRing);
    $audit = new AuditLog($pdo);

    $baseUrl = m2_env('M2_BASE_URL', 'https://portal.example');

    $transports = [
        new EmailTransport(
            recipients: array_values(array_filter(array_map(
                'trim',
                explode(',', m2_env('M2_OPS_EMAILS', 'ops@example.invalid'))
            ))),
            fromAddress: m2_env('M2_MAIL_FROM', 'no-reply@example.invalid'),
            baseUrl: $baseUrl
        ),
    ];

    // Optional chat alert. Absent config simply means one fewer transport —
    // never a boot failure, because chat is a convenience and email is the record.
    $chatEndpoint = getenv('M2_CHAT_WEBHOOK_URL');
    if (is_string($chatEndpoint) && $chatEndpoint !== '') {
        $transports[] = new WebhookTransport(
            endpoint: $chatEndpoint,
            signingSecret: m2_env_bytes('M2_CHAT_WEBHOOK_SECRET'),
            baseUrl: $baseUrl,
            channelName: 'chat'
        );
    }

    $notifier = new OpsNotifier($transports, $audit);
    $invites = new InviteService($pdo, $blindIndex, $audit, m2_env_bytes('M2_INVITE_PEPPER'));
    $invoices = new InvoiceService($pdo, $audit);

    $container = [
        'pdo' => $pdo,
        'keyring' => $keyRing,
        'cipher' => $cipher,
        'blind_index' => $blindIndex,
        'audit' => $audit,
        'notifier' => $notifier,
        'invites' => $invites,
        'invoices' => $invoices,
        'registration' => new Registration(
            $pdo,
            $cipher,
            $blindIndex,
            $invites,
            $audit,
            new Vies()
        ),
        'dsar' => new DsarService($pdo, $cipher, $blindIndex, $audit),
        'retention' => new RetentionPurger($pdo, $cipher, $audit),
        'credit' => new CreditDecisionService($pdo, $cipher, $audit, $notifier),
        'payment_webhook' => new PaymentWebhookController(
            $pdo,
            new WebhookVerifier(m2_env('M2_PSP_WEBHOOK_SECRET')),
            $cipher,
            $invoices,
            $notifier,
            $audit,
            m2_env('M2_PSP_PROVIDER', 'mbway')
        ),
        'ip_hash_key' => m2_env_bytes('M2_IP_HASH_KEY'),
    ];

    return $container;
}
