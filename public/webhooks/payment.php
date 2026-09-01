<?php

declare(strict_types=1);

/**
 * Payment webhook endpoint.
 *
 * Deployment notes:
 *  - Terminate TLS in front of this. A signature over a plaintext channel still
 *    lets an observer read order references and amounts.
 *  - Rate-limit at the edge. Signature verification is cheap but not free, and
 *    an unauthenticated endpoint that does an HMAC per request is a small
 *    amplification target.
 *  - Restrict by source IP where the provider publishes a range. Defence in
 *    depth, never a replacement for the signature: IPs are spoofable upstream of
 *    your load balancer and providers change them without notice.
 *  - Keep this file thin. All logic lives in PaymentWebhookController, which is
 *    testable without a web server.
 */

require dirname(__DIR__, 2) . '/src/bootstrap.php';

// No output before the response, and no PHP notices leaking into the body: a
// warning printed above the JSON breaks the provider's parser and can disclose
// filesystem paths.
ini_set('display_errors', '0');
ini_set('log_errors', '1');

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

$respond = static function (int $status, array $body): never {
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
};

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    $respond(405, ['error' => 'method_not_allowed']);
}

// Read the raw body exactly once. php://input is not re-readable, and this must
// be the bytes the signature was computed over — no json_decode/encode round
// trip, no framework body parsing in between.
$rawBody = file_get_contents('php://input');

if ($rawBody === false) {
    $respond(400, ['error' => 'unreadable_body']);
}

/** @var array<string, string> $headers */
$headers = [];

if (function_exists('getallheaders')) {
    $headers = getallheaders() ?: [];
} else {
    foreach ($_SERVER as $key => $value) {
        if (str_starts_with((string) $key, 'HTTP_')) {
            $name = str_replace('_', '-', strtolower(substr((string) $key, 5)));
            $headers[$name] = (string) $value;
        }
    }
}

try {
    $container = m2_container();
    /** @var \Manager2\Payments\PaymentWebhookController $controller */
    $controller = $container['payment_webhook'];

    $result = $controller->handle($rawBody, $headers);

    $respond($result['status'], $result['body']);
} catch (\Throwable $e) {
    // Log everything, disclose nothing. A 500 makes the PSP retry, which is the
    // correct behaviour for a transient internal fault.
    error_log(sprintf(
        '[payment-webhook] %s: %s in %s:%d',
        $e::class,
        $e->getMessage(),
        $e->getFile(),
        $e->getLine()
    ));

    $respond(500, ['error' => 'internal_error']);
}
