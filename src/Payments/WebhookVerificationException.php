<?php

declare(strict_types=1);

namespace Manager2\Payments;

/**
 * Webhook signature, timestamp or body failed verification.
 *
 * The message is for the server log only. Responses to the caller carry a bare
 * 400: telling an attacker whether the signature or the timestamp failed halves
 * the work of forging one.
 */
final class WebhookVerificationException extends \RuntimeException
{
}
