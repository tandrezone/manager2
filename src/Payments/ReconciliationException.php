<?php

declare(strict_types=1);

namespace Manager2\Payments;

/**
 * A correctly signed payment did not match its order.
 *
 * Distinct from WebhookVerificationException on purpose: that one means
 * "probably an attacker", this one means "probably a real payment that needs a
 * human". They get different HTTP codes, different alerts and different
 * urgencies, and collapsing them would bury genuine money problems in
 * scanner noise.
 */
final class ReconciliationException extends \RuntimeException
{
}
