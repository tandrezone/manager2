<?php

declare(strict_types=1);

namespace Manager2\Auth;

/**
 * Invitation could not be redeemed.
 *
 * The message is intentionally uniform across causes and safe to display.
 */
final class InviteRejectedException extends \RuntimeException
{
}
