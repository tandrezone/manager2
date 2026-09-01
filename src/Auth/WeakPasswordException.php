<?php

declare(strict_types=1);

namespace Manager2\Auth;

/** Raised when a proposed password fails policy. Safe to show to the user. */
final class WeakPasswordException extends \RuntimeException
{
}
