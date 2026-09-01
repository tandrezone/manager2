<?php

declare(strict_types=1);

namespace Manager2\Crypto;

/** Raised when a ciphertext references a key version that is not loaded. */
final class KeyUnavailableException extends \RuntimeException
{
}
