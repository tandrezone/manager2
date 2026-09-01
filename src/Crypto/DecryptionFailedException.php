<?php

declare(strict_types=1);

namespace Manager2\Crypto;

/**
 * Raised when authenticated decryption fails.
 *
 * A GCM tag mismatch means one of: corrupted storage, the wrong key, or an
 * attacker moving ciphertext between rows or columns. The message never
 * distinguishes these cases and never echoes ciphertext — the distinction is
 * an oracle, and the caller has nothing useful to do with it either way.
 */
final class DecryptionFailedException extends \RuntimeException
{
}
