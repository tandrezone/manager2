<?php

declare(strict_types=1);

namespace Manager2\Crypto;

/**
 * Field-level authenticated encryption for PII columns (GDPR Art. 32(1)(a)).
 *
 * Cipher: AES-256-GCM via OpenSSL.
 *
 * Sealed layout, stored raw in a VARBINARY column
 * ----------------------------------------------
 *   offset  size  field
 *   0       1     format magic (0x01)
 *   1       2     key version, big-endian uint16
 *   3       12    nonce (96-bit, the GCM-native size)
 *   15      16    authentication tag
 *   31      ...   ciphertext
 *
 * Overhead is a flat 31 bytes. Size a column as
 * `VARBINARY(31 + max_plaintext_bytes)`.
 *
 * Associated data
 * ---------------
 * Every seal binds `table|column|row-id` as AEAD associated data. This is the
 * part that is easy to omit and expensive to omit. Without it, an attacker with
 * UPDATE access — or a bug in a bulk job — can copy a ciphertext from one row
 * into another and it will decrypt cleanly, silently attributing one person's
 * address or phone number to another. With it, the tag check fails.
 *
 * Deterministic vs. randomised
 * ----------------------------
 * A fresh random nonce per seal means encrypting the same plaintext twice
 * yields different ciphertext. That is correct, and it is why equality search
 * needs the separate BlindIndex rather than a WHERE on the sealed column.
 *
 * What this does and does not defend against
 * ------------------------------------------
 * Defends: stolen disks, stolen backups, a read-only SQL injection, a leaked
 * replica, an over-broad support query, a hosting provider reading the volume.
 * Does not defend: an attacker who has the application key material, since the
 * running application must be able to decrypt to do its job. Field encryption
 * narrows the blast radius of a data-at-rest compromise; it does not make the
 * application itself trustless, and the privacy notice should not imply it does.
 */
final class FieldCipher
{
    private const MAGIC = 0x01;
    private const CIPHER = 'aes-256-gcm';
    private const NONCE_BYTES = 12;
    private const TAG_BYTES = 16;
    private const HEADER_BYTES = 15; // magic + key version + nonce
    public const OVERHEAD_BYTES = self::HEADER_BYTES + self::TAG_BYTES;

    public function __construct(private readonly KeyRing $keyRing)
    {
    }

    /**
     * Seal a plaintext value for a specific column of a specific row.
     *
     * @param string $table  physical table name, e.g. 'users'
     * @param string $column physical column name, e.g. 'email_enc'
     * @param string $rowId  the row's BINARY(16) id — generate it first
     */
    public function seal(string $plaintext, string $table, string $column, string $rowId): string
    {
        $version = $this->keyRing->activeVersion(KeyRing::PURPOSE_FIELD);
        $key = $this->keyRing->subkey(KeyRing::PURPOSE_FIELD, $version, $table, $column);
        $nonce = random_bytes(self::NONCE_BYTES);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $this->associatedData($table, $column, $rowId),
            self::TAG_BYTES
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('AES-256-GCM encryption failed.');
        }

        return pack('Cn', self::MAGIC, $version) . $nonce . $tag . $ciphertext;
    }

    /**
     * Open a sealed value. The associated data must match the seal exactly.
     *
     * @throws DecryptionFailedException on tag mismatch, truncation or misbinding
     * @throws KeyUnavailableException   if the referenced key version is not loaded
     */
    public function open(string $sealed, string $table, string $column, string $rowId): string
    {
        if (strlen($sealed) < self::OVERHEAD_BYTES) {
            throw new DecryptionFailedException('Sealed value is truncated.');
        }

        /** @var array{magic:int, version:int} $header */
        $header = unpack('Cmagic/nversion', substr($sealed, 0, 3));

        if ($header['magic'] !== self::MAGIC) {
            throw new DecryptionFailedException(
                sprintf('Unsupported seal format 0x%02X.', $header['magic'])
            );
        }

        $nonce = substr($sealed, 3, self::NONCE_BYTES);
        $tag = substr($sealed, self::HEADER_BYTES, self::TAG_BYTES);
        $ciphertext = substr($sealed, self::OVERHEAD_BYTES);

        $key = $this->keyRing->subkey(
            KeyRing::PURPOSE_FIELD,
            $header['version'],
            $table,
            $column
        );

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $this->associatedData($table, $column, $rowId)
        );

        if ($plaintext === false) {
            throw new DecryptionFailedException(
                'Authenticated decryption failed for ' . $table . '.' . $column . '.'
            );
        }

        return $plaintext;
    }

    /** Seal a value that may be absent, preserving SQL NULL. */
    public function sealNullable(
        ?string $plaintext,
        string $table,
        string $column,
        string $rowId
    ): ?string {
        return $plaintext === null || $plaintext === ''
            ? null
            : $this->seal($plaintext, $table, $column, $rowId);
    }

    public function openNullable(
        ?string $sealed,
        string $table,
        string $column,
        string $rowId
    ): ?string {
        return $sealed === null ? null : $this->open($sealed, $table, $column, $rowId);
    }

    /** Read the key version out of a sealed value without decrypting it. */
    public function keyVersionOf(string $sealed): int
    {
        if (strlen($sealed) < 3) {
            throw new DecryptionFailedException('Sealed value is truncated.');
        }

        /** @var array{version:int} $header */
        $header = unpack('Cmagic/nversion', substr($sealed, 0, 3));

        return $header['version'];
    }

    /** True if this value is sealed under an older key and should be rewritten. */
    public function needsRotation(string $sealed): bool
    {
        return $this->keyVersionOf($sealed)
            !== $this->keyRing->activeVersion(KeyRing::PURPOSE_FIELD);
    }

    /**
     * Re-seal under the current active key. Used by bin/reencrypt.php.
     *
     * Note this is decrypt-then-encrypt: the plaintext exists in process memory
     * for the duration, which is unavoidable for a key rotation and is why the
     * rotation job should run on the application host and not on a workstation.
     */
    public function rotate(string $sealed, string $table, string $column, string $rowId): string
    {
        return $this->seal(
            $this->open($sealed, $table, $column, $rowId),
            $table,
            $column,
            $rowId
        );
    }

    private function associatedData(string $table, string $column, string $rowId): string
    {
        if (strlen($rowId) !== 16) {
            throw new \InvalidArgumentException(
                'Row id must be the 16-byte BINARY(16) primary key.'
            );
        }

        return 'manager2|' . $table . '|' . $column . '|' . bin2hex($rowId);
    }
}
