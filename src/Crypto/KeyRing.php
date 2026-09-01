<?php

declare(strict_types=1);

namespace Manager2\Crypto;

/**
 * Versioned key material, loaded from the environment or a KMS.
 *
 * Design notes
 * ------------
 * Key material never touches MariaDB. The `encryption_keys` table records only
 * which versions exist and their lifecycle status; the bytes come from here.
 * That separation is the entire point of encrypting at the field level: a dump
 * of the database, on its own, decrypts nothing.
 *
 * Two independent root secrets are held, so that a compromise of the searchable
 * index key does not also yield plaintext:
 *
 *   - `field`       root for AES-256-GCM data encryption keys
 *   - `blind_index` root for HMAC-SHA256 searchable index keys
 *
 * Per-column subkeys are derived with HKDF rather than reusing a root key
 * directly, which bounds the amount of data under any single key and stops a
 * ciphertext from one column being replayed into another.
 *
 * Rotation
 * --------
 * Add a new version, mark it active, and leave the previous versions loaded and
 * readable. New writes seal under the active version; reads accept any loaded
 * version. `bin/reencrypt.php` then walks the tables lazily. Only once no rows
 * reference version N may its material be withdrawn.
 *
 * In production, replace the env-var loader with a call to AWS KMS / GCP KMS /
 * HashiCorp Vault and cache the unwrapped DEK in memory for the request only.
 */
final class KeyRing
{
    public const PURPOSE_FIELD = 'field';
    public const PURPOSE_BLIND_INDEX = 'blind_index';

    private const MIN_KEY_BYTES = 32;

    /** @var array<string, array<int, string>> purpose => [version => 32 raw bytes] */
    private array $keys = [];

    /** @var array<string, int> purpose => active version */
    private array $activeVersion = [];

    /**
     * @param array<string, array<int, string>> $keys          purpose => version => raw key bytes
     * @param array<string, int>                $activeVersion purpose => version to seal new data under
     */
    public function __construct(array $keys, array $activeVersion)
    {
        foreach ($keys as $purpose => $versions) {
            foreach ($versions as $version => $material) {
                if (strlen($material) < self::MIN_KEY_BYTES) {
                    throw new \InvalidArgumentException(sprintf(
                        'Key %s v%d is %d bytes; at least %d required.',
                        $purpose,
                        $version,
                        strlen($material),
                        self::MIN_KEY_BYTES
                    ));
                }
            }
        }

        foreach ($activeVersion as $purpose => $version) {
            if (!isset($keys[$purpose][$version])) {
                throw new \InvalidArgumentException(
                    "Active version {$version} for '{$purpose}' has no key material loaded."
                );
            }
        }

        $this->keys = $keys;
        $this->activeVersion = $activeVersion;
    }

    /**
     * Build a key ring from the environment.
     *
     * Expected variables, base64-encoded, at least 32 bytes decoded:
     *
     *   M2_FIELD_KEY_V1=...        M2_BLIND_INDEX_KEY_V1=...
     *   M2_FIELD_KEY_V2=...        M2_BLIND_INDEX_KEY_V2=...
     *   M2_FIELD_KEY_ACTIVE=2      M2_BLIND_INDEX_KEY_ACTIVE=2
     *
     * Generate one with:  openssl rand -base64 32
     */
    public static function fromEnvironment(): self
    {
        $prefixes = [
            self::PURPOSE_FIELD => 'M2_FIELD_KEY',
            self::PURPOSE_BLIND_INDEX => 'M2_BLIND_INDEX_KEY',
        ];

        $keys = [];
        $active = [];

        foreach ($prefixes as $purpose => $prefix) {
            for ($version = 1; $version <= 99; $version++) {
                $raw = getenv("{$prefix}_V{$version}");
                if ($raw === false || $raw === '') {
                    continue;
                }

                $decoded = base64_decode($raw, true);
                if ($decoded === false) {
                    throw new \RuntimeException("{$prefix}_V{$version} is not valid base64.");
                }

                $keys[$purpose][$version] = $decoded;
            }

            if (!isset($keys[$purpose])) {
                throw new \RuntimeException(
                    "No key material found for '{$purpose}'. Set {$prefix}_V1."
                );
            }

            $declared = getenv("{$prefix}_ACTIVE");
            $active[$purpose] = $declared !== false && $declared !== ''
                ? (int) $declared
                : max(array_keys($keys[$purpose]));
        }

        return new self($keys, $active);
    }

    public function activeVersion(string $purpose): int
    {
        return $this->activeVersion[$purpose]
            ?? throw new \InvalidArgumentException("Unknown key purpose '{$purpose}'.");
    }

    /**
     * Derive the subkey for one logical column.
     *
     * HKDF-Expand with the column identity as `info`, so every
     * (purpose, version, table, column) tuple gets a distinct 256-bit key.
     */
    public function subkey(string $purpose, int $version, string $table, string $column): string
    {
        $root = $this->keys[$purpose][$version] ?? null;

        if ($root === null) {
            // Deliberately vague: this string can reach a log.
            throw new KeyUnavailableException(
                "No key material loaded for {$purpose} v{$version}."
            );
        }

        return hash_hkdf('sha256', $root, 32, "manager2|{$purpose}|{$table}|{$column}", '');
    }

    /** @return list<int> every loaded version for a purpose, ascending */
    public function loadedVersions(string $purpose): array
    {
        $versions = array_keys($this->keys[$purpose] ?? []);
        sort($versions);

        return $versions;
    }

    /** Best-effort scrub of key material from memory. */
    public function __destruct()
    {
        foreach ($this->keys as $purpose => $versions) {
            foreach ($versions as $version => $material) {
                if (function_exists('sodium_memzero')) {
                    try {
                        sodium_memzero($material);
                    } catch (\SodiumException) {
                        // Nothing useful to do; PHP may have copied the string already.
                    }
                }
                unset($this->keys[$purpose][$version]);
            }
        }
    }
}
