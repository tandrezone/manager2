<?php

declare(strict_types=1);

namespace Manager2\Support;

/**
 * UUIDv7 (RFC 9562) as BINARY(16), with a monotonic intra-millisecond counter.
 *
 * Chosen over AUTO_INCREMENT for two reasons that matter here:
 *
 *  1. The id exists *before* the INSERT, so it can be bound into the associated
 *     data of an AEAD-encrypted column (see Crypto\FieldCipher). Without an id
 *     available up front, a row's ciphertext could be copied into another row
 *     undetected.
 *  2. UUIDv7 is time-ordered, so unlike UUIDv4 it does not scatter InnoDB
 *     clustered-index writes across the whole keyspace. With a 16-byte random
 *     primary key, every insert lands in a random page, the buffer pool thrashes
 *     and page splits multiply; time-ordered keys append.
 *
 * Layout (RFC 9562 s5.7):
 *
 *   0-5   48-bit big-endian Unix timestamp, milliseconds
 *   6     version 0b0111 in the high nibble, then the top 4 bits of rand_a
 *   7     low 8 bits of rand_a
 *   8     variant 0b10 in the two high bits, then 6 bits of rand_b
 *   9-15  remaining 56 bits of rand_b
 *
 * rand_a is used as the 12-bit monotonic counter described in RFC 9562 s6.2
 * "method 3": seeded randomly at the start of each millisecond and incremented
 * for subsequent ids in the same millisecond, so ids generated in a tight loop
 * sort in creation order. That property is what makes bulk inserts append
 * rather than scatter, and it makes `ORDER BY id` a valid proxy for
 * `ORDER BY created_at` within a process.
 *
 * Caveat, stated because it is easy to over-trust: monotonicity holds within a
 * single PHP process. Two php-fpm workers generating ids in the same
 * millisecond can interleave. Do not use id ordering as a distributed sequence
 * or as evidence of causal order across requests — that is what the explicit
 * timestamp columns and the audit log's hash chain are for.
 */
final class Uuid
{
    private const COUNTER_BITS = 12;
    private const COUNTER_MAX = (1 << self::COUNTER_BITS) - 1;

    /**
     * Seed ceiling for a new millisecond.
     *
     * Seeding randomly rather than at zero avoids leaking exactly how many ids
     * the process has minted, while leaving at least 3072 increments of headroom
     * before the counter can overflow within one millisecond.
     */
    private const COUNTER_SEED_MAX = 1023;

    private static int $lastMs = -1;
    private static int $counter = 0;

    /** Generate a UUIDv7 as 16 raw bytes. */
    public static function v7(): string
    {
        [$unixTsMs, $counter] = self::nextTick();

        // 48 bits of big-endian millisecond timestamp: drop the top 2 bytes of
        // the 64-bit pack.
        $bytes = substr(pack('J', $unixTsMs), 2, 6);

        // Octet 6: version 7 then the counter's high 4 bits. Octet 7: low 8 bits.
        $bytes .= chr(0x70 | (($counter >> 8) & 0x0F));
        $bytes .= chr($counter & 0xFF);

        $randB = random_bytes(8);
        // Octet 8: RFC 9562 variant 0b10 in the two high bits.
        $bytes .= chr((ord($randB[0]) & 0x3F) | 0x80);
        $bytes .= substr($randB, 1, 7);

        return $bytes;
    }

    /**
     * Advance the clock/counter pair.
     *
     * @return array{0:int, 1:int} millisecond timestamp and 12-bit counter
     */
    private static function nextTick(): array
    {
        $now = (int) (microtime(true) * 1000);

        if ($now > self::$lastMs) {
            self::$lastMs = $now;
            self::$counter = random_int(0, self::COUNTER_SEED_MAX);

            return [$now, self::$counter];
        }

        // Same millisecond, or the wall clock stepped backwards (NTP, leap
        // smear, VM migration). In both cases hold the previous timestamp and
        // keep counting, so ids never regress.
        if (self::$counter < self::COUNTER_MAX) {
            return [self::$lastMs, ++self::$counter];
        }

        // 4096 ids inside one millisecond. Wait for the clock rather than
        // reusing a counter value, which would break uniqueness.
        do {
            usleep(100);
            $now = (int) (microtime(true) * 1000);
        } while ($now <= self::$lastMs);

        self::$lastMs = $now;
        self::$counter = random_int(0, self::COUNTER_SEED_MAX);

        return [$now, self::$counter];
    }

    /** Format 16 raw bytes as canonical 8-4-4-4-12 hyphenated hex. */
    public static function toString(string $bytes): string
    {
        if (strlen($bytes) !== 16) {
            throw new \InvalidArgumentException('UUID must be exactly 16 bytes.');
        }

        return implode('-', unpack('H8a/H4b/H4c/H4d/H12e', $bytes));
    }

    /** Parse a hyphenated or bare hex UUID into 16 raw bytes. */
    public static function fromString(string $uuid): string
    {
        $hex = str_replace('-', '', trim($uuid));

        if (strlen($hex) !== 32 || !ctype_xdigit($hex)) {
            throw new \InvalidArgumentException('Malformed UUID string.');
        }

        return (string) hex2bin($hex);
    }

    /**
     * True if the value is a well-formed v7 id.
     *
     * Use at trust boundaries before binding to a query: it is cheap, and it
     * turns a malformed route parameter into a 400 instead of a puzzling empty
     * result set.
     */
    public static function isValid(string $bytes): bool
    {
        return strlen($bytes) === 16
            && (ord($bytes[6]) >> 4) === 7
            && (ord($bytes[8]) & 0xC0) === 0x80;
    }

    /** Recover the creation time embedded in a v7 id. */
    public static function timestamp(string $bytes): \DateTimeImmutable
    {
        if (strlen($bytes) !== 16) {
            throw new \InvalidArgumentException('UUID must be exactly 16 bytes.');
        }

        /** @var array{ms:int} $parts */
        $parts = unpack('Jms', "\x00\x00" . substr($bytes, 0, 6));

        return \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', $parts['ms'] / 1000))
            ?: throw new \RuntimeException('Could not decode UUIDv7 timestamp.');
    }
}
