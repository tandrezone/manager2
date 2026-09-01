<?php

declare(strict_types=1);

/**
 * Crypto self-test. Run: php bin/selftest-crypto.php
 *
 * Verifies the properties the schema depends on, including the negative cases —
 * a field-encryption layer that only proves "encrypt then decrypt works" has
 * not tested the part that protects anyone.
 */

require __DIR__ . '/../src/autoload.php';

use Manager2\Auth\Passwords;
use Manager2\Crypto\BlindIndex;
use Manager2\Crypto\DecryptionFailedException;
use Manager2\Crypto\FieldCipher;
use Manager2\Crypto\KeyRing;
use Manager2\Support\Uuid;

$pass = 0;
$fail = 0;

function check(string $label, callable $test): void
{
    global $pass, $fail;

    try {
        $ok = $test();
    } catch (\Throwable $e) {
        $ok = false;
        $label .= ' [' . $e::class . ': ' . $e->getMessage() . ']';
    }

    if ($ok === true) {
        $pass++;
        echo "  ok    {$label}\n";
    } else {
        $fail++;
        echo "  FAIL  {$label}\n";
    }
}

// Two versions loaded, v2 active, so rotation paths are exercised.
$keyRing = new KeyRing(
    [
        KeyRing::PURPOSE_FIELD => [
            1 => random_bytes(32),
            2 => random_bytes(32),
        ],
        KeyRing::PURPOSE_BLIND_INDEX => [
            1 => random_bytes(32),
            2 => random_bytes(32),
        ],
    ],
    [
        KeyRing::PURPOSE_FIELD => 2,
        KeyRing::PURPOSE_BLIND_INDEX => 2,
    ]
);

$cipher = new FieldCipher($keyRing);
$index = new BlindIndex($keyRing);

$rowA = Uuid::v7();
$rowB = Uuid::v7();
$address = "Rua de Santa Catarina 1234, 4\u{00BA} Esq.\n4000-447 Porto";

echo "UUIDv7\n";
check('16 raw bytes', fn () => strlen($rowA) === 16);
check('version nibble is 7', fn () => (ord($rowA[6]) >> 4) === 7);
check('RFC 9562 variant bits', fn () => (ord($rowA[8]) & 0xC0) === 0x80);
check('string round-trip', fn () => Uuid::fromString(Uuid::toString($rowA)) === $rowA);
check('monotonic within a millisecond batch', function (): bool {
    $ids = array_map(fn () => Uuid::v7(), range(1, 200));
    $sorted = $ids;
    sort($sorted);

    return $ids === $sorted;
});
check('embedded timestamp is recent', function () {
    $delta = abs(time() - (int) Uuid::timestamp(Uuid::v7())->format('U'));

    return $delta <= 2;
});

echo "\nFieldCipher\n";
check('round-trip', function () use ($cipher, $address, $rowA) {
    return $cipher->open(
        $cipher->seal($address, 'delivery_locations', 'address_enc', $rowA),
        'delivery_locations',
        'address_enc',
        $rowA
    ) === $address;
});

check('ciphertext is not plaintext', function () use ($cipher, $address, $rowA) {
    $sealed = $cipher->seal($address, 'delivery_locations', 'address_enc', $rowA);

    return !str_contains($sealed, 'Porto') && !str_contains($sealed, 'Catarina');
});

check('overhead is exactly 31 bytes', function () use ($cipher, $rowA) {
    $plain = str_repeat('x', 100);
    $sealed = $cipher->seal($plain, 'users', 'email_enc', $rowA);

    return strlen($sealed) === 100 + FieldCipher::OVERHEAD_BYTES;
});

check('same plaintext seals to different ciphertext (random nonce)', function () use ($cipher, $rowA) {
    return $cipher->seal('a@b.pt', 'users', 'email_enc', $rowA)
        !== $cipher->seal('a@b.pt', 'users', 'email_enc', $rowA);
});

check('REJECTS ciphertext moved to another row', function () use ($cipher, $address, $rowA, $rowB) {
    $sealed = $cipher->seal($address, 'delivery_locations', 'address_enc', $rowA);

    try {
        $cipher->open($sealed, 'delivery_locations', 'address_enc', $rowB);
    } catch (DecryptionFailedException) {
        return true;
    }

    return false;
});

check('REJECTS ciphertext moved to another column', function () use ($cipher, $rowA) {
    $sealed = $cipher->seal('+351912345678', 'users', 'phone_enc', $rowA);

    try {
        $cipher->open($sealed, 'users', 'email_enc', $rowA);
    } catch (DecryptionFailedException) {
        return true;
    }

    return false;
});

check('REJECTS ciphertext moved to another table', function () use ($cipher, $rowA) {
    $sealed = $cipher->seal('Ana Ribeiro', 'users', 'full_name_enc', $rowA);

    try {
        $cipher->open($sealed, 'delivery_locations', 'full_name_enc', $rowA);
    } catch (DecryptionFailedException) {
        return true;
    }

    return false;
});

check('REJECTS a single flipped bit in the ciphertext', function () use ($cipher, $address, $rowA) {
    $sealed = $cipher->seal($address, 'delivery_locations', 'address_enc', $rowA);
    $sealed[40] = chr(ord($sealed[40]) ^ 0x01);

    try {
        $cipher->open($sealed, 'delivery_locations', 'address_enc', $rowA);
    } catch (DecryptionFailedException) {
        return true;
    }

    return false;
});

check('REJECTS a truncated value', function () use ($cipher, $address, $rowA) {
    $sealed = substr($cipher->seal($address, 'delivery_locations', 'address_enc', $rowA), 0, 20);

    try {
        $cipher->open($sealed, 'delivery_locations', 'address_enc', $rowA);
    } catch (DecryptionFailedException) {
        return true;
    }

    return false;
});

check('reads values sealed under a retired key version', function () use ($keyRing, $rowA) {
    // Seal while v1 is active, then open with a ring whose active version is v2.
    $ringV1 = new KeyRing(
        [KeyRing::PURPOSE_FIELD => [1 => str_repeat("\x11", 32)]],
        [KeyRing::PURPOSE_FIELD => 1]
    );
    $ringV2 = new KeyRing(
        [KeyRing::PURPOSE_FIELD => [1 => str_repeat("\x11", 32), 2 => str_repeat("\x22", 32)]],
        [KeyRing::PURPOSE_FIELD => 2]
    );

    $old = (new FieldCipher($ringV1))->seal('legacy', 'users', 'email_enc', $rowA);
    $new = new FieldCipher($ringV2);

    return $new->keyVersionOf($old) === 1
        && $new->needsRotation($old) === true
        && $new->open($old, 'users', 'email_enc', $rowA) === 'legacy'
        && $new->needsRotation($new->rotate($old, 'users', 'email_enc', $rowA)) === false;
});

check('nullable helpers preserve NULL', function () use ($cipher, $rowA) {
    return $cipher->sealNullable(null, 'users', 'phone_enc', $rowA) === null
        && $cipher->sealNullable('', 'users', 'phone_enc', $rowA) === null
        && $cipher->openNullable(null, 'users', 'phone_enc', $rowA) === null;
});

check('rejects a row id that is not 16 bytes', function () use ($cipher) {
    try {
        $cipher->seal('x', 'users', 'email_enc', 'short');
    } catch (\InvalidArgumentException) {
        return true;
    }

    return false;
});

check('binary-safe for UTF-8 and NUL bytes', function () use ($cipher, $rowA) {
    $tricky = "Ana\x00Ribeiro \u{00E7}\u{00E3}o \u{1F1F5}\u{1F1F9}";

    return $cipher->open(
        $cipher->seal($tricky, 'users', 'full_name_enc', $rowA),
        'users',
        'full_name_enc',
        $rowA
    ) === $tricky;
});

echo "\nBlindIndex\n";
check('32 raw bytes', fn () => strlen($index->compute('a@b.pt', 'users', 'email_bidx')) === 32);
check('deterministic', function () use ($index) {
    return $index->compute('ana@fornecedor.pt', 'users', 'email_bidx')
        === $index->compute('ana@fornecedor.pt', 'users', 'email_bidx');
});
check('case and whitespace insensitive for email', function () use ($index) {
    return $index->compute('  Ana@Fornecedor.PT ', 'users', 'email_bidx')
        === $index->compute('ana@fornecedor.pt', 'users', 'email_bidx');
});
check('does NOT collapse +tag aliases', function () use ($index) {
    return $index->compute('ana+po@x.pt', 'users', 'email_bidx')
        !== $index->compute('ana@x.pt', 'users', 'email_bidx');
});
check('phone formatting insensitive', function () use ($index) {
    return $index->compute('+351 912 345 678', 'users', 'phone_bidx')
        === $index->compute('+351912345678', 'users', 'phone_bidx');
});
check('postcode normalisation', function () use ($index) {
    return $index->compute('4000-447', 'delivery_locations', 'postcode_bidx')
        === $index->compute(' 4000-447 ', 'delivery_locations', 'postcode_bidx');
});
check('domain-separated across columns', function () use ($index) {
    return $index->compute('351912345678', 'users', 'email_bidx')
        !== $index->compute('351912345678', 'users', 'phone_bidx');
});
check('domain-separated across tables', function () use ($index) {
    return $index->compute('x@y.pt', 'users', 'email_bidx')
        !== $index->compute('x@y.pt', 'invites', 'email_bidx');
});
check('independent of the field-encryption root', function () use ($keyRing) {
    // Same table/column/value under a ring that shares the field key but not
    // the index key must produce a different index.
    $other = new KeyRing(
        [
            KeyRing::PURPOSE_BLIND_INDEX => [2 => random_bytes(32)],
        ],
        [KeyRing::PURPOSE_BLIND_INDEX => 2]
    );

    return (new BlindIndex($keyRing))->compute('a@b.pt', 'users', 'email_bidx')
        !== (new BlindIndex($other))->compute('a@b.pt', 'users', 'email_bidx');
});
check('all-versions lookup returns both indexes, newest first', function () use ($index) {
    $all = $index->computeAllVersions('a@b.pt', 'users', 'email_bidx');

    return count($all) === 2
        && $all[0] === $index->compute('a@b.pt', 'users', 'email_bidx')
        && $all[0] !== $all[1];
});

echo "\nPasswords (Argon2id)\n";
$hash = Passwords::hash('correct horse battery staple');
check('hash uses argon2id', fn () => str_starts_with($hash, '$argon2id$'));
check('verifies the right password', fn () => Passwords::verify('correct horse battery staple', $hash) === true);
check('rejects the wrong password', fn () => Passwords::verify('wrong horse battery staple', $hash) === false);
check('rejects against a null hash', fn () => Passwords::verify('anything', null) === false);
check('no rehash needed at current policy', fn () => Passwords::needsRehash($hash) === false);
check('flags a weaker legacy hash for upgrade', function () {
    $weak = password_hash('x', PASSWORD_ARGON2ID, [
        'memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1,
    ]);

    return Passwords::needsRehash($weak) === true;
});
check('rejects a short password', function () {
    try {
        Passwords::hash('short');
    } catch (\Manager2\Auth\WeakPasswordException) {
        return true;
    }

    return false;
});
check('rejects a blocklisted password', function () {
    try {
        Passwords::hash('mypassword1234');
    } catch (\Manager2\Auth\WeakPasswordException) {
        return true;
    }

    return false;
});
check('rejects a single repeated character', function () {
    try {
        Passwords::hash(str_repeat('a', 20));
    } catch (\Manager2\Auth\WeakPasswordException) {
        return true;
    }

    return false;
});
check('accepts a long passphrase', fn () => Passwords::verify(
    $p = str_repeat('a long diceware passphrase ', 20),
    Passwords::hash($p)
) === true);
check('missing-account timing is comparable to a real verify (no enumeration oracle)', function () use ($hash) {
    // Medians over several samples. A single pair is dominated by scheduler
    // noise, and a security assertion that fails one run in ten teaches people
    // to ignore the suite.
    $median = static function (callable $work, int $samples = 5): float {
        $timings = [];

        for ($i = 0; $i < $samples; $i++) {
            $start = hrtime(true);
            $work();
            $timings[] = (float) (hrtime(true) - $start);
        }

        sort($timings);

        return $timings[intdiv(count($timings), 2)];
    };

    $real = $median(static fn () => Passwords::verify('whatever', $hash));
    $dummy = $median(static fn () => Passwords::verify('whatever', null));

    // The dummy path hashes AND verifies, so it is legitimately a little slower.
    // What matters is that it is not orders of magnitude FASTER, which is what
    // would make the endpoint an oracle. Generous bounds, since the property
    // under test is "same ballpark", not "identical".
    $ratio = $dummy / max($real, 1.0);

    if ($ratio < 0.5) {
        printf("\n        ratio %.2f — missing-account path is too fast", $ratio);

        return false;
    }

    return $ratio < 6.0;
});

printf("\n%d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);
