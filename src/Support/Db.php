<?php

declare(strict_types=1);

namespace Manager2\Support;

use PDO;

/**
 * PDO factory and small transaction helper.
 *
 * ERRMODE_EXCEPTION and EMULATE_PREPARES=false are both load-bearing:
 *
 *  - Without exceptions, a failed statement returns false and execution
 *    continues on stale data, which in a payment path means a silently
 *    unrecorded settlement.
 *  - With emulated prepares, PDO interpolates values into the SQL string
 *    itself. That reintroduces the injection surface real prepared statements
 *    remove, and it also breaks binding of raw BINARY(16) values containing
 *    quote bytes.
 */
final class Db
{
    public static function connect(
        ?string $dsn = null,
        ?string $user = null,
        ?string $password = null
    ): PDO {
        $dsn ??= getenv('M2_DB_DSN')
            ?: 'mysql:host=127.0.0.1;port=3306;dbname=manager2;charset=utf8mb4';
        $user ??= getenv('M2_DB_USER') ?: 'manager2';
        $password ??= getenv('M2_DB_PASSWORD') ?: '';

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ];

        $caFile = getenv('M2_DB_SSL_CA');
        if (is_string($caFile) && $caFile !== '') {
            $options[PDO::MYSQL_ATTR_SSL_CA] = $caFile;
            $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true;
        }

        $pdo = new PDO($dsn, $user, $password, $options);

        // STRICT_ALL_TABLES turns a silently truncated VARBINARY — which would
        // corrupt a ciphertext beyond recovery — into an error.
        $pdo->exec(
            "SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION," .
            "ERROR_FOR_DIVISION_BY_ZERO,NO_ZERO_DATE,NO_ZERO_IN_DATE'"
        );
        $pdo->exec("SET SESSION time_zone = '+00:00'");

        return $pdo;
    }

    /**
     * Run a closure inside a transaction, rolling back on any throwable.
     *
     * Nested calls join the outer transaction rather than opening a second one,
     * because MariaDB has no true nested transactions and a naive inner
     * `commit()` would prematurely publish the outer unit of work.
     *
     * @template T
     * @param  callable(PDO):T $work
     * @return T
     */
    public static function transaction(PDO $pdo, callable $work): mixed
    {
        if ($pdo->inTransaction()) {
            return $work($pdo);
        }

        $pdo->beginTransaction();

        try {
            $result = $work($pdo);
            $pdo->commit();

            return $result;
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            throw $e;
        }
    }

    /**
     * Hash an IP address for storage.
     *
     * An IP is personal data (CJEU C-582/14, Breyer), so it is not stored raw.
     * A keyed HMAC rather than a bare hash: the IPv4 space is 2^32, small
     * enough to enumerate exhaustively against an unkeyed digest in seconds,
     * which would make a "hashed" column plaintext in all but name.
     */
    public static function hashIp(?string $ip, string $key): ?string
    {
        if ($ip === null || $ip === '') {
            return null;
        }

        return hash_hmac('sha256', $ip, $key, true);
    }
}
