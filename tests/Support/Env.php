<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Support;

use PHPUnit\Framework\Assert;
use ScannerTrap\Redis\PhpRedisConnection;
use ScannerTrap\Redis\PredisConnection;

/** Connection settings for integration tests, from the env vars phpunit.xml.dist defaults. */
final class Env
{
    public static function get(string $name): string
    {
        $value = getenv($name);
        return is_string($value) ? $value : '';
    }

    public static function redisDatabase(): int
    {
        return (int) self::get('SCANNER_TRAP_REDIS_DB');
    }

    public static function phpRedis(float $readTimeout = 2.0): PhpRedisConnection
    {
        if (!extension_loaded('redis')) {
            Assert::markTestSkipped('ext-redis is not loaded.');
        }
        return PhpRedisConnection::connect(self::get('SCANNER_TRAP_REDIS_HOST'), (int) self::get('SCANNER_TRAP_REDIS_PORT'), self::redisDatabase(), null, 0.5, $readTimeout);
    }

    public static function predis(float $readTimeout = 2.0): PredisConnection
    {
        if (!class_exists(\Predis\Client::class)) {
            Assert::markTestSkipped('predis/predis is not installed.');
        }
        return PredisConnection::connect(self::get('SCANNER_TRAP_REDIS_HOST'), (int) self::get('SCANNER_TRAP_REDIS_PORT'), self::redisDatabase(), null, 0.5, $readTimeout);
    }

    /** @return array{type: string, host: string, port: int, database: int} the same Redis as a package config */
    public static function redisConfig(): array
    {
        return ['type' => 'redis', 'host' => self::get('SCANNER_TRAP_REDIS_HOST'), 'port' => (int) self::get('SCANNER_TRAP_REDIS_PORT'), 'database' => self::redisDatabase()];
    }

    /** A fresh, empty database: SQLite in a temp file, MySQL or PostgreSQL from the env with every table dropped. */
    public static function pdo(string $driver): \PDO
    {
        if ($driver === 'sqlite') {
            return new \PDO('sqlite:' . tempnam(sys_get_temp_dir(), 'scanner-trap-'), null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        }
        $prefix = 'SCANNER_TRAP_' . strtoupper($driver) . '_';
        if (self::get($prefix . 'DSN') === '') {
            Assert::markTestSkipped("{$prefix}DSN is not set; start docker compose and set it.");
        }
        $pdo = new \PDO(self::get($prefix . 'DSN'), self::get($prefix . 'USER'), self::get($prefix . 'PASSWORD'), [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        foreach (['block', 'pattern', 'allow', 'meta'] as $table) {
            $pdo->exec('DROP TABLE IF EXISTS scanner_trap_' . $table);
        }
        return $pdo;
    }

    /** @return array{dsn: string, user: string, password: string} */
    public static function pdoConfig(string $driver, \PDO $pdo): array
    {
        if ($driver === 'sqlite') {
            $statement = $pdo->query('PRAGMA database_list');
            /** @var array{file: string} $row */
            $row = ($statement === false ? false : $statement->fetch(\PDO::FETCH_ASSOC)) ?: ['file' => ''];
            return ['dsn' => 'sqlite:' . $row['file'], 'user' => '', 'password' => ''];
        }
        $prefix = 'SCANNER_TRAP_' . strtoupper($driver) . '_';
        return ['dsn' => self::get($prefix . 'DSN'), 'user' => self::get($prefix . 'USER'), 'password' => self::get($prefix . 'PASSWORD')];
    }
}
