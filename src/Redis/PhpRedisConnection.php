<?php

declare(strict_types=1);

namespace ScannerTrap\Redis;

use ScannerTrap\Exception\StoreException;

/**
 * ext-redis. Every command goes through rawCommand(), so the client's own prefix and serializer never apply. A connection
 * made by connect() opens on the first command.
 */
final class PhpRedisConnection implements RedisConnection
{
    private ?\Redis $redis = null;

    /** @param \Closure(): \Redis $connector */
    private function __construct(private readonly \Closure $connector)
    {
    }

    public static function wrap(\Redis $redis): self
    {
        return new self(static fn (): \Redis => $redis);
    }

    public static function connect(string $host, int $port, int $database, ?string $password, float $timeout, float $readTimeout): self
    {
        return new self(static function () use ($host, $port, $database, $password, $timeout, $readTimeout): \Redis {
            $redis = new \Redis();
            try {
                if (!$redis->connect($host, $port, $timeout, null, 0, $readTimeout)) {
                    throw new StoreException("Redis unreachable at {$host}:{$port}");
                }
                if ($password !== null && $password !== '') {
                    $redis->auth($password);
                }
                if ($database !== 0) {
                    $redis->select($database);
                }
            } catch (\RedisException $e) {
                throw new StoreException("Redis unreachable at {$host}:{$port}: {$e->getMessage()}", 0, $e);
            }
            return $redis;
        });
    }

    public function eval(string $script, array $keys, array $args): mixed
    {
        return $this->raw('EVAL', $script, (string) count($keys), ...$keys, ...$args);
    }

    public function raw(string ...$args): mixed
    {
        $this->redis ??= ($this->connector)();
        try {
            $this->redis->clearLastError();
            $result = $this->redis->rawCommand(...$args);
            $error = $this->redis->getLastError();
        } catch (\RedisException $e) {
            throw new StoreException('Redis: ' . $e->getMessage(), 0, $e);
        }
        if ($error !== null) {
            throw new StoreException('Redis error: ' . $error);
        }
        return self::nil($result);
    }

    /** phpredis answers nil with false, also inside arrays. */
    private static function nil(mixed $value): mixed
    {
        if ($value === false) {
            return null;
        }
        return is_array($value) ? array_map(self::nil(...), $value) : $value;
    }
}
