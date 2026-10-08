<?php

declare(strict_types=1);

namespace ScannerTrap\Redis;

use Predis\Client;
use Predis\PredisException;
use ScannerTrap\Exception\StoreException;

/** predis/predis. Every command goes through executeRaw(), so the client's own prefix never applies. */
final class PredisConnection implements RedisConnection
{
    public function __construct(private readonly Client $client)
    {
    }

    public static function connect(string $host, int $port, int $database, ?string $password, float $timeout, float $readTimeout, bool $persistent = false): self
    {
        $parameters = ['scheme' => 'tcp', 'host' => $host, 'port' => $port, 'database' => $database, 'timeout' => $timeout, 'read_write_timeout' => $readTimeout];
        if ($password !== null && $password !== '') {
            $parameters['password'] = $password;
        }
        if ($persistent) {
            $parameters['persistent'] = true;
        }
        return new self(new Client($parameters));
    }

    public function raw(string ...$args): mixed
    {
        try {
            $error = false;
            $result = $this->client->executeRaw(array_values($args), $error);
        } catch (PredisException $e) {
            throw new StoreException('Redis: ' . $e->getMessage(), 0, $e);
        }
        if ($error) {
            throw new StoreException('Redis error: ' . (is_scalar($result) ? (string) $result : 'unknown'));
        }
        return $result;
    }
}
