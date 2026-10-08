<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Store;

use ScannerTrap\Exception\StoreException;
use ScannerTrap\Redis\PredisConnection;
use ScannerTrap\Redis\RedisConnection;
use ScannerTrap\Tests\Support\Env;

final class PredisLocalStoreTest extends PhpRedisLocalStoreTest
{
    protected function connect(): RedisConnection
    {
        return Env::predis();
    }

    public function test_an_unreachable_redis_is_a_store_exception(): void
    {
        $this->expectException(StoreException::class);
        PredisConnection::connect('127.0.0.1', 1, 0, null, 0.2, 0.2)->raw('PING');
    }
}
