<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Guard;

use ScannerTrap\Exception\StoreException;
use ScannerTrap\Guard;
use ScannerTrap\Redis\PhpRedisConnection;
use ScannerTrap\Redis\RedisConnection;
use ScannerTrap\RequestContext;
use ScannerTrap\Store\LocalStore;
use ScannerTrap\Store\RedisLocalStore;
use ScannerTrap\Tests\Support\Env;

class PhpRedisGuardTest extends GuardScenarios
{
    protected RedisConnection $redis;

    protected function connect(): RedisConnection
    {
        return Env::phpRedis();
    }

    protected function setUp(): void
    {
        $this->redis = $this->connect();
        $this->redis->raw('FLUSHDB');
    }

    protected function tearDown(): void
    {
        $this->redis->raw('FLUSHDB');
    }

    protected function createStore(): LocalStore
    {
        return new RedisLocalStore($this->connect());
    }

    protected function corruptLists(): void
    {
        $this->redis->raw('SET', 'scanner-trap:patterns', 'plain text');
    }

    public function test_an_unreachable_redis_throws_for_the_entry_point_to_catch(): void
    {
        $this->expectException(StoreException::class);
        $guard = new Guard(new RedisLocalStore(PhpRedisConnection::connect('127.0.0.1', 1, 0, null, 0.2, 0.2)));
        $guard->decide(new RequestContext(self::SCANNER, 'GET', '/.env'));
    }
}
