<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Store;

use ScannerTrap\Block;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Redis\PhpRedisConnection;
use ScannerTrap\Redis\RedisConnection;
use ScannerTrap\Store\LocalStore;
use ScannerTrap\Store\RedisLocalStore;
use ScannerTrap\Tests\Support\Env;

class PhpRedisLocalStoreTest extends LocalStoreContract
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

    public function test_keys_are_the_specs_and_carry_the_prefix(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('203.0.113.7', time(), time() + 600), true);
        $store->replaceLists(['/.env*'], []);

        $this->assertSame(1, $this->redis->raw('EXISTS', 'scanner-trap:block:203.0.113.7'));
        $ttl = $this->redis->raw('TTL', 'scanner-trap:block:203.0.113.7');
        $this->assertIsInt($ttl);
        $this->assertGreaterThan(590, $ttl);
        $this->assertSame('["/.env*"]', $this->redis->raw('GET', 'scanner-trap:patterns'));
        $this->assertSame(1, $this->redis->raw('XLEN', 'scanner-trap:events'));
    }

    public function test_two_prefixes_share_one_database_without_seeing_each_other(): void
    {
        $one = new RedisLocalStore($this->connect(), 'app-one:');
        $two = new RedisLocalStore($this->connect(), 'app-two:');
        $one->addBlock(new Block('203.0.113.7', time(), 0), true);

        $this->assertTrue($one->read('203.0.113.7')->blocked);
        $this->assertFalse($two->read('203.0.113.7')->blocked);
        $this->assertSame([], $two->events(10));
    }

    public function test_a_corrupted_list_key_makes_a_corrupt_snapshot(): void
    {
        $this->redis->raw('SET', 'scanner-trap:patterns', 'plain text');

        $this->assertTrue($this->createStore()->read('203.0.113.7')->corrupt);
    }

    public function test_a_malformed_stream_entry_is_dropped(): void
    {
        $this->redis->raw('XADD', 'scanner-trap:events', '*', 'data', 'garbage');
        $store = $this->createStore();

        $this->assertSame([], $store->events(10));
        $this->assertSame(0, $this->redis->raw('XLEN', 'scanner-trap:events'));
    }

    public function test_an_unreachable_redis_is_a_store_exception(): void
    {
        $this->expectException(StoreException::class);
        PhpRedisConnection::connect('127.0.0.1', 1, 0, null, 0.2, 0.2)->raw('PING');
    }

    public function test_network_keys_are_the_specs(): void
    {
        $this->createStore()->addBlock(new Block('45.155.205.0/24', time(), time() + 600, source: 'subnet'), false);

        $this->assertSame(1, $this->redis->raw('EXISTS', 'scanner-trap:net:45.155.205.0/24'));
        $this->assertSame(['4/24'], $this->redis->raw('SMEMBERS', 'scanner-trap:netlens'));
    }

    public function test_an_import_writes_a_new_generation_and_frees_the_old_one(): void
    {
        $store = $this->createStore();
        $store->replaceList('own', ['45.155.205.0/24'], 1000);
        $first = $this->redis->raw('KEYS', 'scanner-trap:lh:own:*');
        $store->replaceList('own', ['91.92.248.0/22'], 2000);
        $second = $this->redis->raw('KEYS', 'scanner-trap:lh:own:*');

        $this->assertIsArray($first);
        $this->assertIsArray($second);
        $this->assertCount(1, $second);
        $this->assertNotSame($first, $second);
    }
}
