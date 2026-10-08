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

    /** @return array{RedisConnection, \ArrayObject<int, string>} a connection that records each command's name */
    private function recording(): array
    {
        $commands = new \ArrayObject();
        $inner = $this->connect();
        $connection = new class ($inner, $commands) implements RedisConnection {
            /** @param \ArrayObject<int, string> $commands */
            public function __construct(private readonly RedisConnection $inner, private readonly \ArrayObject $commands)
            {
            }

            public function raw(string ...$args): mixed
            {
                $this->commands[] = $args[0];
                return $this->inner->raw(...$args);
            }
        };
        return [$connection, $commands];
    }

    public function test_a_script_is_sent_by_its_hash_once_redis_holds_it(): void
    {
        [$connection, $commands] = $this->recording();
        $store = new RedisLocalStore($connection);
        $this->redis->raw('SCRIPT', 'FLUSH');

        $store->read('203.0.113.7');
        $this->assertSame(['EVALSHA', 'EVAL'], $commands->getArrayCopy());

        $commands->exchangeArray([]);
        $store->read('203.0.113.7');
        $this->assertSame(['EVALSHA'], $commands->getArrayCopy());
    }

    public function test_an_error_other_than_noscript_is_not_retried(): void
    {
        [$connection, $commands] = $this->recording();
        $store = new RedisLocalStore($connection);
        $store->read('203.0.113.7'); // Redis now holds the script: the next error is the script's own
        $commands->exchangeArray([]);
        $this->redis->raw('SET', 'scanner-trap:netlens', 'a string, not a set');

        try {
            $store->read('203.0.113.7');
            $this->fail('No exception');
        } catch (StoreException) {
            $this->assertSame(['EVALSHA'], $commands->getArrayCopy());
        }
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

    public function test_concurrent_imports_of_one_source_leave_the_active_generation_intact(): void
    {
        for ($trial = 0; $trial < 5; $trial++) {
            $this->redis->raw('FLUSHDB');
            $startAt = sprintf('%.6F', microtime(true) + 0.5);
            $processes = [];
            for ($child = 0; $child < 2; $child++) {
                $processes[] = proc_open([PHP_BINARY, __DIR__ . '/../../fixtures/import-list.php', '3000', $startAt], [1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']], $pipes);
            }
            foreach ($processes as $process) {
                $this->assertIsResource($process);
                proc_close($process);
            }

            $status = $this->redis->raw('HGET', 'scanner-trap:lists', 'big');
            $this->assertIsString($status);
            $info = json_decode($status, true);
            $this->assertIsArray($info);
            $this->assertIsInt($info['gen']);
            $this->assertSame($info['count'], $this->redis->raw('HLEN', 'scanner-trap:lh:big:' . $info['gen']), "trial {$trial}");
            $this->assertSame('big', $this->createStore()->read('45.5.7.1')->listed, "trial {$trial}");
        }
    }

    public function test_a_garbage_list_status_does_not_fail_the_read(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('45.155.205.9', time(), 0, source: 'manual'), false);
        $store->replaceLists(['/wp-admin'], []);
        $this->redis->raw('HSET', 'scanner-trap:lists', 'broken', 'not json', 'odd', '[1]');

        $snapshot = $store->read('45.155.205.9');
        $this->assertTrue($snapshot->blocked);
        $this->assertFalse($snapshot->corrupt);
        $this->assertNull($snapshot->listed);
        $this->assertNotSame([], $snapshot->patterns);
    }

    public function test_prune_has_nothing_to_do_because_ttls_expire_everything(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('203.0.113.7', time(), time() + 600), false);
        $this->assertSame(0, $store->prune(time()));
    }
}
