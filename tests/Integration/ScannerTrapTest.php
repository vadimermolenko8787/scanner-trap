<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use ScannerTrap\Guard;
use ScannerTrap\RequestContext;
use ScannerTrap\Snapshot;
use ScannerTrap\Store\LocalStore;
use ScannerTrap\Central\PdoCentralStore;
use ScannerTrap\ScannerTrap;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\Tests\Support\Env;
use ScannerTrap\Tests\Support\MemoryLogger;

final class ScannerTrapTest extends TestCase
{
    private const SCANNER = ['REMOTE_ADDR' => '203.0.113.7', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/.env'];

    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/scanner-trap-facade-' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function config(array $overrides = []): array
    {
        return array_replace(['local' => ['type' => 'file', 'dir' => $this->dir . '/store']], $overrides);
    }

    public function test_one_line_with_a_directory_works_with_safe_defaults_in_watch_mode(): void
    {
        $this->assertFalse(ScannerTrap::check($this->config(), self::SCANNER));
        $this->assertTrue((new FileLocalStore($this->dir . '/store'))->read('203.0.113.7')->blocked);
    }

    public function test_blocking_refuses_the_scanner_and_its_later_requests(): void
    {
        $config = $this->config(['blocking' => true]);

        $this->assertTrue(ScannerTrap::check($config, self::SCANNER));
        $this->assertTrue(ScannerTrap::check($config, ['REQUEST_URI' => '/'] + self::SCANNER));
        $this->assertFalse(ScannerTrap::check($config, ['REMOTE_ADDR' => '203.0.113.8', 'REQUEST_URI' => '/'] + self::SCANNER));
    }

    public function test_a_config_file_path_is_loaded(): void
    {
        mkdir($this->dir, 0775, true);
        file_put_contents($this->dir . '/scanner-trap.php', '<?php return ' . var_export($this->config(['blocking' => true]), true) . ';');

        $this->assertTrue(ScannerTrap::check($this->dir . '/scanner-trap.php', self::SCANNER));
    }

    public function test_loopback_never_builds_a_store(): void
    {
        $this->assertFalse(ScannerTrap::check($this->config(['blocking' => true]), ['REMOTE_ADDR' => '127.0.0.1'] + self::SCANNER));
        $this->assertDirectoryDoesNotExist($this->dir . '/store');
    }

    public function test_trusted_proxies_come_from_the_config(): void
    {
        $config = $this->config(['blocking' => true, 'trustedProxies' => ['10.0.0.0/8']]);

        $this->assertTrue(ScannerTrap::check($config, ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1'] + self::SCANNER));
        $this->assertTrue((new FileLocalStore($this->dir . '/store'))->read('198.51.100.1')->blocked);
        $this->assertFalse((new FileLocalStore($this->dir . '/store'))->read('10.0.0.2')->blocked);
    }

    public function test_a_broken_config_lets_the_request_through_and_is_logged(): void
    {
        $logger = new MemoryLogger();

        $this->assertFalse(ScannerTrap::check(['local' => ['type' => 'nope'], 'logger' => $logger], self::SCANNER));
        $this->assertSame('error', $logger->records[0][0]);
        $this->assertFalse(ScannerTrap::check('/no/such/config.php', self::SCANNER));
    }

    public function test_an_unreachable_redis_lets_the_request_through_and_is_logged(): void
    {
        $logger = new MemoryLogger();
        $config = ['local' => ['type' => 'redis', 'host' => '127.0.0.1', 'port' => 1], 'blocking' => true, 'logger' => $logger];

        $started = microtime(true);
        $this->assertFalse(ScannerTrap::check($config, self::SCANNER));
        $this->assertLessThan(2.0, microtime(true) - $started);
        $this->assertNotSame([], $logger->records);
    }

    public function test_an_unwritable_directory_lets_the_request_through_and_is_logged(): void
    {
        $logger = new MemoryLogger();
        $config = ['local' => ['type' => 'file', 'dir' => '/proc/definitely/not/writable'], 'blocking' => true, 'logger' => $logger];

        $this->assertFalse(ScannerTrap::check($config, self::SCANNER));
        $this->assertNotSame([], $logger->records);
    }

    public function test_an_existing_phpredis_or_predis_client_is_used_as_is(): void
    {
        foreach ([Env::phpRedis(), Env::predis()] as $connection) {
            $connection->raw('FLUSHDB');
        }
        if (extension_loaded('redis')) {
            $redis = new \Redis();
            $redis->connect(Env::get('SCANNER_TRAP_REDIS_HOST'), (int) Env::get('SCANNER_TRAP_REDIS_PORT'));
            $redis->select(Env::redisDatabase());
            $redis->setOption(\Redis::OPT_PREFIX, 'project:');
            $this->assertTrue(ScannerTrap::check(['local' => ['type' => 'redis', 'client' => $redis], 'blocking' => true], self::SCANNER));
            $this->assertSame(1, Env::phpRedis()->raw('EXISTS', 'scanner-trap:block:203.0.113.7'));
        }
        $predis = new \Predis\Client(['host' => Env::get('SCANNER_TRAP_REDIS_HOST'), 'port' => (int) Env::get('SCANNER_TRAP_REDIS_PORT'), 'database' => Env::redisDatabase()]);
        $this->assertTrue(ScannerTrap::check(['local' => ['type' => 'redis', 'client' => $predis, 'prefix' => 'p:'], 'blocking' => true], self::SCANNER));
        $this->assertSame(1, Env::phpRedis()->raw('EXISTS', 'p:block:203.0.113.7'));
        Env::phpRedis()->raw('FLUSHDB');
    }

    public function test_with_a_central_store_an_empty_local_store_blocks_nobody(): void
    {
        $pdo = Env::pdo('sqlite');
        $config = $this->config(['blocking' => true, 'central' => Env::pdoConfig('sqlite', $pdo)]);

        $this->assertFalse(ScannerTrap::check($config, self::SCANNER));

        ScannerTrap::fromConfig($config)->manager()->install('test');
        $this->assertTrue(ScannerTrap::check($config, ['REMOTE_ADDR' => '203.0.113.8'] + self::SCANNER));
        $this->assertNotSame([], (new PdoCentralStore($pdo))->patterns());
    }

    public function test_events_are_kept_only_with_a_central_store(): void
    {
        $this->assertTrue(ScannerTrap::check($this->config(['blocking' => true]), self::SCANNER));
        $this->assertSame([], (new FileLocalStore($this->dir . '/store'))->events(10));
        $this->assertFileDoesNotExist($this->dir . '/store/events.log');

        $config = $this->config(['blocking' => true, 'central' => Env::pdoConfig('sqlite', Env::pdo('sqlite'))]);
        ScannerTrap::fromConfig($config)->manager()->install('test');
        $this->assertTrue(ScannerTrap::check($config, ['REMOTE_ADDR' => '203.0.113.8'] + self::SCANNER));
        $this->assertCount(1, (new FileLocalStore($this->dir . '/store'))->events(10));
    }

    public function test_apcu_with_a_central_store_is_a_config_error(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ScannerTrap::fromConfig(['local' => ['type' => 'apcu'], 'central' => ['dsn' => 'sqlite::memory:']]);
    }

    public function test_guard_prints_nothing_and_passes_on_failure_and_answers_403_when_refused(): void
    {
        $run = function (array $config, string $ip, string $uri): string {
            $process = proc_open([PHP_BINARY, __DIR__ . '/../fixtures/guard-entry.php', (string) json_encode($config), $ip, $uri], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $this->assertIsResource($process);
            $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            proc_close($process);
            return (string) $output;
        };

        $this->assertSame('PASSED', $run(['local' => ['type' => 'file', 'dir' => '/proc/definitely/not/writable'], 'blocking' => true], '203.0.113.7', '/.env'));
        $this->assertSame('PASSED', $run(['local' => ['type' => 'redis', 'port' => 1], 'blocking' => true], '203.0.113.7', '/.env'));
        $this->assertSame('PASSED', $run(['local' => 'garbage'], '203.0.113.7', '/.env'));
        $this->assertSame('PASSED', $run($this->config(['blocking' => true]), '203.0.113.7', '/'));
        $this->assertSame('Forbidden', $run($this->config(['blocking' => true]), '203.0.113.7', '/.env'));
    }

    public function test_a_deprecation_inside_is_swallowed_and_the_request_is_still_decided(): void
    {
        $logger = new MemoryLogger();
        $store = $this->createStub(LocalStore::class);
        $store->method('read')->willReturnCallback(static function (): Snapshot {
            trigger_error('simulated deprecation', E_USER_DEPRECATED);
            return new Snapshot(true, [], []);
        });

        $refuse = ScannerTrap::failSafe(
            static fn (): bool => (new Guard($store, true))->decide(RequestContext::fromGlobals(self::SCANNER))->refuse,
            false,
            $logger,
        );

        $this->assertTrue($refuse);
        $this->assertSame([], $logger->records);
    }

    public function test_a_suppressed_warning_inside_stays_silent_and_does_not_fail_the_request_open(): void
    {
        $logger = new MemoryLogger();
        $store = $this->createStub(LocalStore::class);
        $store->method('read')->willReturnCallback(static function (): Snapshot {
            @trigger_error('suppressed', E_USER_WARNING);
            return new Snapshot(true, [], []);
        });

        $refuse = ScannerTrap::failSafe(
            static fn (): bool => (new Guard($store, true))->decide(RequestContext::fromGlobals(self::SCANNER))->refuse,
            false,
            $logger,
        );

        $this->assertTrue($refuse);
        $this->assertSame([], $logger->records);
    }

    public function test_a_logger_that_throws_does_not_escape_the_fail_safe(): void
    {
        $logger = $this->createStub(LoggerInterface::class);
        $logger->method('error')->willThrowException(new \RuntimeException('logger down'));

        $this->assertSame('fallback', ScannerTrap::failSafe(static function (): never {
            throw new \LogicException('boom');
        }, 'fallback', $logger));
    }
}
