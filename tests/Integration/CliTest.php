<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration;

use PHPUnit\Framework\TestCase;
use ScannerTrap\Tests\Support\Env;

/** bin/scanner-trap in a child process, as an operator runs it. */
final class CliTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/scanner-trap-cli-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0775, true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    /** @param array<string, mixed> $overrides */
    private function writeConfig(array $overrides = [], string $name = 'scanner-trap.php'): string
    {
        $config = array_replace([
            'local' => ['type' => 'file', 'dir' => $this->dir . '/store'],
            'patterns' => ['/.env*', '*.sql'],
            'allow' => ['10.0.0.0/8'],
            'ownPaths' => ['/admin'],
        ], $overrides);
        file_put_contents($this->dir . '/' . $name, '<?php return ' . var_export($config, true) . ';');
        return $this->dir . '/' . $name;
    }

    /** @return array{int, string, string} exit code, stdout, stderr */
    private function cli(string ...$args): array
    {
        $process = proc_open([PHP_BINARY, __DIR__ . '/../../bin/scanner-trap', ...array_values($args)], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->dir);
        $this->assertIsResource($process);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        return [proc_close($process), $out, $err];
    }

    public function test_the_default_config_is_read_from_the_working_directory(): void
    {
        $this->writeConfig();

        [$code, $out] = $this->cli('pattern:list');

        $this->assertSame(0, $code);
        $this->assertSame("/.env*\n*.sql\n", $out);
    }

    public function test_install_then_manage_patterns(): void
    {
        $config = '--config=' . $this->writeConfig([], 'other.php');

        $this->assertSame(0, $this->cli($config, 'install')[0]);
        $this->assertSame(0, $this->cli($config, 'pattern:add', '~union select')[0]);
        $this->assertSame("/.env*\n*.sql\n~union select\n", $this->cli($config, 'pattern:list')[1]);
        $this->assertSame(0, $this->cli($config, 'pattern:remove', '*.sql')[0]);
        $this->assertSame("/.env*\n~union select\n", $this->cli($config, 'pattern:list')[1]);
    }

    public function test_install_refuses_an_invalid_config_pattern(): void
    {
        $this->writeConfig(['patterns' => ['/', '/.env*']]);

        [$code, , $err] = $this->cli('install');

        $this->assertSame(2, $code);
        $this->assertStringContainsString('"/"', $err);
    }

    public function test_refusals_exit_with_2_and_say_why(): void
    {
        $this->writeConfig();

        [$code, , $err] = $this->cli('pattern:add', '*.js');
        $this->assertSame(2, $code);
        $this->assertStringContainsString('extension', $err);

        $this->assertSame(2, $this->cli('pattern:add', '/admin/x')[0]);
        $this->assertSame(2, $this->cli('block', '10.1.2.3')[0]);
        $this->assertSame(2, $this->cli('allow:add', 'office')[0]);
        $this->assertSame(2, $this->cli('sync')[0]);
    }

    public function test_usage_errors_exit_with_1(): void
    {
        $this->writeConfig();

        $this->assertSame(1, $this->cli()[0]);
        $this->assertSame(1, $this->cli('nonsense')[0]);
        $this->assertSame(1, $this->cli('block')[0]);
        $this->assertSame(1, $this->cli('block', '203.0.113.7', '--ttl=soon')[0]);
        $this->assertSame(1, $this->cli('list', '--colour')[0]);
        $this->assertSame(1, $this->cli('--config=' . $this->dir . '/missing.php', 'pattern:list')[0]);
        $this->assertSame(0, $this->cli('help')[0]);
    }

    public function test_block_list_unblock(): void
    {
        $this->writeConfig();

        [$code, $out] = $this->cli('block', '203.0.113.7', '--reason=abuse report', '--ttl=0');
        $this->assertSame(0, $code, $out);
        [, $list] = $this->cli('list', '--active');
        $this->assertStringContainsString('203.0.113.7', $list);
        $this->assertStringContainsString('forever', $list);
        $this->assertStringContainsString('abuse report', $list);
        $this->assertSame(0, $this->cli('unblock', '203.0.113.7')[0]);
        $this->assertStringNotContainsString('203.0.113.7', $this->cli('list', '--active')[1]);
    }

    public function test_whitelist_commands(): void
    {
        $this->writeConfig();

        $this->assertSame(0, $this->cli('allow:add', '192.168.0.*', '--comment=office wifi', '--ttl=3600')[0]);
        [, $list] = $this->cli('allow:list');
        $this->assertStringContainsString('192.168.0.*', $list);
        $this->assertStringContainsString('office wifi', $list);
        $this->assertSame(0, $this->cli('allow:remove', '192.168.0.*')[0]);
        $this->assertStringNotContainsString('192.168.0.*', $this->cli('allow:list')[1]);
    }

    public function test_install_and_sync_with_a_central_database(): void
    {
        $pdo = Env::pdo('sqlite');
        $this->writeConfig(['central' => Env::pdoConfig('sqlite', $pdo)]);

        $this->assertSame(0, $this->cli('install')[0]);
        $this->assertSame(0, $this->cli('block', '203.0.113.7')[0]);
        [$code, $out] = $this->cli('sync', '--watch=1');
        $this->assertSame(0, $code, $out);
        $count = $pdo->query("SELECT COUNT(*) FROM scanner_trap_block WHERE ip = '203.0.113.7'");
        $this->assertNotFalse($count);
        $this->assertSame(1, (int) $count->fetchColumn());
    }

    public function test_the_acting_user_is_the_process_user_not_the_script_owner(): void
    {
        $pdo = Env::pdo('sqlite');
        $this->writeConfig(['central' => Env::pdoConfig('sqlite', $pdo)]);
        $user = function_exists('posix_geteuid') && function_exists('posix_getpwuid')
            ? (posix_getpwuid(posix_geteuid())['name'] ?? '')
            : (string) getenv('USER');
        $this->assertNotSame('', $user);

        $this->assertSame(0, $this->cli('install')[0]);
        $this->assertSame(0, $this->cli('block', '203.0.113.7')[0]);
        $this->assertSame(0, $this->cli('unblock', '203.0.113.7')[0]);

        $statement = $pdo->query("SELECT lifted_by FROM scanner_trap_block WHERE ip = '203.0.113.7'");
        $this->assertNotFalse($statement);
        $this->assertStringStartsWith($user . '@', (string) $statement->fetchColumn());
    }

    public function test_import_and_lists(): void
    {
        $fixtures = __DIR__ . '/../fixtures/lists';
        $this->writeConfig(['lists' => [['name' => 'own', 'file' => $fixtures . '/own.txt'], ['name' => 'firehol', 'file' => $fixtures . '/firehol-sample.netset']]]);

        [$code, $out] = $this->cli('import');
        $this->assertSame(0, $code, $out);
        $this->assertStringContainsString("own\t1 networks", $out);
        $this->assertStringContainsString('2 reserved', $out);

        [, $lists] = $this->cli('lists');
        $this->assertMatchesRegularExpression("/^firehol\t3\t\\d{4}-\\d{2}-\\d{2} [\\d:]{8}\tconfigured$/m", $lists);
        $this->assertSame(0, $this->cli('import', '--source=own')[0]);
        $this->assertSame(2, $this->cli('import', '--source=nope')[0]);
    }

    public function test_a_failing_source_exits_with_3_after_importing_the_others(): void
    {
        $fixtures = __DIR__ . '/../fixtures/lists';
        $this->writeConfig(['lists' => [['name' => 'gone', 'file' => $fixtures . '/missing.txt'], ['name' => 'own', 'file' => $fixtures . '/own.txt']]]);

        [$code, $out, $err] = $this->cli('import');

        $this->assertSame(3, $code);
        $this->assertStringContainsString('gone', $out . $err);
        $this->assertMatchesRegularExpression("/^own\t1\t/m", $this->cli('lists')[1]);
    }

    public function test_networks_are_blocked_and_unblocked_and_browser_signatures_refused(): void
    {
        $this->writeConfig();

        $this->assertSame(0, $this->cli('block', '45.155.205.0/24', '--reason=rotation')[0]);
        $this->assertStringContainsString('45.155.205.0/24', $this->cli('list', '--ip=45.155.205.9')[1]);
        $this->assertSame(0, $this->cli('unblock', '45.155.205.0/24')[0]);
        $this->assertSame(2, $this->cli('block', '10.0.0.0/8')[0]);
        $this->assertSame(0, $this->cli('pattern:add', '@gobuster')[0]);
        $this->assertSame(2, $this->cli('pattern:add', '@mozilla')[0]);
    }

    public function test_an_unreachable_store_exits_with_3(): void
    {
        $this->writeConfig(['local' => ['type' => 'redis', 'host' => '127.0.0.1', 'port' => 1]]);

        [$code, , $err] = $this->cli('install');

        $this->assertSame(3, $code);
        $this->assertStringContainsString('Redis', $err);
    }
}
