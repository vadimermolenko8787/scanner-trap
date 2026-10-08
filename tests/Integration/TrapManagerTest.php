<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Central\PdoCentralStore;
use ScannerTrap\Exception\RefusedException;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Guard;
use ScannerTrap\RequestContext;
use ScannerTrap\Store\ApcuLocalStore;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\TrapManager;
use ScannerTrap\Tests\Support\Env;

final class TrapManagerTest extends TestCase
{
    private const CONFIG_PATTERNS = ['/.env*', '*.sql'];
    private const CONFIG_ALLOW = ['10.0.0.0/8'];

    private string $dir;
    private FileLocalStore $local;
    private ?PdoCentralStore $central = null;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/scanner-trap-manager-' . bin2hex(random_bytes(6));
        $this->local = new FileLocalStore($this->dir);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    private function manager(bool $central): TrapManager
    {
        if ($central && $this->central === null) {
            $this->central = new PdoCentralStore(Env::pdo('sqlite'));
        }
        return new TrapManager($this->local, $central ? $this->central : null, self::CONFIG_PATTERNS, self::CONFIG_ALLOW, ['/admin'], 'web1', 600);
    }

    private function installed(bool $central): TrapManager
    {
        $manager = $this->manager($central);
        $manager->install('ops');
        return $manager;
    }

    /** @return array<string, array{bool}> */
    public static function modes(): array
    {
        return ['local store only' => [false], 'central store' => [true]];
    }

    #[DataProvider('modes')]
    public function test_install_puts_the_config_lists_where_guard_reads_them(bool $central): void
    {
        $this->installed($central);

        $this->assertSame(self::CONFIG_PATTERNS, $this->local->patterns());
        $this->assertSame(self::CONFIG_ALLOW, array_map(static fn (AllowEntry $e): string => $e->entry, $this->local->allow() ?? []));
        if ($central) {
            $this->assertNotNull($this->local->marker());
            $this->assertSame(self::CONFIG_PATTERNS, $this->central?->patterns());
        }
    }

    public function test_before_install_the_local_mode_shows_and_extends_the_config_lists(): void
    {
        $manager = $this->manager(false);

        $this->assertSame(self::CONFIG_PATTERNS, $manager->patterns());
        $manager->addPattern('/.git', 'ops');
        $this->assertSame(['/.env*', '*.sql', '/.git'], $this->local->patterns());
    }

    #[DataProvider('modes')]
    public function test_install_refuses_invalid_config_patterns_and_writes_nothing(bool $central): void
    {
        $manager = new TrapManager($this->local, $central ? ($this->central = new PdoCentralStore(Env::pdo('sqlite'))) : null, ['/', '/.env*', '*.js'], [], ['/admin']);

        try {
            $manager->install('ops');
            $this->fail('install must refuse');
        } catch (RefusedException $e) {
            $this->assertStringContainsString('"/"', $e->getMessage());
            $this->assertStringContainsString('"*.js"', $e->getMessage());
            $this->assertStringNotContainsString('.env', $e->getMessage());
        }
        $this->assertNull($this->local->patterns());
        if ($central) {
            $this->expectException(StoreException::class); // not even the tables exist
            $this->central?->patterns();
        }
    }

    public function test_before_install_invalid_config_patterns_are_left_out_of_the_local_lists(): void
    {
        $manager = new TrapManager($this->local, null, ['/', '/.env*', '*.js'], [], ['/admin']);

        $this->assertSame(['/.env*'], $manager->patterns());
        $manager->addPattern('/.git', 'ops');
        $this->assertSame(['/.env*', '/.git'], $this->local->patterns());
    }

    #[DataProvider('modes')]
    public function test_a_manual_block_applies_at_once_and_keeps_its_reason(bool $central): void
    {
        $manager = $this->installed($central);

        $block = $manager->block('2001:DB8::7', 'abuse report 42', null, 'ops');

        $this->assertSame('2001:db8::7', $block->ip);
        $this->assertSame(Block::SOURCE_MANUAL, $block->source);
        $this->assertTrue($this->local->read('2001:db8::7')->blocked);
        $listed = $manager->blocks(true, '2001:db8::7');
        $this->assertCount(1, $listed);
        $this->assertSame('abuse report 42', $listed[0]->pattern);
        $this->assertEqualsWithDelta(time() + 600, $listed[0]->expiresAt, 2);
    }

    #[DataProvider('modes')]
    public function test_a_manual_block_with_ttl_zero_is_forever(bool $central): void
    {
        $this->assertSame(0, $this->installed($central)->block('203.0.113.7', '', 0, 'ops')->expiresAt);
    }

    /** @return array<string, array{bool, string, string}> */
    public static function refusedBlocks(): array
    {
        $cases = [];
        foreach (self::modes() as $mode => [$central]) {
            $cases["{$mode}: not an IP"] = [$central, 'office', 'not an IP address'];
            $cases["{$mode}: whitelisted"] = [$central, '10.1.2.3', 'whitelist'];
        }
        return $cases;
    }

    #[DataProvider('refusedBlocks')]
    public function test_a_manual_block_is_refused_for_garbage_and_for_a_whitelisted_ip(bool $central, string $ip, string $message): void
    {
        $manager = $this->installed($central);

        $this->expectException(RefusedException::class);
        $this->expectExceptionMessage($message);
        $manager->block($ip, '', null, 'ops');
    }

    #[DataProvider('modes')]
    public function test_blocking_twice_is_refused(bool $central): void
    {
        $manager = $this->installed($central);
        $manager->block('203.0.113.7', '', null, 'ops');

        $this->expectException(RefusedException::class);
        $this->expectExceptionMessage('already blocked');
        $manager->block('203.0.113.7', '', null, 'ops');
    }

    #[DataProvider('modes')]
    public function test_unblock_lifts_and_removes_locally(bool $central): void
    {
        $manager = $this->installed($central);
        $manager->block('203.0.113.7', '', null, 'ops');

        $this->assertSame(1, $manager->unblock('203.0.113.7', 'ops'));
        $this->assertFalse($this->local->read('203.0.113.7')->blocked);
        $this->assertSame([], $manager->blocks());
        $this->assertSame(0, $manager->unblock('203.0.113.7', 'ops'));
        if ($central) {
            $this->assertSame('ops', $manager->blocks(false, '203.0.113.7')[0]->liftedBy);
        }
    }

    public function test_unblock_ships_a_waiting_trap_event_first_so_it_cannot_come_back(): void
    {
        $manager = $this->installed(true);
        (new Guard($this->local, true, 600))->decide(new RequestContext('203.0.113.7', 'GET', '/.env'));

        $this->assertSame(1, $manager->unblock('203.0.113.7', 'ops'));
        $manager->sync();
        $this->assertFalse($this->local->read('203.0.113.7')->blocked);
    }

    /** @return array<string, array{bool, string, string}> */
    public static function refusedPatterns(): array
    {
        $cases = [];
        foreach (self::modes() as $mode => [$central]) {
            $cases["{$mode}: site extension"] = [$central, '*.js', 'extension'];
            $cases["{$mode}: own path"] = [$central, '/admin/x', 'ownPaths'];
            $cases["{$mode}: duplicate"] = [$central, '/.ENV*', 'already on the list'];
        }
        return $cases;
    }

    #[DataProvider('refusedPatterns')]
    public function test_patterns_are_validated_before_they_are_stored(bool $central, string $pattern, string $message): void
    {
        $manager = $this->installed($central);

        $this->expectException(RefusedException::class);
        $this->expectExceptionMessage($message);
        $manager->addPattern($pattern, 'ops');
    }

    #[DataProvider('modes')]
    public function test_a_pattern_added_or_removed_applies_at_once(bool $central): void
    {
        $manager = $this->installed($central);

        $this->assertSame('/.git', $manager->addPattern(' /.GIT/ ', 'ops'));
        $this->assertTrue((new Guard($this->local, true))->decide(new RequestContext('203.0.113.7', 'GET', '/.git/config'))->refuse);

        $manager->removePattern('/.git');
        $this->assertSame(self::CONFIG_PATTERNS, $manager->patterns());
        $this->expectException(RefusedException::class);
        $manager->removePattern('/.git');
    }

    #[DataProvider('modes')]
    public function test_whitelist_entries_are_validated_and_apply_at_once(bool $central): void
    {
        $manager = $this->installed($central);
        $manager->block('203.0.113.7', '', null, 'ops');

        $entry = $manager->addAllow('203.0.113.*', 'partner', 3600, 'ops');

        $this->assertEqualsWithDelta(time() + 3600, $entry->expiresAt, 2);
        $this->assertFalse((new Guard($this->local, true))->decide(new RequestContext('203.0.113.7', 'GET', '/'))->refuse);
        $this->assertContains('203.0.113.*', array_map(static fn (AllowEntry $e): string => $e->entry, $manager->allowEntries()));

        $manager->removeAllow('203.0.113.*');
        $this->assertTrue((new Guard($this->local, true))->decide(new RequestContext('203.0.113.7', 'GET', '/'))->refuse);

        $this->expectException(RefusedException::class);
        $manager->addAllow('office', '', null, 'ops');
    }

    public function test_sync_needs_a_central_store(): void
    {
        $this->expectException(RefusedException::class);
        $this->manager(false)->sync();
    }

    public function test_an_apcu_store_without_a_central_store_cannot_be_managed_from_the_cli(): void
    {
        $manager = new TrapManager(new ApcuLocalStore(), null, self::CONFIG_PATTERNS, [], [], 'web1', 600);

        $this->expectException(RefusedException::class);
        $this->expectExceptionMessage('APCu');
        $manager->block('203.0.113.7', '', null, 'ops');
    }
}
