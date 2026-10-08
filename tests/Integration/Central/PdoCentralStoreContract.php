<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Central;

use PHPUnit\Framework\TestCase;
use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Central\PdoCentralStore;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Tests\Support\Env;

abstract class PdoCentralStoreContract extends TestCase
{
    protected \PDO $pdo;

    abstract protected function driver(): string;

    protected function setUp(): void
    {
        $this->pdo = Env::pdo($this->driver());
    }

    private function installed(): PdoCentralStore
    {
        $store = new PdoCentralStore($this->pdo);
        $store->install(['/.env*', '~union select'], [new AllowEntry('10.0.0.0/8', 'office')], 'test');
        return $store;
    }

    public function test_an_uninstalled_store_is_a_store_exception(): void
    {
        $this->expectException(StoreException::class);
        (new PdoCentralStore($this->pdo))->owner();
    }

    public function test_install_is_idempotent_and_seeds_patterns_only_into_an_empty_table(): void
    {
        $store = $this->installed();
        $owner = $store->owner();
        $store->install(['/.git'], [new AllowEntry('192.168.0.*')], 'test');

        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $owner);
        $this->assertSame($owner, $store->owner());
        $this->assertSame(['/.env*', '~union select'], $store->patterns());
        $this->assertSame(['10.0.0.0/8', '192.168.0.*'], array_map(static fn (AllowEntry $e): string => $e->entry, $store->allowEntries()));
    }

    public function test_every_list_change_bumps_the_version_and_blocks_do_not(): void
    {
        $store = $this->installed();
        $version = $store->version();

        $this->assertTrue($store->addPattern('/.git', 'ops'));
        $this->assertSame($version + 1, $store->version());
        $this->assertFalse($store->addPattern('/.git', 'ops'));
        $this->assertSame($version + 1, $store->version());
        $this->assertTrue($store->removePattern('/.git'));
        $store->saveAllow(new AllowEntry('203.0.113.7', 'partner'));
        $this->assertTrue($store->removeAllow('203.0.113.7'));
        $this->assertFalse($store->removeAllow('203.0.113.7'));
        $this->assertSame($version + 4, $store->version());

        $store->insertBlocks([new Block('203.0.113.9', time(), 0)]);
        $this->assertSame($version + 4, $store->version());
    }

    public function test_two_store_instances_bump_the_same_version_counter(): void
    {
        $first = $this->installed();
        $second = new PdoCentralStore($this->pdo);
        $version = $first->version();

        $first->addPattern('/.git', 'ops');
        $second->addPattern('/.svn', 'ops');

        $this->assertSame($version + 2, $first->version());
        $this->assertSame($version + 2, $second->version());
    }

    public function test_an_event_merges_into_the_active_block_and_keeps_the_later_expiry(): void
    {
        $store = $this->installed();
        $now = time();
        $store->insertBlocks([new Block('203.0.113.7', $now, $now + 600, 'web1', 'GET', '/.env', '/.env*')]);
        $store->insertBlocks([new Block('203.0.113.7', $now, $now + 60, 'web2'), new Block('203.0.113.7', $now, $now + 900, 'web2')]);

        $active = $store->blocks();
        $this->assertCount(1, $active);
        $this->assertSame($now + 900, $active[0]->expiresAt);
        $this->assertSame('web1', $active[0]->server);
    }

    public function test_a_forever_block_stays_forever_when_a_timed_event_follows(): void
    {
        $store = $this->installed();
        $store->insertBlocks([new Block('203.0.113.7', time(), 0)]);
        $store->insertBlocks([new Block('203.0.113.7', time(), time() + 60)]);

        $this->assertSame(0, $store->blocks()[0]->expiresAt);
    }

    public function test_a_lifted_block_is_history_and_a_new_event_starts_a_new_one(): void
    {
        $store = $this->installed();
        $store->insertBlocks([new Block('2001:db8::7', time(), 0)]);

        $this->assertSame(1, $store->lift('2001:DB8:0:0::7', 'ops'));
        $this->assertSame(0, $store->lift('2001:db8::7', 'ops'));
        $this->assertSame([], $store->blocks());
        $history = $store->blocks(false, '2001:db8::7');
        $this->assertCount(1, $history);
        $this->assertSame('ops', $history[0]->liftedBy);

        $store->insertBlocks([new Block('2001:db8::7', time(), 0)]);
        $this->assertCount(1, $store->blocks());
        $this->assertCount(2, $store->blocks(false));
    }

    public function test_expired_blocks_and_whitelist_entries_are_not_active(): void
    {
        $store = $this->installed();
        $store->insertBlocks([new Block('203.0.113.7', time() - 100, time() - 1)]);
        $store->saveAllow(new AllowEntry('203.0.113.8', '', time() - 1));

        $this->assertSame([], $store->blocks());
        $this->assertSame(['10.0.0.0/8'], array_map(static fn (AllowEntry $e): string => $e->entry, $store->allowEntries()));
    }

    public function test_saving_an_existing_whitelist_entry_updates_it(): void
    {
        $store = $this->installed();
        $store->saveAllow(new AllowEntry('10.0.0.0/8', 'whole office', time() + 3600, 'ops'));

        $entries = $store->allowEntries();
        $this->assertCount(1, $entries);
        $this->assertSame('whole office', $entries[0]->comment);
        $this->assertSame('ops', $entries[0]->createdBy);
    }

    public function test_rows_that_bypassed_validation_or_are_disabled_are_left_out(): void
    {
        $store = $this->installed();
        $this->pdo->exec("INSERT INTO scanner_trap_pattern (pattern, type, enabled, created_at, created_by) VALUES ('*.js', 'suffix', 1, 0, 'sql')");
        $this->pdo->exec("INSERT INTO scanner_trap_pattern (pattern, type, enabled, created_at, created_by) VALUES ('/.git', 'prefix', 0, 0, 'sql')");
        $this->pdo->exec("INSERT INTO scanner_trap_allow (entry, comment, created_at, created_by) VALUES ('office', '', 0, 'sql')");

        $this->assertSame(['/.env*', '~union select'], $store->patterns());
        $this->assertSame(['10.0.0.0/8'], array_map(static fn (AllowEntry $e): string => $e->entry, $store->allowEntries()));
    }

    public function test_broken_utf8_and_long_text_are_stored(): void
    {
        $store = $this->installed();
        $store->insertBlocks([new Block('203.0.113.7', time(), 0, 'web1', 'GET', '/' . str_repeat('a', 3000) . "\xff", '/.env*', "agent\xfe")]);

        $this->assertLessThanOrEqual(1024, mb_strlen($store->blocks()[0]->path));
    }

    public function test_a_table_prefix_with_a_trailing_newline_is_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoCentralStore($this->pdo, "x\n");
    }

    public function test_the_table_prefix_is_honoured(): void
    {
        foreach (['block', 'pattern', 'allow', 'meta'] as $table) {
            $this->pdo->exec('DROP TABLE IF EXISTS other_' . $table);
        }
        $store = new PdoCentralStore($this->pdo, 'other_');
        $store->install(['/.git'], [], 'test');

        $this->assertSame(['/.git'], $store->patterns());
        $count = $this->pdo->query('SELECT COUNT(*) FROM other_pattern');
        $this->assertInstanceOf(\PDOStatement::class, $count);
        $this->assertSame(1, (int) $count->fetchColumn());
        $count->closeCursor(); // an open cursor would lock the table against the DROP below
        foreach (['block', 'pattern', 'allow', 'meta'] as $table) {
            $this->pdo->exec('DROP TABLE IF EXISTS other_' . $table);
        }
    }
}
