<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration;

use PHPUnit\Framework\TestCase;
use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Central\CentralStore;
use ScannerTrap\Central\PdoCentralStore;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Guard;
use ScannerTrap\RequestContext;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\Store\LocalStore;
use ScannerTrap\SubnetPolicy;
use ScannerTrap\Sync;
use ScannerTrap\Tests\Support\Env;

/** Two servers (two file stores) and one central SQLite database in one test. */
final class SyncTest extends TestCase
{
    private const SCANNER = '203.0.113.7';

    private string $dirA;
    private string $dirB;
    private FileLocalStore $a;
    private FileLocalStore $b;
    private PdoCentralStore $central;

    protected function setUp(): void
    {
        $this->dirA = sys_get_temp_dir() . '/scanner-trap-a-' . bin2hex(random_bytes(6));
        $this->dirB = sys_get_temp_dir() . '/scanner-trap-b-' . bin2hex(random_bytes(6));
        $this->a = new FileLocalStore($this->dirA);
        $this->b = new FileLocalStore($this->dirB);
        $this->central = new PdoCentralStore(Env::pdo('sqlite'));
        $this->central->install(['/.env*', '~union select'], [], 'test');
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dirA) . ' ' . escapeshellarg($this->dirB));
    }

    private function trap(FileLocalStore $store, int $ttl = 600, string $ip = self::SCANNER): void
    {
        (new Guard($store, true, $ttl, 'web', [], ['/.env*']))->decide(new RequestContext($ip, 'GET', '/.env'));
    }

    public function test_push_ships_every_event_in_batches_and_removes_it_locally(): void
    {
        for ($i = 1; $i <= 450; $i++) {
            $this->a->addBlock(new Block('198.51.' . intdiv($i, 250) . '.' . ($i % 250), time(), 0), true);
        }

        $this->assertSame(450, (new Sync($this->a, $this->central))->push());
        $this->assertSame([], $this->a->events(10));
        $this->assertCount(450, $this->central->blocks(true, null, 1000));
    }

    public function test_push_throws_when_acking_makes_no_progress(): void
    {
        $block = new Block('198.51.100.1', time(), 0);
        $local = $this->createMock(LocalStore::class);
        $local->method('marker')->willReturn(null);
        $local->method('events')->willReturn(['same-id' => $block]);
        $local->expects($this->once())->method('ackEvents');

        $this->expectException(StoreException::class);
        (new Sync($local, $this->central))->push();
    }

    public function test_a_failed_insert_leaves_the_events_for_the_next_run(): void
    {
        $this->trap($this->a);
        $central = $this->createStub(CentralStore::class);
        $central->method('insertBlocks')->willThrowException(new StoreException('down'));

        try {
            (new Sync($this->a, $central))->push();
            $this->fail('push() must rethrow');
        } catch (StoreException) {
        }
        $this->assertCount(1, $this->a->events(10));
    }

    public function test_a_block_made_on_one_server_reaches_the_other_with_its_remaining_ttl(): void
    {
        $this->trap($this->a, 600);

        $this->assertTrue((new Sync($this->a, $this->central))->run());
        $this->assertTrue((new Sync($this->b, $this->central))->run());

        $this->assertTrue($this->b->read(self::SCANNER)->blocked);
        $this->assertEqualsWithDelta(time() + 600, $this->b->blocks()[0]->expiresAt, 2);
        $this->assertSame(['/.env*', '~union select'], $this->b->patterns());
        $this->assertTrue((new Guard($this->b, true))->decide(new RequestContext(self::SCANNER, 'GET', '/'))->refuse);
    }

    public function test_lifting_a_block_centrally_removes_it_on_every_server(): void
    {
        $this->trap($this->a);
        (new Sync($this->a, $this->central))->run();
        (new Sync($this->b, $this->central))->run();

        $this->central->lift(self::SCANNER, 'ops');
        (new Sync($this->a, $this->central))->pull();
        (new Sync($this->b, $this->central))->pull();

        $this->assertFalse($this->a->read(self::SCANNER)->blocked);
        $this->assertFalse($this->b->read(self::SCANNER)->blocked);
    }

    public function test_a_block_whose_event_is_still_waiting_is_left_alone(): void
    {
        $this->trap($this->a);

        (new Sync($this->a, $this->central))->pull();

        $this->assertTrue($this->a->read(self::SCANNER)->blocked);
    }

    public function test_the_owner_marker_refuses_a_foreign_central_store(): void
    {
        (new Sync($this->a, $this->central))->pull();
        $foreign = new PdoCentralStore(Env::pdo('sqlite'));
        $foreign->install(['/.git'], [], 'test');

        try {
            (new Sync($this->a, $foreign))->pull();
            $this->fail('pull() must refuse a foreign central store');
        } catch (StoreException $e) {
            $this->assertStringContainsString('another central store', $e->getMessage());
        }
        $this->assertSame(['/.env*', '~union select'], $this->a->patterns());
    }

    public function test_push_refuses_a_foreign_central_store_before_writing_to_it(): void
    {
        (new Sync($this->a, $this->central))->pull();
        $this->trap($this->a);
        $foreign = new PdoCentralStore(Env::pdo('sqlite'));
        $foreign->install(['/.git'], [], 'test');

        try {
            (new Sync($this->a, $foreign))->push();
            $this->fail('push() must refuse a foreign central store');
        } catch (StoreException $e) {
            $this->assertStringContainsString('another central store', $e->getMessage());
        }
        $this->assertSame([], $foreign->blocks(false, null, 10));
        $this->assertCount(1, $this->a->events(10));
    }

    public function test_lists_are_replaced_only_when_the_central_version_changed(): void
    {
        $sync = new Sync($this->a, $this->central);
        $sync->pull();
        $this->a->replaceLists(['/local-only'], []);

        $sync->pull();
        $this->assertSame(['/local-only'], $this->a->patterns());

        $this->central->addPattern('/.git', 'ops');
        $sync->pull();
        $this->assertSame(['/.env*', '~union select', '/.git'], $this->a->patterns());
    }

    public function test_a_forever_block_stays_forever_across_servers(): void
    {
        $this->trap($this->a, 0);
        (new Sync($this->a, $this->central))->run();
        $this->central->insertBlocks([new Block(self::SCANNER, time(), time() + 60, 'web9')]);
        (new Sync($this->b, $this->central))->run();

        $this->assertSame(0, $this->central->blocks()[0]->expiresAt);
        $this->assertSame(0, $this->b->blocks()[0]->expiresAt);
    }

    public function test_run_gives_way_when_another_process_holds_the_lock(): void
    {
        $other = new FileLocalStore($this->dirA);
        $this->assertTrue($other->lock(60));

        $this->assertFalse((new Sync($this->a, $this->central))->run());
        $other->unlock();
    }

    public function test_run_with_watch_pushes_a_block_made_while_it_waits(): void
    {
        (new Sync($this->a, $this->central))->pull();
        $startAt = sprintf('%.6F', microtime(true) + 1.0);
        $process = proc_open([PHP_BINARY, __DIR__ . '/../fixtures/hit.php', 'file', $this->dirA, $startAt], [1 => ['pipe', 'w']], $pipes);
        $this->assertIsResource($process);

        $this->assertTrue((new Sync($this->a, $this->central))->run(3));
        proc_close($process);

        $this->assertSame([], $this->a->events(10));
        $this->assertSame('203.0.113.9', $this->central->blocks()[0]->ip);
    }

    public function test_hits_spread_over_two_servers_escalate_centrally_and_reach_both(): void
    {
        $policy = new SubnetPolicy();
        $syncA = new Sync($this->a, $this->central, null, $policy);
        $syncB = new Sync($this->b, $this->central, null, $policy);
        $guardA = new Guard($this->a, true, 600, 'web-a', [], ['/.env*'], null, null, true, $policy);
        $guardB = new Guard($this->b, true, 600, 'web-b', [], ['/.env*'], null, null, true, $policy);

        $guardA->decide(new RequestContext('45.155.205.1', 'GET', '/.env'));
        $guardB->decide(new RequestContext('45.155.205.2', 'GET', '/.env'));
        $guardA->decide(new RequestContext('45.155.205.3', 'GET', '/.env'));
        $this->assertFalse($this->a->read('45.155.205.250')->blocked, 'each server alone stays below the threshold');

        $syncA->run();
        $syncB->run();
        $syncA->run();

        $network = array_values(array_filter($this->central->blocks(), static fn (Block $b): bool => $b->isNetwork()));
        $this->assertCount(1, $network);
        $this->assertSame([Block::SOURCE_SUBNET, '45.155.205.0/24'], [$network[0]->source, $network[0]->ip]);
        $this->assertTrue($this->a->read('45.155.205.250')->blocked);
        $this->assertTrue($this->b->read('45.155.205.250')->blocked);
    }

    public function test_a_lifted_network_is_not_blocked_again_by_the_next_single_hit(): void
    {
        $policy = new SubnetPolicy();
        $syncA = new Sync($this->a, $this->central, null, $policy);
        $guardA = new Guard($this->a, true, 600, 'web-a', [], ['/.env*'], null, null, true, $policy);
        foreach (['45.155.205.1', '45.155.205.2', '45.155.205.3'] as $ip) {
            $guardA->decide(new RequestContext($ip, 'GET', '/.env'));
        }
        $syncA->run();
        $this->assertCount(1, $this->central->networkBlocks());

        $this->central->lift('45.155.205.0/24', 'ops');
        $this->a->removeBlock('45.155.205.0/24');
        $guardA->decide(new RequestContext('45.155.205.4', 'GET', '/.env'));
        $syncA->run();

        $this->assertSame([], $this->central->networkBlocks());
        $this->assertFalse($this->a->read('45.155.205.250')->blocked);
    }

    public function test_a_network_block_lifted_centrally_leaves_every_server(): void
    {
        $this->central->insertBlocks([new Block('45.155.205.0/24', time(), 0, source: Block::SOURCE_MANUAL)]);
        (new Sync($this->a, $this->central))->pull();
        $this->assertTrue($this->a->read('45.155.205.9')->blocked);

        $this->central->lift('45.155.205.0/24', 'ops');
        (new Sync($this->a, $this->central))->pull();

        $this->assertFalse($this->a->read('45.155.205.9')->blocked);
    }

    public function test_lists_reach_every_server_and_are_replaced_only_on_a_new_version(): void
    {
        $this->central->replaceList('spamhaus-drop', ['45.155.205.0/24'], 1000);
        (new Sync($this->a, $this->central))->pull();
        $this->assertSame('spamhaus-drop', $this->a->read('45.155.205.9')->listed);
        $this->assertSame(1, $this->a->marker()['listsVersion'] ?? null);

        $this->a->replaceList('spamhaus-drop', [], 1000);
        (new Sync($this->a, $this->central))->pull();
        $this->assertNull($this->a->read('45.155.205.9')->listed, 'same version: the local copy is left alone');

        $this->central->replaceList('own', ['91.92.248.0/22'], 2000);
        $this->central->replaceList('spamhaus-drop', [], 2000);
        (new Sync($this->a, $this->central))->pull();
        $this->assertSame('own', $this->a->read('91.92.249.1')->listed);
        $this->assertSame(['own'], array_keys($this->a->listStatus()));
    }

    public function test_hits_of_a_shipped_batch_escalate_even_when_a_later_batch_fails(): void
    {
        $policy = new SubnetPolicy();
        $guard = new Guard($this->a, true, 600, 'web-a', [], ['/.env*']);
        foreach (['45.155.205.1', '45.155.205.2', '45.155.205.3'] as $ip) {
            $guard->decide(new RequestContext($ip, 'GET', '/.env'));
        }
        for ($i = 0; $i < 198; $i++) {
            $guard->decide(new RequestContext('91.' . intdiv($i, 250) . '.' . ($i % 250) . '.1', 'GET', '/.env'));
        }
        $this->assertCount(201, $this->a->events(1000));

        $failing = new class ($this->central) implements CentralStore {
            private int $batches = 0;

            public function __construct(private readonly PdoCentralStore $inner)
            {
            }

            public function insertBlocks(array $blocks): void
            {
                // Only shipped batches count; the escalation's own network block must go through
                if ($blocks !== [] && !$blocks[0]->isNetwork() && ++$this->batches === 2) {
                    throw new StoreException('second batch fails');
                }
                $this->inner->insertBlocks($blocks);
            }

            public function install(array $patterns, array $allow, string $by): void
            {
                $this->inner->install($patterns, $allow, $by);
            }

            public function owner(): string
            {
                return $this->inner->owner();
            }

            public function version(): int
            {
                return $this->inner->version();
            }

            public function blocks(bool $activeOnly = true, ?string $ip = null, int $limit = 1000): array
            {
                return $this->inner->blocks($activeOnly, $ip, $limit);
            }

            public function networkBlocks(bool $activeOnly = true): array
            {
                return $this->inner->networkBlocks($activeOnly);
            }

            public function lift(string $ip, string $by): int
            {
                return $this->inner->lift($ip, $by);
            }

            public function patterns(): array
            {
                return $this->inner->patterns();
            }

            public function addPattern(string $pattern, string $by): bool
            {
                return $this->inner->addPattern($pattern, $by);
            }

            public function removePattern(string $pattern): bool
            {
                return $this->inner->removePattern($pattern);
            }

            public function allowEntries(): array
            {
                return $this->inner->allowEntries();
            }

            public function saveAllow(AllowEntry $entry): void
            {
                $this->inner->saveAllow($entry);
            }

            public function removeAllow(string $entry): bool
            {
                return $this->inner->removeAllow($entry);
            }

            public function replaceList(string $source, array $networks, int $at): bool
            {
                return $this->inner->replaceList($source, $networks, $at);
            }

            public function listEntries(string $source): array
            {
                return $this->inner->listEntries($source);
            }

            public function listStatus(): array
            {
                return $this->inner->listStatus();
            }

            public function listsVersion(): int
            {
                return $this->inner->listsVersion();
            }

            public function recentTrapIps(int $since): array
            {
                return $this->inner->recentTrapIps($since);
            }
        };

        try {
            (new Sync($this->a, $failing, null, $policy))->push();
            $this->fail('The second batch should have thrown');
        } catch (StoreException) {
        }

        $network = $this->central->blocks(true, '45.155.205.0/24');
        $this->assertCount(1, $network);
        $this->assertTrue($network[0]->isNetwork());
    }
}
