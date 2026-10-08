<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration;

use PHPUnit\Framework\TestCase;
use ScannerTrap\Block;
use ScannerTrap\Central\CentralStore;
use ScannerTrap\Central\PdoCentralStore;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Guard;
use ScannerTrap\RequestContext;
use ScannerTrap\Store\FileLocalStore;
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
}
