<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Store;

use ScannerTrap\Block;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\Store\LocalStore;

final class FileLocalStoreTest extends LocalStoreContract
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/scanner-trap-test-' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    protected function createStore(): LocalStore
    {
        return new FileLocalStore($this->dir);
    }

    public function test_a_log_of_garbage_gives_no_events_and_nothing_to_wait_for(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('203.0.113.7', time(), 0), false);
        file_put_contents($this->dir . '/events.log', "not json\n{\"a\":1}\n");

        $this->assertSame([], $store->events(10));
        $this->assertFalse($store->waitForEvents(0));
    }

    public function test_acking_throws_when_the_log_cannot_be_opened(): void
    {
        $store = $this->createStore();
        mkdir($this->dir . '/events.log', 0775, true);

        $this->expectException(StoreException::class);
        $store->ackEvents(['x']);
    }

    public function test_the_layout_is_the_specs(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('203.0.113.7', time(), 0), true);
        $store->addBlock(new Block('45.155.205.0/24', time(), 0, source: 'manual'), false);
        $store->replaceLists(['/.env*'], []);
        $store->saveMarker('abc', 1);

        $this->assertFileExists($this->dir . '/blocks/' . sha1('203.0.113.7'));
        $this->assertFileExists($this->dir . '/networks.json');
        $this->assertFileExists($this->dir . '/patterns.json');
        $this->assertFileExists($this->dir . '/allow.json');
        $this->assertFileExists($this->dir . '/events.log');
        $this->assertFileExists($this->dir . '/owner');
    }

    public function test_an_expired_block_is_replaced_by_exactly_one_of_two_handles(): void
    {
        $first = $this->createStore();
        $second = $this->createStore();
        $first->addBlock(new Block('203.0.113.7', time() - 10, time() - 5), false);

        $results = [
            $first->addBlock(new Block('203.0.113.7', time(), time() + 600), true),
            $second->addBlock(new Block('203.0.113.7', time(), time() + 600), true),
        ];

        $this->assertSame([true, false], $results);
        $this->assertCount(1, $first->events(10));
        $this->assertCount(1, $first->blocks());
    }

    public function test_a_fresh_block_replacing_an_expired_one_is_not_deleted_by_a_reader(): void
    {
        $reader = $this->createStore();
        $writer = $this->createStore();
        $writer->addBlock(new Block('203.0.113.7', time() - 10, time() - 5), false);
        $writer->addBlock(new Block('203.0.113.7', time(), time() + 600), false);

        $this->assertTrue($reader->read('203.0.113.7')->blocked);
        $this->assertCount(1, $reader->blocks());
    }

    public function test_a_list_written_by_another_process_is_seen_despite_the_cache(): void
    {
        $store = $this->createStore();
        $store->replaceLists(['/.env*'], []);
        $this->assertSame(['/.env*'], $store->read('203.0.113.7')->patterns);

        (new FileLocalStore($this->dir))->replaceLists(['/.git'], []);
        $this->assertSame(['/.git'], $store->read('203.0.113.7')->patterns);
    }

    public function test_a_corrupted_list_file_makes_a_corrupt_snapshot(): void
    {
        mkdir($this->dir, 0775, true);
        file_put_contents($this->dir . '/patterns.json', '{"oops":');

        $this->assertTrue($this->createStore()->read('203.0.113.7')->corrupt);
    }

    public function test_an_unwritable_directory_is_a_store_exception(): void
    {
        $store = new FileLocalStore('/proc/definitely/not/writable');

        $this->expectException(\ScannerTrap\Exception\StoreException::class);
        $store->addBlock(new Block('203.0.113.7', time(), 0), true);
    }

    public function test_a_network_block_written_by_another_process_is_seen_despite_the_cache(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('45.155.205.0/24', time(), 0, source: 'manual'), false);
        $this->assertTrue($store->read('45.155.205.1')->blocked);
        $this->assertFalse($store->read('91.92.249.1')->blocked);

        (new FileLocalStore($this->dir))->addBlock(new Block('91.92.248.0/22', time(), 0, source: 'manual'), false);
        $this->assertTrue($store->read('91.92.249.1')->blocked);
    }

    public function test_after_a_network_block_and_an_import_the_directory_holds_no_php_file(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('45.155.205.0/24', time(), 0, source: 'manual'), false);
        $store->replaceList('own', ['91.92.248.0/22'], 1000);
        $store->removeBlock('45.155.205.0/24');

        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($files as $file) {
            $this->assertInstanceOf(\SplFileInfo::class, $file);
            $this->assertNotSame('php', $file->getExtension(), $file->getPathname());
        }
    }

    public function test_a_networks_file_without_blocks_is_not_corrupt(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('45.155.205.0/24', time(), 0, source: 'manual'), false);
        $store->removeBlock('45.155.205.0/24');
        $this->assertFalse($this->createStore()->read('45.155.205.1')->corrupt);

        file_put_contents($this->dir . '/networks.json', '{"blocks":[]}');
        $snapshot = $this->createStore()->read('45.155.205.1');
        $this->assertFalse($snapshot->corrupt);
        $this->assertFalse($snapshot->blocked);
    }

    public function test_a_networks_file_from_before_networks_json_is_ignored(): void
    {
        mkdir($this->dir, 0775, true);
        $block = (new Block('45.155.205.0/24', time(), 0, source: 'manual'))->toArray();
        file_put_contents($this->dir . '/networks.current', 'networks-0123456789abcdef.php');
        file_put_contents($this->dir . '/networks-0123456789abcdef.php', '<?php return ' . var_export(['blocks' => [4 => [24 => ['45.155.205.0' => $block]]]], true) . ';');
        $store = $this->createStore();

        $this->assertFalse($store->read('45.155.205.1')->corrupt);
        $this->assertFalse($store->read('45.155.205.1')->blocked);
        $store->addBlock(new Block('91.92.248.0/22', time(), 0, source: 'manual'), false);
        $this->assertTrue($store->read('91.92.249.1')->blocked);
    }

    public function test_a_corrupt_networks_file_makes_a_corrupt_snapshot(): void
    {
        mkdir($this->dir, 0775, true);
        foreach (['{"oops":', '"nope"', '[1,2]', '{"blocks":"nope"}'] as $garbage) {
            file_put_contents($this->dir . '/networks.json', $garbage);
            $this->assertTrue($this->createStore()->read('45.155.205.1')->corrupt, $garbage);
        }
    }

    public function test_a_corrupt_lists_pointer_or_file_makes_a_corrupt_snapshot(): void
    {
        mkdir($this->dir, 0775, true);
        file_put_contents($this->dir . '/lists.current', '../../etc/passwd');
        $this->assertTrue($this->createStore()->read('45.155.205.1')->corrupt);

        file_put_contents($this->dir . '/lists.current', 'lists-0123456789abcdef.bin');
        file_put_contents($this->dir . '/lists-0123456789abcdef.bin', 'garbage');
        $this->assertTrue($this->createStore()->read('45.155.205.1')->corrupt);
    }

    public function test_a_superseded_lists_file_is_kept_for_ten_minutes_after_it_stops_being_current(): void
    {
        $store = $this->createStore();
        $store->replaceList('own', ['45.155.205.0/24'], 1000);
        $first = $this->dir . '/' . trim((string) file_get_contents($this->dir . '/lists.current'));
        touch($first, time() - 3600);

        $store->replaceList('own', ['91.92.248.0/22'], 2000);
        $second = $this->dir . '/' . trim((string) file_get_contents($this->dir . '/lists.current'));

        $this->assertFileExists($first);
        $this->assertNotSame($first, $second);

        $stale = $this->dir . '/lists-0123456789abcdef.bin';
        file_put_contents($stale, 'old');
        touch($stale, time() - 3600);
        $store->replaceList('own', ['185.0.0.0/16'], 3000);

        $this->assertFileDoesNotExist($stale);
        $this->assertFileExists($second);
    }

    public function test_prune_removes_expired_block_files_stale_counters_and_orphan_locks(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('203.0.113.7', time() - 10, time() - 5), false);   // expired file on disk
        $store->addBlock(new Block('203.0.113.8', time(), 0), false);                 // live
        mkdir($this->dir . '/seen', 0775, true);
        file_put_contents($this->dir . '/seen/stale', '{}');
        touch($this->dir . '/seen/stale', time() - 7200);
        file_put_contents($this->dir . '/seen/fresh', '{}');
        mkdir($this->dir . '/locks', 0775, true);
        file_put_contents($this->dir . '/locks/' . sha1('203.0.113.99'), '');         // orphan
        file_put_contents($this->dir . '/locks/' . sha1('203.0.113.8'), '');          // its block is live

        // the expired block file, the lock file its removal leaves, the stale counter, the orphan lock
        $this->assertSame(4, $store->prune(time() - 3600));

        $this->assertFileDoesNotExist($this->dir . '/blocks/' . sha1('203.0.113.7'));
        $this->assertFileExists($this->dir . '/blocks/' . sha1('203.0.113.8'));
        $this->assertFileDoesNotExist($this->dir . '/seen/stale');
        $this->assertFileExists($this->dir . '/seen/fresh');
        $this->assertFileDoesNotExist($this->dir . '/locks/' . sha1('203.0.113.99'));
        $this->assertFileExists($this->dir . '/locks/' . sha1('203.0.113.8'));
    }
}
