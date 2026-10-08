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
        $store->replaceLists(['/.env*'], []);
        $store->saveMarker('abc', 1);

        $this->assertFileExists($this->dir . '/blocks/' . sha1('203.0.113.7'));
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

    public function test_every_network_write_gets_a_new_file_name_so_opcache_cannot_hide_it(): void
    {
        $writer = $this->createStore();
        $reader = $this->createStore();
        $writer->addBlock(new Block('45.155.205.0/24', time(), 0, source: 'manual'), false);
        $first = trim((string) file_get_contents($this->dir . '/networks.current'));
        $this->assertTrue($reader->read('45.155.205.1')->blocked);

        $writer->addBlock(new Block('91.92.248.0/22', time(), 0, source: 'manual'), false);
        $second = trim((string) file_get_contents($this->dir . '/networks.current'));

        $this->assertMatchesRegularExpression('/^networks-[0-9a-f]{16}\.php$/', $second);
        $this->assertNotSame($first, $second);
        $this->assertTrue($reader->read('91.92.249.1')->blocked);
    }

    public function test_a_corrupt_networks_pointer_or_file_makes_a_corrupt_snapshot(): void
    {
        mkdir($this->dir, 0775, true);
        file_put_contents($this->dir . '/networks.current', '../../etc/passwd');
        $this->assertTrue($this->createStore()->read('45.155.205.1')->corrupt);

        file_put_contents($this->dir . '/networks.current', 'networks-0123456789abcdef.php');
        file_put_contents($this->dir . '/networks-0123456789abcdef.php', '<?php return "nope";');
        $this->assertTrue($this->createStore()->read('45.155.205.1')->corrupt);

        file_put_contents($this->dir . '/networks-0123456789abcdef.php', '<?php syntax error');
        $this->assertTrue($this->createStore()->read('45.155.205.1')->corrupt);
    }

    public function test_a_superseded_networks_file_is_kept_for_ten_minutes_after_it_stops_being_current(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('45.155.205.0/24', time(), 0, source: 'manual'), false);
        $first = $this->dir . '/' . trim((string) file_get_contents($this->dir . '/networks.current'));
        touch($first, time() - 3600);

        $store->addBlock(new Block('91.92.248.0/22', time(), 0, source: 'manual'), false);
        $second = $this->dir . '/' . trim((string) file_get_contents($this->dir . '/networks.current'));

        $this->assertFileExists($first);
        $this->assertNotSame($first, $second);

        $stale = $this->dir . '/networks-0123456789abcdef.php';
        file_put_contents($stale, '<?php return [];');
        touch($stale, time() - 3600);
        $store->addBlock(new Block('185.0.0.0/16', time(), 0, source: 'manual'), false);

        $this->assertFileDoesNotExist($stale);
        $this->assertFileExists($second);
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
}
