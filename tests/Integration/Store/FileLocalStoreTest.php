<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Store;

use ScannerTrap\Block;
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
}
