<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Store;

use PHPUnit\Framework\TestCase;
use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Store\LocalStore;

/** Every LocalStore runs these. createStore() must return an empty store; called twice it returns two handles on one backend. */
abstract class LocalStoreContract extends TestCase
{
    abstract protected function createStore(): LocalStore;

    protected function supportsEvents(): bool
    {
        return true;
    }

    public function test_an_empty_store_has_no_block_and_no_lists(): void
    {
        $snapshot = $this->createStore()->read('203.0.113.7');

        $this->assertFalse($snapshot->blocked);
        $this->assertNull($snapshot->patterns);
        $this->assertNull($snapshot->allow);
        $this->assertFalse($snapshot->corrupt);
    }

    public function test_a_block_is_created_once_and_read_back(): void
    {
        $store = $this->createStore();
        $block = new Block('203.0.113.7', time(), time() + 600, 'web1', 'GET', '/.env', '/.env*', 'curl');

        $this->assertTrue($store->addBlock($block, false));
        $this->assertFalse($store->addBlock($block, false));
        $this->assertTrue($store->read('203.0.113.7')->blocked);
        $this->assertFalse($store->read('203.0.113.8')->blocked);
        $blocks = $store->blocks();
        $this->assertCount(1, $blocks);
        $this->assertSame('/.env*', $blocks[0]->pattern);
        $this->assertSame($block->expiresAt, $blocks[0]->expiresAt);
    }

    public function test_a_forever_block_has_no_expiry(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('2001:db8::1', time(), 0), false);

        $this->assertTrue($store->read('2001:db8::1')->blocked);
        $this->assertSame(0, $store->blocks()[0]->expiresAt);
    }

    public function test_an_expired_block_is_gone_and_can_be_made_again(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('203.0.113.7', time(), time() + 1), false);
        sleep(2);

        $this->assertFalse($store->read('203.0.113.7')->blocked);
        $this->assertSame([], $store->blocks());
        $this->assertTrue($store->addBlock(new Block('203.0.113.7', time(), time() + 60), false));
    }

    public function test_a_block_is_removed(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('203.0.113.7', time(), 0), false);
        $store->removeBlock('203.0.113.7');

        $this->assertFalse($store->read('203.0.113.7')->blocked);
        $this->assertSame([], $store->blocks());
    }

    public function test_lists_are_replaced_and_read_back(): void
    {
        $store = $this->createStore();
        $allow = [new AllowEntry('10.0.0.0/8', 'office', 0, 'ops'), new AllowEntry('192.168.0.*', '', time() + 60)];
        $store->replaceLists(['/.env*', '~union select'], $allow);

        $this->assertSame(['/.env*', '~union select'], $store->patterns());
        $this->assertEquals($allow, $store->allow());
        $snapshot = $this->createStore()->read('10.1.2.3');
        $this->assertSame(['/.env*', '~union select'], $snapshot->patterns);
        $this->assertSame(['10.0.0.0/8', '192.168.0.*'], $snapshot->allowedEntries(time()));

        $store->replaceLists([], []);
        $this->assertSame([], $this->createStore()->read('10.1.2.3')->patterns);
    }

    public function test_only_the_creating_call_queues_an_event(): void
    {
        if (!$this->supportsEvents()) {
            $this->markTestSkipped('This store keeps no events.');
        }
        $store = $this->createStore();
        $block = new Block('203.0.113.7', time(), time() + 600, 'web1', 'GET', '/.env', '/.env*', 'curl');
        $store->addBlock($block, true);
        $store->addBlock($block, true);
        $store->addBlock(new Block('203.0.113.8', time(), 0), false);

        $events = $store->events(10);
        $this->assertCount(1, $events);
        $this->assertEquals($block, array_values($events)[0]);
    }

    public function test_events_come_oldest_first_up_to_the_limit_and_leave_when_acknowledged(): void
    {
        if (!$this->supportsEvents()) {
            $this->markTestSkipped('This store keeps no events.');
        }
        $store = $this->createStore();
        foreach (['203.0.113.1', '203.0.113.2', '203.0.113.3'] as $ip) {
            $store->addBlock(new Block($ip, time(), 0), true);
        }

        $first = $store->events(2);
        $this->assertSame(['203.0.113.1', '203.0.113.2'], array_map(static fn (Block $b): string => $b->ip, array_values($first)));
        $store->ackEvents(array_map('strval', array_keys($first)));
        $this->assertSame(['203.0.113.3'], array_map(static fn (Block $b): string => $b->ip, array_values($store->events(10))));
        $this->assertTrue($store->waitForEvents(0));
    }

    public function test_waiting_without_events_returns_false_after_the_timeout(): void
    {
        $started = microtime(true);

        $this->assertFalse($this->createStore()->waitForEvents(1));
        $this->assertLessThan(3.0, microtime(true) - $started);
    }

    public function test_the_marker_is_absent_then_saved(): void
    {
        $store = $this->createStore();
        $this->assertNull($store->marker());

        $store->saveMarker('abc123', 7);
        $this->assertSame(['owner' => 'abc123', 'version' => 7], $this->createStore()->marker());
    }

    public function test_the_sync_lock_is_exclusive_until_released(): void
    {
        $first = $this->createStore();
        $second = $this->createStore();

        $this->assertTrue($first->lock(60));
        $this->assertFalse($second->lock(60));
        $first->unlock();
        $this->assertTrue($second->lock(60));
        $second->unlock();
    }
}
