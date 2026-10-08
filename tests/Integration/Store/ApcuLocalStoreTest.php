<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Store;

use ScannerTrap\Block;
use ScannerTrap\Store\ApcuLocalStore;
use ScannerTrap\Store\LocalStore;

final class ApcuLocalStoreTest extends LocalStoreContract
{
    protected function setUp(): void
    {
        if (!extension_loaded('apcu') || !apcu_enabled()) {
            $this->markTestSkipped('ext-apcu with apc.enable_cli=1 is needed.');
        }
        apcu_clear_cache();
    }

    protected function createStore(): LocalStore
    {
        return new ApcuLocalStore();
    }

    public function test_only_the_creating_call_queues_an_event(): void
    {
        $store = $this->createStore();

        $this->assertTrue($store->addBlock(new Block('203.0.113.7', time(), time() + 600), true));
        $this->assertTrue($store->read('203.0.113.7')->blocked);
        $this->assertSame([], $store->events(10));
    }

    public function test_events_come_oldest_first_up_to_the_limit_and_leave_when_acknowledged(): void
    {
        $store = $this->createStore();

        $store->ackEvents([]);
        $this->assertSame([], $store->events(10));
        $this->assertFalse($store->waitForEvents(0));
    }

    protected function keepsEvents(): bool
    {
        return false;
    }

    public function test_prune_has_nothing_to_do_because_ttls_expire_everything(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('203.0.113.7', time(), time() + 600), false);
        $this->assertSame(0, $store->prune(time()));
    }
}
