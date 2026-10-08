<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Store;

use PHPUnit\Framework\TestCase;
use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Escalation;
use ScannerTrap\Store\LocalStore;

/** Every LocalStore runs these. createStore() must return an empty store; called twice it returns two handles on one backend. */
abstract class LocalStoreContract extends TestCase
{
    abstract protected function createStore(): LocalStore;

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
        $this->assertSame(['owner' => 'abc123', 'version' => 7, 'listsVersion' => -1], $this->createStore()->marker());
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

    public function test_a_network_block_covers_every_address_in_it(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('45.155.205.0/24', time(), time() + 600, source: 'subnet'), false);

        $snapshot = $this->createStore()->read('45.155.205.77');
        $this->assertTrue($snapshot->blocked);
        $this->assertSame('45.155.205.0/24', $snapshot->network);
        $this->assertFalse($store->read('45.155.206.1')->blocked);
        $this->assertNull($store->read('45.155.206.1')->network);
    }

    public function test_network_blocks_at_several_prefix_lengths(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('45.155.0.0/16', time(), 0, source: 'manual'), false);
        $store->addBlock(new Block('91.92.248.0/22', time(), 0, source: 'manual'), false);

        $this->assertSame('45.155.0.0/16', $store->read('45.155.1.1')->network);
        $this->assertSame('91.92.248.0/22', $store->read('91.92.251.200')->network);
        $this->assertFalse($store->read('91.92.252.1')->blocked);
    }

    public function test_an_ipv6_network_block(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('2a01:4f8:c0c:1234::/64', time(), 0, source: 'subnet'), false);

        $this->assertSame('2a01:4f8:c0c:1234::/64', $store->read('2a01:4f8:c0c:1234:ffff::9')->network);
        $this->assertFalse($store->read('2a01:4f8:c0c:1235::1')->blocked);
    }

    public function test_a_network_block_is_created_once_listed_and_removed(): void
    {
        $store = $this->createStore();
        $block = new Block('45.155.205.0/24', time(), time() + 600, 'web1', 'GET', '/.env', '/.env*', 'zgrab', 'subnet');
        $store->addBlock(new Block('45.155.205.9', time(), time() + 600), false);

        $this->assertTrue($store->addBlock($block, false));
        $this->assertFalse($store->addBlock($block, false));
        $listed = array_values(array_filter($store->blocks(), static fn (Block $b): bool => $b->isNetwork()));
        $this->assertEquals([$block], $listed);

        $store->removeBlock('45.155.205.0/24');
        $this->assertNull($store->read('45.155.205.77')->network);
        $this->assertFalse($store->read('45.155.205.77')->blocked);
        $this->assertTrue($store->read('45.155.205.9')->blocked, 'the IP block is a separate entry');
    }

    public function test_a_network_block_queues_an_event_when_asked(): void
    {
        $store = $this->createStore();
        $block = new Block('45.155.205.0/24', time(), 0, source: 'subnet');
        $store->addBlock($block, true);

        $events = array_values($store->events(10));
        $this->assertContainsOnlyInstancesOf(Block::class, $events);
        $this->assertSame($this->keepsEvents() ? ['45.155.205.0/24'] : [], array_map(static fn (Block $b): string => $b->ip, $events));
    }

    public function test_an_expired_network_block_lets_the_network_back_in(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block('45.155.205.0/24', time(), time() + 1, source: 'subnet'), false);
        sleep(2);

        $this->assertFalse($store->read('45.155.205.77')->blocked);
        $this->assertSame([], array_values(array_filter($store->blocks(), static fn (Block $b): bool => $b->isNetwork())));
        $this->assertTrue($store->addBlock(new Block('45.155.205.0/24', time(), time() + 60, source: 'subnet'), false));
    }

    private function hit(string $ip): Block
    {
        return new Block($ip, time(), time() + 600, 'web1', 'GET', '/.env', '/.env*', 'zgrab');
    }

    public function test_the_third_address_of_a_slash_24_blocks_the_network(): void
    {
        $store = $this->createStore();
        $escalation = new Escalation('45.155.205.0/24', '4/24', 3, 86400);

        $store->addBlock($this->hit('45.155.205.1'), true, $escalation);
        $store->addBlock($this->hit('45.155.205.2'), true, $escalation);
        $this->assertFalse($store->read('45.155.205.250')->blocked);

        $store->addBlock($this->hit('45.155.205.3'), true, $escalation);
        $snapshot = $this->createStore()->read('45.155.205.250');
        $this->assertTrue($snapshot->blocked);
        $this->assertSame('45.155.205.0/24', $snapshot->network);

        $networks = array_values(array_filter($store->blocks(), static fn (Block $b): bool => $b->isNetwork()));
        $this->assertCount(1, $networks);
        $this->assertSame([Block::SOURCE_SUBNET, '/.env*', 'web1'], [$networks[0]->source, $networks[0]->pattern, $networks[0]->server]);
        if ($this->keepsEvents()) {
            $this->assertSame(['45.155.205.1', '45.155.205.2', '45.155.205.3', '45.155.205.0/24'], array_map(static fn (Block $b): string => $b->ip, array_values($store->events(10))));
        }
    }

    public function test_an_unblocked_network_is_not_blocked_again_by_the_next_single_hit(): void
    {
        $store = $this->createStore();
        $escalation = new Escalation('45.155.205.0/24', '4/24', 3, 86400);
        foreach (['45.155.205.1', '45.155.205.2', '45.155.205.3'] as $ip) {
            $store->addBlock($this->hit($ip), false, $escalation);
        }
        $this->assertSame('45.155.205.0/24', $store->read('45.155.205.250')->network);

        $store->removeBlock('45.155.205.0/24');
        $store->addBlock($this->hit('45.155.205.4'), false, $escalation);

        $this->assertNull($store->read('45.155.205.250')->network);
        $store->addBlock($this->hit('45.155.205.5'), false, $escalation);
        $store->addBlock($this->hit('45.155.205.6'), false, $escalation);
        $this->assertSame('45.155.205.0/24', $store->read('45.155.205.250')->network, 'three new hits escalate again');
    }

    public function test_one_address_counted_twice_is_still_one(): void
    {
        $store = $this->createStore();
        $escalation = new Escalation('45.155.205.0/24', '4/24', 2, 86400);

        $store->addBlock($this->hit('45.155.205.1'), false, $escalation);
        $store->removeBlock('45.155.205.1');
        $store->addBlock($this->hit('45.155.205.1'), false, $escalation);

        $this->assertFalse($store->read('45.155.205.99')->blocked);
    }

    public function test_a_threshold_of_one_blocks_the_ipv6_slash_64_at_once(): void
    {
        $store = $this->createStore();

        $store->addBlock($this->hit('2a01:4f8:c0c:1234::7'), false, new Escalation('2a01:4f8:c0c:1234::/64', '6/64', 1, 86400));

        $this->assertSame('2a01:4f8:c0c:1234::/64', $store->read('2a01:4f8:c0c:1234:dead::1')->network);
    }

    public function test_hits_older_than_the_window_do_not_count(): void
    {
        $store = $this->createStore();
        $escalation = new Escalation('45.155.205.0/24', '4/24', 2, 1);

        $store->addBlock($this->hit('45.155.205.1'), false, $escalation);
        sleep(2);
        $store->addBlock($this->hit('45.155.205.2'), false, $escalation);

        $this->assertFalse($store->read('45.155.205.99')->blocked);
    }

    public function test_without_an_escalation_nothing_is_counted(): void
    {
        $store = $this->createStore();
        foreach (['45.155.205.1', '45.155.205.2', '45.155.205.3'] as $ip) {
            $store->addBlock($this->hit($ip), false);
        }

        $this->assertFalse($store->read('45.155.205.99')->blocked);
    }

    protected function keepsEvents(): bool
    {
        return true;
    }

    public function test_a_listed_network_is_reported_but_not_blocked(): void
    {
        $store = $this->createStore();
        $store->replaceList('spamhaus-drop', ['45.155.205.0/24', '2a01:4f8:c0c:1234::/64'], 1000);

        $v4 = $this->createStore()->read('45.155.205.77');
        $this->assertFalse($v4->blocked);
        $this->assertSame('spamhaus-drop', $v4->listed);
        $this->assertSame('spamhaus-drop', $store->read('2a01:4f8:c0c:1234::9')->listed);
        $this->assertNull($store->read('45.155.206.1')->listed);
        $this->assertSame(['spamhaus-drop' => ['count' => 2, 'at' => 1000]], $store->listStatus());
    }

    public function test_a_new_import_replaces_the_sources_networks(): void
    {
        $store = $this->createStore();
        $store->replaceList('own', ['45.155.205.0/24', '91.92.248.0/22'], 1000);
        $store->replaceList('own', ['91.92.248.0/22', '185.220.101.0/24'], 2000);

        $this->assertNull($store->read('45.155.205.77')->listed);
        $this->assertSame('own', $store->read('91.92.250.1')->listed);
        $this->assertSame('own', $store->read('185.220.101.5')->listed);
        $this->assertSame(['own' => ['count' => 2, 'at' => 2000]], $store->listStatus());
    }

    public function test_a_network_stays_listed_while_any_source_lists_it(): void
    {
        $store = $this->createStore();
        $store->replaceList('a', ['45.155.205.0/24'], 1000);
        $store->replaceList('b', ['45.155.205.0/24'], 1000);
        $store->replaceList('a', [], 2000);

        $this->assertSame('b', $store->read('45.155.205.1')->listed);
        $this->assertSame(['b'], array_keys($store->listStatus()));
        $store->replaceList('b', [], 2000);
        $this->assertNull($store->read('45.155.205.1')->listed);
        $this->assertSame([], $store->listStatus());
    }

    public function test_lists_and_network_blocks_are_independent(): void
    {
        $store = $this->createStore();
        $store->replaceList('own', ['45.155.205.0/24'], 1000);
        $store->addBlock(new Block('45.155.205.0/24', time(), 0, source: 'manual'), false);
        $store->replaceList('own', [], 2000);

        $this->assertSame('45.155.205.0/24', $store->read('45.155.205.1')->network);
        $store->replaceList('own', ['45.155.205.0/24'], 3000);
        $store->removeBlock('45.155.205.0/24');
        $this->assertSame('own', $store->read('45.155.205.1')->listed);
    }

    public function test_a_large_list_is_imported_and_looked_up(): void
    {
        $networks = [];
        for ($i = 0; $i < 20_000; $i++) {
            $networks[] = sprintf('45.%d.%d.0/24', intdiv($i, 256), $i % 256);
        }
        $store = $this->createStore();
        $store->replaceList('big', $networks, 1000);

        $this->assertSame('big', $this->createStore()->read('45.77.200.9')->listed);
        $this->assertNull($store->read('46.0.0.1')->listed);
        $this->assertSame(20_000, $store->listStatus()['big']['count']);
    }

    public function test_the_marker_carries_the_lists_version(): void
    {
        $store = $this->createStore();
        $store->saveMarker('abc', 3);
        $this->assertSame(['owner' => 'abc', 'version' => 3, 'listsVersion' => -1], $store->marker());

        $store->saveMarker('abc', 3, 9);
        $this->assertSame(['owner' => 'abc', 'version' => 3, 'listsVersion' => 9], $this->createStore()->marker());
    }

    public function test_a_source_name_must_be_a_plain_word(): void
    {
        $store = $this->createStore();
        foreach (['2024', 'a*b'] as $name) {
            try {
                $store->replaceList($name, ['45.155.205.0/24'], 1000);
                $this->fail("Accepted {$name}");
            } catch (\InvalidArgumentException) {
                $this->assertNull($store->read('45.155.205.1')->listed);
            }
        }
    }
}
