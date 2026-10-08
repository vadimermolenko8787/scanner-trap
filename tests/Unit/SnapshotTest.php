<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Snapshot;

final class SnapshotTest extends TestCase
{
    public function test_absent_lists_are_null_and_present_ones_decoded(): void
    {
        $absent = Snapshot::decode(false, null, null);
        $this->assertFalse($absent->corrupt);
        $this->assertNull($absent->patterns);
        $this->assertNull($absent->allow);

        $present = Snapshot::decode(true, '["/.env*","~union select"]', '[{"entry":"10.0.0.0/8","comment":"office","expires":0}]');
        $this->assertTrue($present->blocked);
        $this->assertSame(['/.env*', '~union select'], $present->patterns);
        $this->assertSame(['10.0.0.0/8'], $present->allowedEntries(time()));
    }

    public function test_expired_whitelist_entries_are_left_out(): void
    {
        $snapshot = Snapshot::decode(false, '[]', '[{"entry":"10.0.0.1","expires":100},{"entry":"10.0.0.2","expires":0}]');

        $this->assertSame(['10.0.0.2'], $snapshot->allowedEntries(200));
    }

    public function test_corrupted_lists_mark_the_snapshot_corrupt(): void
    {
        $this->assertTrue(Snapshot::decode(false, 'not json', '[]')->corrupt);
        $this->assertTrue(Snapshot::decode(false, '{"a":"/.env"}', '[]')->corrupt);
        $this->assertTrue(Snapshot::decode(false, '[1,2]', '[]')->corrupt);
        $this->assertTrue(Snapshot::decode(false, '[]', '"10.0.0.1"')->corrupt);
        $this->assertTrue(Snapshot::decode(false, '[]', '[{"entry":"office"}]')->corrupt);
    }

    public function test_block_round_trips_and_cuts_long_or_broken_text(): void
    {
        $block = new Block('2001:DB8::1', 1000, 0, 'web1', 'GET', '/' . str_repeat('a', 2000) . "\xff", '/.env*', "agent\xfe");
        $copy = Block::fromArray($block->toArray());

        $this->assertNotNull($copy);
        $this->assertSame('2001:db8::1', $copy->ip);
        $this->assertSame(0, $copy->expiresAt);
        $this->assertLessThanOrEqual(1024, mb_strlen($copy->path));
        $this->assertTrue(mb_check_encoding($copy->path, 'UTF-8'));
        $this->assertTrue(mb_check_encoding($copy->userAgent, 'UTF-8'));
        $this->assertNotFalse(json_encode($copy->toArray()));
        $this->assertNull(Block::fromArray(['ip' => 'garbage']));
    }

    public function test_block_text_stays_valid_utf8_within_the_byte_limit(): void
    {
        foreach (["\xff" . str_repeat('я', 600), str_repeat('€', 400)] as $path) {
            $block = new Block('10.0.0.1', 1, 0, path: $path);

            $this->assertSame(1, preg_match('//u', $block->path));
            $this->assertLessThanOrEqual(1024, strlen($block->path));
            $this->assertNotFalse(json_encode($block->toArray()));
        }
    }

    public function test_block_activity_and_ttl(): void
    {
        $forever = new Block('10.0.0.1', 100, 0);
        $timed = new Block('10.0.0.1', 100, 200);
        $lifted = new Block('10.0.0.1', 100, 0, liftedAt: 150, liftedBy: 'ops');

        $this->assertTrue($forever->isActive(10_000));
        $this->assertSame(0, $forever->ttl(10_000));
        $this->assertTrue($timed->isActive(150));
        $this->assertSame(50, $timed->ttl(150));
        $this->assertFalse($timed->isActive(200));
        $this->assertFalse($lifted->isActive(150));
    }

    public function test_allow_entry_round_trips_and_refuses_garbage(): void
    {
        $entry = new AllowEntry('192.168.0.*', 'office', 0, 'ops');

        $this->assertEquals($entry, AllowEntry::fromArray($entry->toArray()));
        $this->assertNull(AllowEntry::fromArray(['entry' => 'office']));
        $this->assertFalse((new AllowEntry('10.0.0.1', '', 100))->isActive(100));
    }
}
