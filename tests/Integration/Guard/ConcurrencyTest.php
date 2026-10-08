<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Guard;

use PHPUnit\Framework\TestCase;
use ScannerTrap\Block;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\Store\LocalStore;
use ScannerTrap\Store\RedisLocalStore;
use ScannerTrap\Tests\Support\Env;

/** Several processes hit the same decoy at the same moment: exactly one block event. */
final class ConcurrencyTest extends TestCase
{
    private const PROCESSES = 8;

    public function test_file_store_records_one_event(): void
    {
        $dir = sys_get_temp_dir() . '/scanner-trap-race-' . bin2hex(random_bytes(6));
        try {
            $this->assertOneEvent('file', $dir, new FileLocalStore($dir));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    }

    public function test_redis_store_records_one_event(): void
    {
        $redis = Env::phpRedis();
        $redis->raw('FLUSHDB');
        try {
            $this->assertOneEvent('redis', 'race:', new RedisLocalStore($redis, 'race:'));
        } finally {
            $redis->raw('FLUSHDB');
        }
    }

    private function assertOneEvent(string $type, string $target, LocalStore $store): void
    {
        $startAt = sprintf('%.6F', microtime(true) + 1.0);
        $processes = [];
        for ($i = 0; $i < self::PROCESSES; $i++) {
            $command = [PHP_BINARY, __DIR__ . '/../../fixtures/hit.php', $type, $target, $startAt];
            $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $this->assertIsResource($process);
            $processes[] = [$process, $pipes];
        }
        $outputs = [];
        foreach ($processes as [$process, $pipes]) {
            $outputs[] = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            proc_close($process);
        }

        $this->assertSame(1, count(array_filter($outputs, static fn ($o): bool => $o === 'recorded')), implode("\n", $outputs));
        $this->assertCount(1, $store->events(100));
    }

    public function test_parallel_hits_from_one_network_record_one_network_event(): void
    {
        $dir = sys_get_temp_dir() . '/scanner-trap-race-net-' . bin2hex(random_bytes(6));
        try {
            $store = new FileLocalStore($dir);
            $startAt = sprintf('%.6F', microtime(true) + 1.0);
            $processes = [];
            for ($i = 1; $i <= self::PROCESSES; $i++) {
                $process = proc_open([PHP_BINARY, __DIR__ . '/../../fixtures/hit.php', 'file', $dir, $startAt, "45.155.205.{$i}", 'escalate'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
                $this->assertIsResource($process);
                $processes[] = [$process, $pipes];
            }
            foreach ($processes as [$process, $pipes]) {
                stream_get_contents($pipes[1]);
                stream_get_contents($pipes[2]);
                proc_close($process);
            }

            $networkEvents = array_filter($store->events(100), static fn (Block $b): bool => $b->isNetwork());
            $this->assertCount(1, $networkEvents);
            $this->assertTrue($store->read('45.155.205.250')->blocked);
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    }
}
