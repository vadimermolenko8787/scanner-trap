<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Store\RangeFile;

final class RangeFileTest extends TestCase
{
    private string $file;

    protected function setUp(): void
    {
        $this->file = (string) tempnam(sys_get_temp_dir(), 'ranges-');
    }

    protected function tearDown(): void
    {
        @unlink($this->file);
    }

    /** @param array<string, list<string>> $sources */
    private function write(array $sources): void
    {
        file_put_contents($this->file, RangeFile::build($sources));
    }

    public function test_looks_up_v4_and_v6_with_boundaries(): void
    {
        $this->write(['drop' => ['45.155.205.0/24', '91.92.248.0/22', '2a01:4f8:c0c:1234::/64'], 'own' => ['185.220.101.7/32']]);

        $this->assertSame('drop', RangeFile::lookup($this->file, '45.155.205.0'));
        $this->assertSame('drop', RangeFile::lookup($this->file, '45.155.205.255'));
        $this->assertNull(RangeFile::lookup($this->file, '45.155.206.0'));
        $this->assertNull(RangeFile::lookup($this->file, '45.155.204.255'));
        $this->assertSame('drop', RangeFile::lookup($this->file, '91.92.251.255'));
        $this->assertSame('own', RangeFile::lookup($this->file, '185.220.101.7'));
        $this->assertNull(RangeFile::lookup($this->file, '185.220.101.8'));
        $this->assertSame('drop', RangeFile::lookup($this->file, '2a01:4f8:c0c:1234:ffff:ffff:ffff:ffff'));
        $this->assertNull(RangeFile::lookup($this->file, '2a01:4f8:c0c:1235::'));
        $this->assertNull(RangeFile::lookup($this->file, '1.1.1.1'));
    }

    public function test_overlapping_networks_merge_and_keep_the_first_source(): void
    {
        $this->write(['a' => ['45.155.0.0/16'], 'b' => ['45.155.205.0/24', '45.156.0.0/16']]);

        $this->assertSame('a', RangeFile::lookup($this->file, '45.155.205.9'));
        $this->assertSame('b', RangeFile::lookup($this->file, '45.156.1.1'));
    }

    public function test_an_empty_build_finds_nothing(): void
    {
        $this->write([]);

        $this->assertNull(RangeFile::lookup($this->file, '45.155.205.9'));
        $this->assertNull(RangeFile::lookup($this->file, '2a01::1'));
    }

    public function test_a_large_list_is_found_quickly(): void
    {
        $networks = [];
        for ($i = 0; $i < 200_000; $i++) {
            $networks[] = sprintf('%d.%d.%d.0/24', 45 + intdiv($i, 65536), intdiv($i, 256) % 256, $i % 256);
        }
        $this->write(['big' => $networks]);

        $started = microtime(true);
        for ($i = 0; $i < 1000; $i++) {
            $this->assertSame('big', RangeFile::lookup($this->file, sprintf('45.%d.%d.9', $i % 256, $i % 200)));
        }
        $this->assertLessThan(1.0, microtime(true) - $started, '1000 lookups in 200 000 ranges');
    }

    public function test_a_corrupt_file_is_a_store_exception(): void
    {
        file_put_contents($this->file, 'STL1' . pack('NNN', 5, 0, 2) . '[]');

        $this->expectException(StoreException::class);
        RangeFile::lookup($this->file, '45.155.205.9');
    }

    public function test_building_200_000_networks_fits_a_small_memory_limit(): void
    {
        $process = proc_open(
            [PHP_BINARY, '-d', 'memory_limit=96M', dirname(__DIR__) . '/fixtures/build_range_file.php'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        $this->assertIsResource($process);
        $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);

        $this->assertSame(0, proc_close($process), $output);
    }
}
