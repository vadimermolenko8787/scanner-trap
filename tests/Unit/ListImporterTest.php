<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ScannerTrap\Exception\RefusedException;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\ListImporter;
use ScannerTrap\ListSource;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\TrapManager;

final class ListImporterTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../fixtures/lists';

    public function test_text_lists_keep_public_networks_and_count_what_they_drop(): void
    {
        $result = (new ListImporter())->parse((string) file_get_contents(self::FIXTURES . '/firehol-sample.netset'), ListSource::FORMAT_TEXT);

        $this->assertSame(['185.220.101.7/32', '45.155.205.0/24', '91.92.248.0/22'], $result['networks']);
        $this->assertSame(['invalid' => 1, 'reserved' => 2, 'tooWide' => 2], ['invalid' => $result['invalid'], 'reserved' => $result['reserved'], 'tooWide' => $result['tooWide']]);
    }

    public function test_spamhaus_json_lines_skip_the_metadata_line(): void
    {
        $result = (new ListImporter())->parse((string) file_get_contents(self::FIXTURES . '/spamhaus-sample.json'), ListSource::FORMAT_SPAMHAUS);

        $this->assertSame(['2a01:4f8:c0c:1234::/64', '45.155.205.0/24'], $result['networks']);
        $this->assertSame([1, 1, 1], [$result['invalid'], $result['reserved'], $result['tooWide']]);
    }

    public function test_a_file_source_is_imported(): void
    {
        $source = ListSource::fromConfig([['name' => 'own', 'file' => self::FIXTURES . '/own.txt']])[0];

        $this->assertSame(['185.220.101.0/24'], (new ListImporter())->import($source)['networks']);
    }

    public function test_a_missing_or_empty_file_is_a_store_exception(): void
    {
        $empty = tempnam(sys_get_temp_dir(), 'list-');
        $this->expectException(StoreException::class);
        try {
            (new ListImporter())->import(ListSource::fromConfig([['name' => 'own', 'file' => (string) $empty]])[0]);
        } finally {
            @unlink((string) $empty);
        }
    }

    public function test_a_download_without_any_network_is_a_store_exception(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'list-');
        file_put_contents((string) $file, "<html><body>Access denied</body></html>\n");
        $this->expectException(StoreException::class);
        $this->expectExceptionMessage('own parsed to no networks; the previous entries stay');
        try {
            (new ListImporter())->import(ListSource::fromConfig([['name' => 'own', 'file' => (string) $file]])[0]);
        } finally {
            @unlink((string) $file);
        }
    }

    public function test_more_than_the_limit_is_refused(): void
    {
        $lines = [];
        for ($i = 0; $i < 200_001; $i++) {
            $lines[] = sprintf('45.%d.%d.%d', intdiv($i, 65536) % 256, intdiv($i, 256) % 256, $i % 256);
        }
        $file = tempnam(sys_get_temp_dir(), 'list-');
        file_put_contents((string) $file, implode("\n", $lines));

        $this->expectException(RefusedException::class);
        try {
            (new ListImporter())->import(ListSource::fromConfig([['name' => 'huge', 'file' => (string) $file]])[0]);
        } finally {
            @unlink((string) $file);
        }
    }

    public function test_presets_and_custom_sources(): void
    {
        [$drop, $firehol, $own] = ListSource::fromConfig(['spamhaus-drop', 'firehol-level1', ['name' => 'own', 'url' => 'https://example.org/deny.txt']]);

        $this->assertSame(['https://www.spamhaus.org/drop/drop_v4.json', 'https://www.spamhaus.org/drop/drop_v6.json'], $drop->locations);
        $this->assertSame(ListSource::FORMAT_SPAMHAUS, $drop->format);
        $this->assertSame(['https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset'], $firehol->locations);
        $this->assertSame(['own', ['https://example.org/deny.txt'], ListSource::FORMAT_TEXT], [$own->name, $own->locations, $own->format]);
        $this->assertSame([], ListSource::fromConfig(null));
    }

    /** @return array<string, array{mixed}> */
    public static function brokenSources(): array
    {
        return [
            'not a list' => ['spamhaus-drop'],
            'unknown preset' => [['spamhaus-edrop']],
            'bad name' => [[['name' => 'Own List', 'file' => '/tmp/x']]],
            'name with a trailing newline' => [[['name' => "own\n", 'file' => '/tmp/x']]],
            'name starting with a digit' => [[['name' => '2024', 'file' => '/tmp/x']]],
            'preset name reused' => [[['name' => 'firehol-level1', 'file' => '/tmp/x']]],
            'duplicate name' => [[['name' => 'own', 'file' => '/tmp/x'], ['name' => 'own', 'file' => '/tmp/y']]],
            'url and file' => [[['name' => 'own', 'file' => '/tmp/x', 'url' => 'https://example.org/x']]],
            'neither' => [[['name' => 'own']]],
            'not http' => [[['name' => 'own', 'url' => 'ftp://example.org/x']]],
            'bad format' => [[['name' => 'own', 'file' => '/tmp/x', 'format' => 'xml']]],
        ];
    }

    #[DataProvider('brokenSources')]
    public function test_a_broken_source_config_is_refused(mixed $config): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ListSource::fromConfig($config);
    }

    public function test_a_file_over_the_cap_is_refused_and_the_error_reaches_the_import_report(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'list-');
        file_put_contents((string) $file, str_repeat("45.155.205.1\n", 10)); // 130 bytes
        $source = ListSource::fromConfig([['name' => 'own', 'file' => (string) $file]])[0];
        $dir = sys_get_temp_dir() . '/scanner-trap-test-' . bin2hex(random_bytes(6));
        try {
            try {
                (new ListImporter(maxBytes: 100))->import($source);
                $this->fail('No exception');
            } catch (StoreException $e) {
                $this->assertSame("{$file} is larger than 100 bytes; the previous entries stay", $e->getMessage());
            }
            $manager = new TrapManager(new FileLocalStore($dir), null, [], [], listSources: [$source], importer: new ListImporter(maxBytes: 100));
            $this->assertSame("{$file} is larger than 100 bytes; the previous entries stay", $manager->import()['own']['error']);
            $this->assertSame(['45.155.205.1/32'], (new ListImporter(maxBytes: 130))->import($source)['networks']);
        } finally {
            @unlink((string) $file);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    }
}
