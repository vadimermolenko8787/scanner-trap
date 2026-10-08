<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration;

use PHPUnit\Framework\TestCase;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\ListImporter;
use ScannerTrap\ListSource;

final class ListImporterHttpTest extends TestCase
{
    /** @var resource|null */
    private static $server = null;
    private static int $port = 0;

    public static function setUpBeforeClass(): void
    {
        self::$port = random_int(20000, 40000);
        self::$server = proc_open([PHP_BINARY, '-S', '127.0.0.1:' . self::$port, '-t', __DIR__ . '/../fixtures/lists'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes) ?: null;
        for ($i = 0; $i < 50; $i++) {
            $socket = @fsockopen('127.0.0.1', self::$port, $errno, $error, 0.1);
            if ($socket !== false) {
                fclose($socket);
                return;
            }
            usleep(100_000);
        }
        self::fail('The local HTTP server did not start');
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$server)) {
            proc_terminate(self::$server);
            proc_close(self::$server);
        }
    }

    /** @return array<string, array{bool}> */
    public static function transports(): array
    {
        return ['curl' => [true], 'streams' => [false]];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('transports')]
    public function test_a_url_source_is_fetched_and_parsed(bool $curl): void
    {
        if ($curl && !extension_loaded('curl')) {
            $this->markTestSkipped('ext-curl is not loaded.');
        }
        $source = ListSource::fromConfig([['name' => 'drop', 'url' => 'http://127.0.0.1:' . self::$port . '/spamhaus-sample.json', 'format' => 'spamhaus-json']])[0];

        $this->assertSame(['2a01:4f8:c0c:1234::/64', '45.155.205.0/24'], (new ListImporter(5.0, $curl))->import($source)['networks']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('transports')]
    public function test_a_404_is_a_store_exception(bool $curl): void
    {
        if ($curl && !extension_loaded('curl')) {
            $this->markTestSkipped('ext-curl is not loaded.');
        }
        $source = ListSource::fromConfig([['name' => 'gone', 'url' => 'http://127.0.0.1:' . self::$port . '/missing.txt']])[0];

        $this->expectException(StoreException::class);
        (new ListImporter(5.0, $curl))->import($source);
    }
}
