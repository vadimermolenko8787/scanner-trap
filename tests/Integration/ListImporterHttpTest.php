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
        self::$server = proc_open([PHP_BINARY, '-S', '127.0.0.1:' . self::$port, '-t', __DIR__ . '/../fixtures/lists', __DIR__ . '/../fixtures/lists-router.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes) ?: null;
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

    /** @return array<string, array{bool, bool}> */
    public static function bodies(): array
    {
        return ['curl' => [true, false], 'curl, announced length' => [true, true], 'streams' => [false, false]];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('bodies')]
    public function test_a_body_over_the_cap_is_refused(bool $curl, bool $announce): void
    {
        if ($curl && !extension_loaded('curl')) {
            $this->markTestSkipped('ext-curl is not loaded.');
        }
        $url = 'http://127.0.0.1:' . self::$port . '/bytes/5000' . ($announce ? '?announce=1' : '');
        $source = ListSource::fromConfig([['name' => 'big', 'url' => $url]])[0];

        $this->expectException(StoreException::class);
        $this->expectExceptionMessage("{$url} is larger than 1000 bytes; the previous entries stay");
        (new ListImporter(5.0, $curl, 1000))->import($source);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('bodies')]
    public function test_a_body_exactly_at_the_cap_is_imported(bool $curl, bool $announce): void
    {
        if ($curl && !extension_loaded('curl')) {
            $this->markTestSkipped('ext-curl is not loaded.');
        }
        $url = 'http://127.0.0.1:' . self::$port . '/bytes/1300' . ($announce ? '?announce=1' : '');
        $source = ListSource::fromConfig([['name' => 'big', 'url' => $url]])[0];

        $this->assertSame(['45.155.205.1/32'], (new ListImporter(5.0, $curl, 1300))->import($source)['networks']);
    }
}
