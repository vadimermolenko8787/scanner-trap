<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ScannerTrap\Rules;

final class RulesTest extends TestCase
{
    private const PATTERNS = ['/.env', '/.env*', '/wp-admin', '/debug', '/boaform', '*.php.bak', '*.sql'];

    /** @return array<string, array{string, ?string}> */
    public static function paths(): array
    {
        return [
            'prefix itself' => ['/wp-admin', '/wp-admin'],
            'under the prefix' => ['/wp-admin/setup.php', '/wp-admin'],
            'whole segment only' => ['/wp-admin2', null],
            'longer word' => ['/debugger', null],
            'other dot file' => ['/environment', null],
            'suffix' => ['/backup/index.php.bak', '*.php.bak'],
            'suffix needs the dot' => ['/mysql', null],
            'ordinary page' => ['/helpdesk/default/index', null],
            'decoy extension outside the routes' => ['/backup.sql', '*.sql'],
            'seven characters, like an entry link' => ['/boaform', '/boaform'],
            'open prefix itself' => ['/.env', '/.env'],
            'open prefix, variant' => ['/.env.production', '/.env*'],
            'open prefix, no separator' => ['/.env_copy', '/.env*'],
            'open prefix, below a variant' => ['/.env.local/x', '/.env*'],
            'open prefix is anchored at the root' => ['/api/.env.local', null],
        ];
    }

    #[DataProvider('paths')]
    public function test_matches_prefixes_by_whole_segments_and_suffixes_by_extension(string $path, ?string $expected): void
    {
        $this->assertSame($expected, Rules::matchedPattern($path, self::PATTERNS));
    }

    /** @return array<string, array{string, string}> */
    public static function rawPaths(): array
    {
        return [
            'upper case' => ['/WP-Admin/', '/wp-admin/'],
            'percent-encoded dot' => ['/%2eenv', '/.env'],
            'doubled slashes' => ['//wp-admin', '/wp-admin'],
        ];
    }

    #[DataProvider('rawPaths')]
    public function test_normalizes_the_path_before_matching(string $raw, string $expected): void
    {
        $this->assertSame($expected, Rules::normalizePath($raw));
    }

    /** @return array<string, array{string, ?string}> */
    public static function uris(): array
    {
        return [
            'quote and or, in a path segment' => ['/api/ifbck/client/get/test%27%20OR%20%271%27%3D%271', "~' or '"],
            'union select, in the query' => ['/api/ifbck/client/get?params=test%27%20UNION%20SELECT%201%2C2%2C3--%20-', '~union select'],
            'double-encoded' => ['/api/ifbck/client/get/test%2527%2520AND%2520SLEEP%283%29--%2520-', '~sleep('],
            'double-encoded quote' => ['/api/ifbck/client/get/test%2527%2520OR%2520%25271%2527%253D%25271', "~' or '"],
            'plus as a space' => ['/search?q=1+union+select+2', '~union select'],
            'comment as a space' => ['/search?id=1/**/UNION/**/SELECT/**/1', '~union select'],
            'newline and tab' => ['/search?id=1%0aunion%09select', '~union select'],
            'bracket, no quote' => ['/api/ifbck/client/get?params=test)%20OR%201%3D1--%20-', '~or 1=1'],
            'apostrophe in a name' => ["/app/58855c39?104576=D'Agrosa", null],
            'apostrophe in a file name' => ["/Uploads/Images/Maarten%20Smuts'%20Picture.jpg", null],
            'dashes in a token' => ['/jwt-login?token=eyJ0--eXAi', null],
            'words run together' => ['/search?q=unionselect', null],
        ];
    }

    #[DataProvider('uris')]
    public function test_matches_fragments_anywhere_in_the_decoded_uri(string $uri, ?string $expected): void
    {
        $patterns = array_merge(self::PATTERNS, ['~union select', "~' or '", '~sleep(', '~or 1=1']);

        $this->assertNull(Rules::matchedPattern(Rules::normalizePath((string) strtok($uri, '?')), $patterns));
        $this->assertSame($expected, Rules::matchedFragment($uri, $patterns));
    }

    public function test_pattern_types(): void
    {
        $this->assertSame(Rules::TYPE_PREFIX, Rules::patternType('/wp-admin'));
        $this->assertSame(Rules::TYPE_PREFIX, Rules::patternType('/.env*'));
        $this->assertSame(Rules::TYPE_SUFFIX, Rules::patternType('*.php.bak'));
        $this->assertSame(Rules::TYPE_CONTAINS, Rules::patternType('~union select'));
    }

    /** @return array<string, array{string, list<string>, bool}> */
    public static function allowlist(): array
    {
        return [
            'exact v4' => ['198.51.100.7', ['198.51.100.7'], true],
            'other v4' => ['198.51.100.8', ['198.51.100.7'], false],
            'exact v6 in another spelling' => ['2001:db8::1', ['2001:DB8:0:0::1'], true],
            'inside a v4 range' => ['192.168.0.200', ['192.168.0.0/24'], true],
            'neighbouring v4 range' => ['192.168.1.1', ['192.168.0.0/24'], false],
            'range not on a byte boundary' => ['10.0.0.9', ['10.0.0.8/29'], true],
            'just past it' => ['10.0.0.16', ['10.0.0.8/29'], false],
            'inside a v6 range' => ['2001:db8:ffff::1', ['2001:db8::/32'], true],
            'v4 against a v6 range' => ['192.168.0.1', ['2001:db8::/32'], false],
            'last octet mask' => ['192.168.0.42', ['192.168.0.*'], true],
            'mask in the middle' => ['10.77.0.1', ['10.*.0.1'], true],
            'mask in the middle, other last octet' => ['10.77.0.2', ['10.*.0.1'], false],
            'mask against v6' => ['2001:db8::1', ['10.*.*.*'], false],
            'nothing allowed' => ['192.168.0.1', [], false],
            'whole range' => ['203.0.113.9', ['0.0.0.0/0'], true],
            'garbage entry is skipped' => ['198.51.100.7', ['office', '198.51.100.0/33', '198.51.100.7'], true],
        ];
    }

    /** @param list<string> $entries */
    #[DataProvider('allowlist')]
    public function test_allowlist_takes_ips_ranges_and_octet_masks(string $ip, array $entries, bool $expected): void
    {
        $this->assertSame($expected, Rules::isAllowed($ip, $entries));
    }

    public function test_ipv6_collapses_to_one_spelling_and_garbage_is_no_address(): void
    {
        $this->assertSame('2001:db8::7', Rules::normalizeIp('2001:DB8:0:0::7'));
        $this->assertSame('203.0.113.7', Rules::normalizeIp('203.0.113.7'));
        $this->assertNull(Rules::normalizeIp('not-an-ip'));
        $this->assertNull(Rules::normalizeIp(''));
        $this->assertNull(Rules::normalizeIp('1.2.3.4:80'));
    }

    /** @return array<string, array{string, bool}> */
    public static function ownPaths(): array
    {
        return [
            'the path itself' => ['/wp-admin', true],
            'below it' => ['/wp-admin/install.php', true],
            'another segment' => ['/wp-admin2', false],
            'elsewhere' => ['/.env', false],
        ];
    }

    #[DataProvider('ownPaths')]
    public function test_own_paths_cover_whole_segments_however_they_are_written(string $path, bool $expected): void
    {
        $this->assertSame($expected, Rules::underOwnPath($path, ['/WP-Admin/']));
        $this->assertSame($expected, Rules::underOwnPath($path, ['/wp-admin']));
    }

    /** @return array<string, array{string, bool}> */
    public static function loopbacks(): array
    {
        return [
            'v4 loopback' => ['127.0.0.1', true],
            'anywhere in 127/8' => ['127.3.2.1', true],
            'v6 loopback' => ['::1', true],
            'public v4' => ['203.0.113.7', false],
            'public v6' => ['2001:db8::1', false],
        ];
    }

    #[DataProvider('loopbacks')]
    public function test_loopback_is_127_slash_8_and_v6_one(string $ip, bool $expected): void
    {
        $this->assertSame($expected, Rules::isLoopback($ip));
    }
}
