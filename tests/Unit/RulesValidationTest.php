<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ScannerTrap\Rules;

final class RulesValidationTest extends TestCase
{
    /** @return array<string, array{string, bool}> */
    public static function patterns(): array
    {
        return [
            'path' => ['/wp-admin', true],
            'nested path' => ['/vendor/phpunit', true],
            'extension' => ['*.php.bak', true],
            'root' => ['/', false],
            'no leading slash' => ['wp-admin', false],
            'one character extension' => ['*.b', false],
            'one character part' => ['*.php.b', false],
            'script' => ['*.js', false],
            'stylesheet' => ['*.css', false],
            'minified script' => ['*.min.js', false],
            'php itself' => ['*.php', false],
            'image' => ['*.webp', false],
            'font' => ['*.woff2', false],
            'whitespace in a path' => ['/wp admin', false],
            'question mark in a path' => ['/index?x', false],
            'open prefix' => ['/.env*', true],
            'open prefix further down' => ['/vendor/phpu*', true],
            'star alone' => ['/*', false],
            'star inside a segment' => ['/wp-*-admin', false],
            'star before a slash' => ['/wp*/admin', false],
            'fragment of two words' => ['~union select', true],
            'fragment with quotes' => ["~' or '", true],
            'fragment with a bracket' => ['~sleep(', true],
            'fragment with @' => ['~@@version', true],
            'fragment too short' => ['~1=1', false],
            'fragment of one plain word' => ['~select', false],
            'fragment of one word with an underscore' => ['~information_schema', false],
            'fragment with a slash' => ['~/helpdesk/ x', false],
            'fragment with a query separator' => ['~id=1&x=2', false],
        ];
    }

    #[DataProvider('patterns')]
    public function test_validates_patterns(string $pattern, bool $valid): void
    {
        $this->assertSame($valid, Rules::patternError(Rules::normalizePattern($pattern)) === null);
    }

    /** @return array<string, array{string, bool}> */
    public static function ownPathPatterns(): array
    {
        return [
            'the own path itself' => ['/admin', false],
            'below the own path' => ['/admin/x', false],
            'above the own path' => ['/app', false],
            'open prefix beginning the own path' => ['/adm*', false],
            'open prefix past the own path' => ['/adminx*', true],
            'neighbouring segment' => ['/administrator', true],
            'unrelated' => ['/.git', true],
        ];
    }

    #[DataProvider('ownPathPatterns')]
    public function test_refuses_patterns_covering_own_paths(string $pattern, bool $valid): void
    {
        $this->assertSame($valid, Rules::patternError($pattern, ['/admin', '/app/assets']) === null);
    }

    public function test_normalizes_patterns_the_way_they_are_stored(): void
    {
        $this->assertSame('/wp-admin', Rules::normalizePattern('  /WP-Admin/ '));
        $this->assertSame('~union select', Rules::normalizePattern('~ UNION   Select '));
        $this->assertSame('/', Rules::normalizePattern('/'));
        $this->assertSame('*.php.bak', Rules::normalizePattern('*.PHP.bak'));
    }

    /** @return array<string, array{string, bool}> */
    public static function allowEntries(): array
    {
        return [
            'v4' => ['203.0.113.7', true],
            'v6' => ['2001:db8::1', true],
            'v4 range' => ['192.168.0.0/24', true],
            'v6 range' => ['2001:db8::/32', true],
            'mask' => ['10.*.0.1', true],
            'mask of three octets' => ['192.168.*', false],
            'star inside an octet' => ['192.168.0.1*', false],
            'octet out of range' => ['256.*.*.*', false],
            'prefix too long' => ['10.0.0.0/33', false],
            'v6 prefix too long' => ['2001:db8::/129', false],
            'empty prefix' => ['10.0.0.0/', false],
            'mask on v6' => ['2001:db8::*', false],
            'not an address' => ['office', false],
            'empty' => ['', false],
        ];
    }

    #[DataProvider('allowEntries')]
    public function test_validates_whitelist_entries(string $entry, bool $valid): void
    {
        $this->assertSame($valid, Rules::allowEntryError($entry) === null);
    }
}
