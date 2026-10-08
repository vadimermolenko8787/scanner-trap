<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ScannerTrap\DefaultPatterns;
use ScannerTrap\Rules;

final class SignatureTest extends TestCase
{
    public function test_type_and_normalizing(): void
    {
        $this->assertSame(Rules::TYPE_AGENT, Rules::patternType('@sqlmap'));
        $this->assertSame('@nmap scripting engine', Rules::normalizePattern('  @Nmap   Scripting  Engine '));
    }

    /** @return array<string, array{string, ?string}> */
    public static function agents(): array
    {
        return [
            'sqlmap' => ['sqlmap/1.8.4#stable (https://sqlmap.org)', '@sqlmap'],
            'case does not matter' => ['Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))', '@nuclei'],
            'two words' => ['Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)', '@nmap scripting engine'],
            'a browser' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15', null],
            'empty' => ['', null],
        ];
    }

    #[DataProvider('agents')]
    public function test_matches_the_user_agent(string $userAgent, ?string $expected): void
    {
        $patterns = ['/.env*', '~union select', '@sqlmap', '@nuclei', '@nmap scripting engine'];

        $this->assertSame($expected, Rules::matchedAgent($userAgent, $patterns));
    }

    public function test_path_matching_ignores_signatures(): void
    {
        $this->assertNull(Rules::matchedPattern('/@sqlmap', ['@sqlmap']));
        $this->assertNull(Rules::matchedFragment('/x?q=@sqlmap', ['@sqlmap']));
    }

    /** @return array<string, array{string, bool}> */
    public static function validation(): array
    {
        return [
            'tool' => ['@sqlmap', true],
            'two words' => ['@nmap scripting engine', true],
            'four characters' => ['@nmap', true],
            'three characters' => ['@zap', false],
            'two characters' => ['@ab', false],
            'browser token' => ['@mozilla', false],
            'part of a browser token' => ['@ozill', false],
            'bot' => ['@bot', false],
            'gecko' => ['@gecko', false],
            'a browser token with a slash' => ['@mozilla/5.0', false],
            'a browser phrase' => ['@like gecko', false],
            'a browser engine note' => ['@(khtml, like gecko)', false],
            'a platform note' => ['@win64; x64', false],
            'empty' => ['@', false],
        ];
    }

    #[DataProvider('validation')]
    public function test_validates_signatures(string $pattern, bool $valid): void
    {
        $this->assertSame($valid, Rules::patternError(Rules::normalizePattern($pattern)) === null);
    }

    public function test_the_default_signatures_are_valid_and_in_the_default_list(): void
    {
        foreach (DefaultPatterns::SCANNER_AGENTS as $pattern) {
            $this->assertNull(Rules::patternError($pattern), $pattern);
            $this->assertContains($pattern, DefaultPatterns::LIST);
        }
    }
}
