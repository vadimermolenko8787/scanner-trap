<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ScannerTrap\DefaultPatterns;
use ScannerTrap\Rules;

final class DefaultPatternsTest extends TestCase
{
    public function test_every_default_pattern_passes_validation_and_is_stored_normalized(): void
    {
        foreach (array_merge(DefaultPatterns::LIST, DefaultPatterns::WORDPRESS_PROBES) as $pattern) {
            $this->assertSame($pattern, Rules::normalizePattern($pattern), $pattern);
            $this->assertNull(Rules::patternError($pattern), $pattern);
        }
    }

    public function test_the_lists_do_not_overlap_and_hold_no_real_application_paths(): void
    {
        $this->assertSame([], array_intersect(DefaultPatterns::LIST, DefaultPatterns::WORDPRESS_PROBES));
        foreach (['/storage', '/build', '/public', '/static', '/web', '/config'] as $real) {
            $this->assertNull(Rules::matchedPattern($real, DefaultPatterns::LIST), $real);
            $this->assertNull(Rules::matchedPattern($real . '/app.js', DefaultPatterns::LIST), $real);
        }
    }

    public function test_the_defaults_catch_the_classic_probes(): void
    {
        foreach (['/.env', '/.env.production', '/.git/config', '/phpmyadmin/index.php', '/backup.sql', '/index.php.bak'] as $probe) {
            $this->assertNotNull(Rules::matchedPattern($probe, DefaultPatterns::LIST), $probe);
        }
        $this->assertNotNull(Rules::matchedFragment('/x?id=1%20UNION%20SELECT%201', DefaultPatterns::LIST));
        $this->assertNull(Rules::matchedPattern('/wp-login.php', DefaultPatterns::LIST));
        $this->assertSame('/wp-login.php', Rules::matchedPattern('/wp-login.php', DefaultPatterns::WORDPRESS_PROBES));
    }
}
