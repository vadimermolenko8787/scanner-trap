<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ScannerTrap\Rules;
use ScannerTrap\TrustedProxies;

final class TrustedProxiesTest extends TestCase
{
    public function test_every_cloudflare_range_is_a_valid_entry(): void
    {
        $this->assertNotSame([], TrustedProxies::CLOUDFLARE);
        foreach (TrustedProxies::CLOUDFLARE as $range) {
            $this->assertNull(Rules::allowEntryError($range), $range);
        }
    }
}
