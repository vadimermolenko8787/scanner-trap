<?php

declare(strict_types=1);

namespace ScannerTrap;

/** What a store needs to escalate one trap hit to its network. */
final class Escalation
{
    public function __construct(
        public readonly string $network,
        public readonly string $token,
        public readonly int $threshold,
        public readonly int $window,
    ) {
    }
}
