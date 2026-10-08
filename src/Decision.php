<?php

declare(strict_types=1);

namespace ScannerTrap;

/** What Guard decided for one request, and why. */
final class Decision
{
    /** Loopback or no usable client address: the store was not asked. */
    public const NO_CLIENT = 'no-client';
    /** The store's lists could not be read: let through, logged. */
    public const UNUSABLE = 'unusable';
    public const WHITELISTED = 'whitelisted';
    /** Blacklisted earlier. */
    public const BLOCKED = 'blocked';
    public const NO_MATCH = 'no-match';
    /** A decoy requested on behalf of another site: refused, never blocked. */
    public const CROSS_SITE = 'cross-site';
    /** A decoy: the IP is blacklisted now. */
    public const TRAPPED = 'trapped';

    public function __construct(
        public readonly bool $refuse,
        public readonly string $reason,
        public readonly ?string $pattern = null,
        public readonly bool $recorded = false,
    ) {
    }
}
