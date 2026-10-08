<?php

declare(strict_types=1);

namespace ScannerTrap\Central;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;

/** The source of truth in mode 3: every server's blocks, the patterns, the whitelist and the imported lists. Failures are StoreExceptions. */
interface CentralStore
{
    /**
     * Creates missing tables, the owner id and the version; seeds patterns into an empty table and adds missing entries.
     *
     * @param list<string> $patterns
     * @param list<AllowEntry> $allow
     */
    public function install(array $patterns, array $allow, string $by): void;

    /** The random id `install` generated; a StoreException when the store is not installed. */
    public function owner(): string;

    /** Bumped by every pattern or whitelist change. */
    public function version(): int;

    /** @param list<Block> $blocks merged into the IP's active block when there is one */
    public function insertBlocks(array $blocks): void;

    /** @return list<Block> newest first; `$ip` may be an IP or a CIDR */
    public function blocks(bool $activeOnly = true, ?string $ip = null, int $limit = 1000): array;

    /** @return list<Block> every network block (the active ones, or with `$activeOnly` false the history too), newest first */
    public function networkBlocks(bool $activeOnly = true): array;

    /** Lifts every active block of the IP or CIDR; returns how many. */
    public function lift(string $ip, string $by): int;

    /** @return list<string> enabled and valid patterns, oldest first */
    public function patterns(): array;

    /** False when the pattern is already there. */
    public function addPattern(string $pattern, string $by): bool;

    public function removePattern(string $pattern): bool;

    /** @return list<AllowEntry> entries in force and valid */
    public function allowEntries(): array;

    /** Inserts the entry, or updates its comment, expiry and author. */
    public function saveAllow(AllowEntry $entry): void;

    public function removeAllow(string $entry): bool;

    /**
     * Makes exactly `$networks` (normalized CIDRs) the entries of the source, all stamped `imported_at = $at`, in one
     * transaction. True, and `listsVersion` incremented, only when the set changed.
     *
     * @param list<string> $networks
     */
    public function replaceList(string $source, array $networks, int $at): bool;

    /** @return list<string> the CIDRs of one source, sorted */
    public function listEntries(string $source): array;

    /** @return array<string, array{count: int, at: int}> per source: entries and last import time */
    public function listStatus(): array;

    /** Incremented by every list change; 0 when never imported. */
    public function listsVersion(): int;

    /** @return array<string, int> distinct addresses (not networks) with an active trap block since `$since`, each with the time of its latest one */
    public function recentTrapIps(int $since): array;
}
