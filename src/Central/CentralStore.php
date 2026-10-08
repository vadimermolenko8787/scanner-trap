<?php

declare(strict_types=1);

namespace ScannerTrap\Central;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;

/** The source of truth in mode 3: every server's blocks, the patterns and the whitelist. Failures are StoreExceptions. */
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

    /** @return list<Block> newest first */
    public function blocks(bool $activeOnly = true, ?string $ip = null, int $limit = 1000): array;

    /** Lifts every active block of the IP; returns how many. */
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
}
