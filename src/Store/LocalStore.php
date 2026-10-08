<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Snapshot;

/** This server's copy of the blacklist and lists; Guard reads it once per request. Every failure is a StoreException. */
interface LocalStore
{
    /** One round trip: is the IP blocked, the patterns, the whitelist. */
    public function read(string $ip): Snapshot;

    /**
     * Blocks $block->ip until $block->expiresAt (0 = forever) and, when $recordEvent, queues the block as an event, both
     * atomically: of several parallel calls for one IP exactly one returns true and queues an event.
     */
    public function addBlock(Block $block, bool $recordEvent): bool;

    /** @return list<Block> the active blocks */
    public function blocks(): array;

    public function removeBlock(string $ip): void;

    /** @return list<string>|null null = never stored */
    public function patterns(): ?array;

    /** @return list<AllowEntry>|null null = never stored */
    public function allow(): ?array;

    /**
     * @param list<string> $patterns
     * @param list<AllowEntry> $allow
     */
    public function replaceLists(array $patterns, array $allow): void;

    /** @return array<string, Block> queued events by id, oldest first, at most $limit */
    public function events(int $limit): array;

    /** @param list<string> $ids */
    public function ackEvents(array $ids): void;

    /** Waits up to $seconds for a queued event; true as soon as there is one. */
    public function waitForEvents(int $seconds): bool;

    /** @return array{owner: string, version: int}|null the central store this one follows, and the lists' version */
    public function marker(): ?array;

    public function saveMarker(string $owner, int $version): void;

    /** The sync lock; false when another process holds it. A store may hold it until unlock() or until the holder exits (file store) rather than for exactly $seconds. */
    public function lock(int $seconds): bool;

    public function unlock(): void;
}
