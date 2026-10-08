<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Escalation;
use ScannerTrap\Snapshot;

/**
 * This server's copy of the blacklist and lists; Guard reads it once per request. Every failure is a StoreException.
 *
 * @phpstan-type Marker array{owner: string, version: int, listsVersion: int, lastId: int, fullAt: int, pulledAt: int}
 */
interface LocalStore
{
    /** One round trip: is the IP blocked (by itself or a network), is it listed, the patterns, the whitelist. */
    public function read(string $ip): Snapshot;

    /**
     * Blocks $block->ip, an IP or a network, until $block->expiresAt (0 = forever) and, when $recordEvent, queues the block as
     * an event, both atomically: of several parallel calls for one IP exactly one returns true and queues an event.
     * With $escalation, an IP block created here also counts its IP for the escalation network and blocks that network
     * (source subnet, with its event) once the threshold is reached within the window.
     */
    public function addBlock(Block $block, bool $recordEvent, ?Escalation $escalation = null): bool;

    /** @return list<Block> the active blocks */
    public function blocks(): array;

    public function removeBlock(string $target): void;

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

    /**
     * Makes $networks (normalized CIDRs) exactly the networks listing $source; readers switch from the old set to the
     * new one in one step (APCu: a superset for an instant). [] removes the source. A network stays listed while any
     * source lists it.
     *
     * @param list<string> $networks
     */
    public function replaceList(string $source, array $networks, int $at): void;

    /** @return array<string, array{count: int, at: int}> every source with entries: their number and the import time */
    public function listStatus(): array;

    /** Removes what expiry left behind before $before (file store); returns how many files. Stores with TTLs return 0. */
    public function prune(int $before): int;

    /**
     * The central store this one follows, the patterns' and the lists' versions applied, the highest central block id
     * applied (-1: none), the last full pass and the last pull (0: never). Absent keys get those defaults (lists' version
     * -1), so a marker stored before they existed makes the next pull a full one.
     *
     * @return Marker|null
     */
    public function marker(): ?array;

    /** @param Marker $marker */
    public function saveMarker(array $marker): void;

    /** The sync lock; false when another process holds it. A store may hold it until unlock() or until the holder exits (file store) rather than for exactly $seconds. */
    public function lock(int $seconds): bool;

    public function unlock(): void;
}
