<?php

declare(strict_types=1);

namespace ScannerTrap;

use Psr\Log\LoggerInterface;
use ScannerTrap\Central\CentralStore;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Store\LocalStore;

/**
 * Keeps one server's local store and the central store in step: push() ships the blocks made here, pull() brings every
 * server's blocks, the patterns and the whitelist back.
 */
final class Sync
{
    private const BATCH = 200;
    private const ALL = 1_000_000;
    private const WAIT_SLICE = 5;

    public function __construct(
        private readonly LocalStore $local,
        private readonly CentralStore $central,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /** Returns how many events were shipped. An event leaves the local store only after its batch is inserted. */
    public function push(): int
    {
        $this->assertOwner();
        $pushed = 0;
        while (($events = $this->local->events(self::BATCH)) !== []) {
            $this->central->insertBlocks(array_values($events));
            $this->local->ackEvents(array_map('strval', array_keys($events)));
            $pushed += count($events);
        }
        if ($pushed > 0) {
            $this->logger?->info('Scanner trap: pushed {count} block events', ['count' => $pushed]);
        }
        return $pushed;
    }

    public function pull(): void
    {
        $owner = $this->assertOwner();
        $marker = $this->local->marker();
        $version = $this->central->version();
        if ($marker === null || $marker['version'] !== $version) {
            $this->local->replaceLists($this->central->patterns(), $this->central->allowEntries());
            $this->local->saveMarker($owner, $version);
        }

        $central = [];
        foreach ($this->central->blocks(true, null, self::ALL) as $block) {
            $known = $central[$block->ip] ?? null;
            if ($known === null || $known->expiresAt !== 0 && ($block->expiresAt === 0 || $block->expiresAt > $known->expiresAt)) {
                $central[$block->ip] = $block;
            }
        }
        $local = [];
        foreach ($this->local->blocks() as $block) {
            $local[$block->ip] = $block;
        }
        foreach (array_diff_key($central, $local) as $block) {
            $this->local->addBlock($block, false);
        }
        // Blocked here after this run's push: their events are still waiting, the central store cannot know them yet
        $pending = [];
        foreach ($this->local->events(self::ALL) as $event) {
            $pending[$event->ip] = true;
        }
        foreach (array_keys(array_diff_key($local, $central, $pending)) as $ip) {
            $this->local->removeBlock((string) $ip);
        }
    }

    /** Two installations with different central stores on one Redis would overwrite each other's lists every minute */
    private function assertOwner(): string
    {
        $owner = $this->central->owner();
        $marker = $this->local->marker();
        if ($marker !== null && $marker['owner'] !== $owner) {
            throw new StoreException("This local store follows another central store ({$marker['owner']}), not {$owner}; nothing was written");
        }
        return $owner;
    }

    /** One sync run: push, pull, then push new events as they come until $watchSeconds pass. False when already running. */
    public function run(int $watchSeconds = 0): bool
    {
        if (!$this->local->lock($watchSeconds + 60)) {
            return false;
        }
        try {
            $this->push();
            $this->pull();
            $deadline = time() + $watchSeconds;
            while (($left = $deadline - time()) > 0) {
                if ($this->local->waitForEvents(min($left, self::WAIT_SLICE))) {
                    $this->push();
                }
            }
        } finally {
            $this->local->unlock();
        }
        return true;
    }
}
