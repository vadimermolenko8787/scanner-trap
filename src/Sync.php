<?php

declare(strict_types=1);

namespace ScannerTrap;

use Psr\Log\LoggerInterface;
use ScannerTrap\Central\CentralStore;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Store\LocalStore;

/**
 * Keeps one server's local store and the central store in step: push() ships the blocks made here, pull() brings every
 * server's blocks (addresses and networks), the patterns, the whitelist and the imported lists back.
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
        private readonly ?SubnetPolicy $subnets = null,
    ) {
    }

    /** Returns how many events were shipped. An event leaves the local store only after its batch is inserted. */
    public function push(): int
    {
        $this->assertOwner();
        $pushed = 0;
        $previous = null;
        while (($events = $this->local->events(self::BATCH)) !== []) {
            if (array_keys($events) === $previous) {
                throw new StoreException('The local store did not drop the events it shipped; nothing more was pushed');
            }
            $previous = array_keys($events);
            $this->central->insertBlocks(array_values($events));
            $this->local->ackEvents(array_map('strval', $previous));
            $pushed += count($events);
            // Per batch: once acked, a batch's hits are gone locally and a later failure must not lose them
            $hits = array_filter($events, static fn (Block $event): bool => $event->source === Block::SOURCE_TRAP && !$event->isNetwork());
            if ($hits !== []) {
                $this->escalateCentrally(array_values($hits));
            }
        }
        if ($pushed > 0) {
            $this->logger?->info('Scanner trap: pushed {count} block events', ['count' => $pushed]);
        }
        return $pushed;
    }

    /**
     * The local stores escalate from their own hits only; here hits of the same network on different servers add up.
     *
     * @param list<Block> $hits
     */
    private function escalateCentrally(array $hits): void
    {
        if ($this->subnets === null) {
            return;
        }
        $newest = [];
        $thresholds = [];
        foreach ($hits as $hit) {
            $escalation = $this->subnets->escalationFor($hit->ip);
            if ($escalation === null) {
                continue;
            }
            $known = $newest[$escalation->network] ?? null;
            if ($known === null || $known->blockedAt <= $hit->blockedAt) {
                $newest[$escalation->network] = $hit;
                $thresholds[$escalation->network] = $escalation->threshold;
            }
        }
        if ($newest === []) {
            return;
        }
        // Hits from before a network's latest lift do not count: an operator's unblock starts that network's count afresh
        $liftedAt = [];
        foreach (array_keys($newest) as $network) {
            $liftedAt[$network] = $this->central->blocks(false, (string) $network, 1)[0]->liftedAt ?? 0;
        }
        $counts = [];
        foreach ($this->central->recentTrapIps(time() - $this->subnets->window()) as $ip => $blockedAt) {
            $network = $this->subnets->escalationFor((string) $ip)?->network;
            if ($network !== null && isset($liftedAt[$network]) && $blockedAt > $liftedAt[$network]) {
                $counts[$network] = ($counts[$network] ?? 0) + 1;
            }
        }
        foreach ($newest as $network => $hit) {
            if (($counts[$network] ?? 0) >= $thresholds[$network] && $this->central->blocks(true, (string) $network) === []) {
                $this->central->insertBlocks([Block::forNetwork($hit, (string) $network)]);
                $this->logger?->info('Scanner trap: {network} blocked after hits from several servers', ['network' => $network]);
            }
        }
    }

    public function pull(): void
    {
        $owner = $this->assertOwner();
        $marker = $this->local->marker();
        $version = $this->central->version();
        $listsVersion = $this->central->listsVersion();
        if ($marker === null || $marker['version'] !== $version) {
            $this->local->replaceLists($this->central->patterns(), $this->central->allowEntries());
        }
        if ($marker === null || $marker['listsVersion'] !== $listsVersion) {
            $this->pullLists();
        }
        if ($marker === null || $marker['version'] !== $version || $marker['listsVersion'] !== $listsVersion) {
            $this->local->saveMarker($owner, $version, $listsVersion);
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

    /** One source at a time: a large list never sits in memory together with the others. */
    private function pullLists(): void
    {
        $status = $this->central->listStatus();
        foreach ($status as $source => $entry) {
            $this->local->replaceList($source, $this->central->listEntries($source), $entry['at']);
        }
        foreach (array_keys(array_diff_key($this->local->listStatus(), $status)) as $source) {
            $this->local->replaceList((string) $source, [], time());
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
