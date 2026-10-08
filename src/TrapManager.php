<?php

declare(strict_types=1);

namespace ScannerTrap;

use Psr\Log\LoggerInterface;
use ScannerTrap\Central\CentralStore;
use ScannerTrap\Exception\RefusedException;
use ScannerTrap\Store\ApcuLocalStore;
use ScannerTrap\Store\LocalStore;

/**
 * Every management action, for the CLI and for framework bridges. With a central store every write goes there and is
 * followed by a pull, so this server applies it at once and the others on their next sync; without one it goes to the
 * local store.
 */
final class TrapManager
{
    /**
     * @param list<string> $configPatterns
     * @param list<string> $configAllow
     * @param list<string> $ownPaths
     */
    public function __construct(
        private readonly LocalStore $local,
        private readonly ?CentralStore $central,
        private readonly array $configPatterns,
        private readonly array $configAllow,
        private readonly array $ownPaths = [],
        private readonly string $serverName = '',
        private readonly int $blockTtl = 604800,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /** Mode 3: tables, owner id, seeded lists, then a pull. Modes 1 and 2: the config's lists into the local store. */
    public function install(string $by): void
    {
        $this->assertManageable();
        $patterns = array_values(array_unique(array_map(Rules::normalizePattern(...), $this->configPatterns)));
        $allow = $this->configAllowEntries($by);
        if ($this->central !== null) {
            $this->central->install($patterns, $allow, $by);
            $this->syncer()->pull();
            return;
        }
        $this->local->replaceLists($patterns, $allow);
    }

    public function sync(int $watchSeconds = 0): bool
    {
        if ($this->central === null) {
            throw new RefusedException('No central store is configured: sync is for several servers with a central database');
        }
        return $this->syncer()->run($watchSeconds);
    }

    /** @return list<Block> */
    public function blocks(bool $activeOnly = true, ?string $ip = null): array
    {
        $this->assertManageable();
        if ($this->central !== null) {
            return $this->central->blocks($activeOnly, $ip);
        }
        $ip = $ip === null ? null : (Rules::normalizeIp($ip) ?? $ip);
        return array_values(array_filter($this->local->blocks(), static fn (Block $b): bool => $ip === null || $b->ip === $ip));
    }

    public function block(string $ip, string $reason, ?int $ttl, string $by): Block
    {
        $this->assertManageable();
        $normalized = Rules::normalizeIp(trim($ip)) ?? throw new RefusedException("{$ip} is not an IP address");
        if (Rules::isAllowed($normalized, array_map(static fn (AllowEntry $e): string => $e->entry, $this->allowEntries()))) {
            throw new RefusedException("{$normalized} is on the whitelist, which wins over any block; remove the entry first");
        }
        $ttl ??= $this->blockTtl;
        $now = time();
        $block = new Block($normalized, $now, $ttl > 0 ? $now + $ttl : 0, $this->serverName, '', '', trim($reason) !== '' ? trim($reason) : "manual by {$by}", '', Block::SOURCE_MANUAL);
        if ($this->central !== null) {
            if ($this->central->blocks(true, $normalized) !== []) {
                throw new RefusedException("{$normalized} is already blocked");
            }
            $this->central->insertBlocks([$block]);
            $this->syncer()->pull();
        } elseif (!$this->local->addBlock($block, false)) {
            throw new RefusedException("{$normalized} is already blocked");
        }
        $this->logger?->notice('Scanner trap: {ip} blocked by {by}', ['ip' => $normalized, 'by' => $by]);
        return $block;
    }

    /** Ships this server's waiting events first, or a later push would bring the block back. */
    public function unblock(string $ip, string $by): int
    {
        $this->assertManageable();
        $normalized = Rules::normalizeIp(trim($ip)) ?? throw new RefusedException("{$ip} is not an IP address");
        if ($this->central !== null) {
            $sync = $this->syncer();
            $sync->push();
            $lifted = $this->central->lift($normalized, $by);
            $this->local->removeBlock($normalized);
            $sync->pull();
            return $lifted;
        }
        $known = $this->local->read($normalized)->blocked;
        $this->local->removeBlock($normalized);
        return $known ? 1 : 0;
    }

    /** @return list<string> */
    public function patterns(): array
    {
        $this->assertManageable();
        return $this->central !== null ? $this->central->patterns() : $this->localPatterns();
    }

    public function addPattern(string $pattern, string $by): string
    {
        $this->assertManageable();
        $pattern = Rules::normalizePattern($pattern);
        $error = Rules::patternError($pattern, $this->ownPaths);
        if ($error !== null) {
            throw new RefusedException($error);
        }
        if ($this->central !== null) {
            if (!$this->central->addPattern($pattern, $by)) {
                throw new RefusedException("{$pattern} is already on the list");
            }
            $this->syncer()->pull();
            return $pattern;
        }
        $patterns = $this->localPatterns();
        if (in_array($pattern, $patterns, true)) {
            throw new RefusedException("{$pattern} is already on the list");
        }
        $this->local->replaceLists([...$patterns, $pattern], $this->localAllow());
        return $pattern;
    }

    public function removePattern(string $pattern): void
    {
        $this->assertManageable();
        $pattern = Rules::normalizePattern($pattern);
        if ($this->central !== null) {
            if (!$this->central->removePattern($pattern)) {
                throw new RefusedException("{$pattern} is not on the list");
            }
            $this->syncer()->pull();
            return;
        }
        $patterns = $this->localPatterns();
        if (!in_array($pattern, $patterns, true)) {
            throw new RefusedException("{$pattern} is not on the list");
        }
        $this->local->replaceLists(array_values(array_diff($patterns, [$pattern])), $this->localAllow());
    }

    /** @return list<AllowEntry> */
    public function allowEntries(): array
    {
        $this->assertManageable();
        if ($this->central !== null) {
            return $this->central->allowEntries();
        }
        return array_values(array_filter($this->localAllow(), static fn (AllowEntry $e): bool => $e->isActive(time())));
    }

    /** $ttl in seconds, null = kept until removed. Adding an existing entry sets its comment and term anew. */
    public function addAllow(string $entry, string $comment, ?int $ttl, string $by): AllowEntry
    {
        $this->assertManageable();
        $entry = trim($entry);
        $error = Rules::allowEntryError($entry);
        if ($error !== null) {
            throw new RefusedException($error);
        }
        $allow = new AllowEntry($entry, trim($comment), $ttl === null || $ttl <= 0 ? 0 : time() + $ttl, $by);
        if ($this->central !== null) {
            $this->central->saveAllow($allow);
            $this->syncer()->pull();
            return $allow;
        }
        $kept = array_filter($this->localAllow(), static fn (AllowEntry $e): bool => $e->entry !== $entry);
        $this->local->replaceLists($this->localPatterns(), [...array_values($kept), $allow]);
        return $allow;
    }

    public function removeAllow(string $entry): void
    {
        $this->assertManageable();
        $entry = trim($entry);
        if ($this->central !== null) {
            if (!$this->central->removeAllow($entry)) {
                throw new RefusedException("{$entry} is not on the whitelist");
            }
            $this->syncer()->pull();
            return;
        }
        $allow = $this->localAllow();
        $kept = array_values(array_filter($allow, static fn (AllowEntry $e): bool => $e->entry !== $entry));
        if (count($kept) === count($allow)) {
            throw new RefusedException("{$entry} is not on the whitelist");
        }
        $this->local->replaceLists($this->localPatterns(), $kept);
    }

    private function syncer(): Sync
    {
        return new Sync($this->local, $this->central ?? throw new \LogicException('No central store'), $this->logger);
    }

    /** @return list<string> the stored list, or the config's while none is stored (Decision 1) */
    private function localPatterns(): array
    {
        return $this->local->patterns() ?? array_values(array_unique(array_map(Rules::normalizePattern(...), $this->configPatterns)));
    }

    /** @return list<AllowEntry> */
    private function localAllow(): array
    {
        return $this->local->allow() ?? $this->configAllowEntries('config');
    }

    /** @return list<AllowEntry> */
    private function configAllowEntries(string $by): array
    {
        $entries = [];
        foreach ($this->configAllow as $entry) {
            if (Rules::allowEntryError(trim($entry)) === null) {
                $entries[] = new AllowEntry(trim($entry), 'config', 0, $by);
            }
        }
        return $entries;
    }

    private function assertManageable(): void
    {
        if ($this->central === null && $this->local instanceof ApcuLocalStore) {
            throw new RefusedException('The APCu store lives inside the web server and this process cannot reach it; change patterns and allow in the config instead');
        }
    }
}
