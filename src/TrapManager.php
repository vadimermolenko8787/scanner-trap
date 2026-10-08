<?php

declare(strict_types=1);

namespace ScannerTrap;

use Psr\Log\LoggerInterface;
use ScannerTrap\Central\CentralStore;
use ScannerTrap\Exception\RefusedException;
use ScannerTrap\Exception\StoreException;
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
     * @param list<ListSource> $listSources
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
        private readonly ?SubnetPolicy $subnets = null,
        private readonly array $listSources = [],
        private readonly ListImporter $importer = new ListImporter(),
    ) {
    }

    /** Mode 3: tables, owner id, seeded lists, then a pull. Modes 1 and 2: the config's lists into the local store. */
    public function install(string $by): void
    {
        $this->assertManageable();
        $patterns = [];
        $problems = [];
        foreach ($this->configPatternErrors() as $pattern => $error) {
            if ($error === null) {
                $patterns[] = $pattern;
            } else {
                $problems[] = "\"{$pattern}\": {$error}";
            }
        }
        if ($problems !== []) {
            throw new RefusedException("The config's patterns are invalid, nothing was installed:\n" . implode("\n", $problems));
        }
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

    /** @return list<Block> with $ip: the exact block and every network block containing it */
    public function blocks(bool $activeOnly = true, ?string $ip = null): array
    {
        $this->assertManageable();
        $all = $this->central !== null ? $this->central->blocks($activeOnly, null, 1_000_000) : $this->local->blocks();
        if ($ip === null) {
            return $all;
        }
        $target = self::target($ip) ?? $ip;
        return array_values(array_filter($all, static fn (Block $b): bool => $b->ip === $target
            || ($b->isNetwork() && !str_contains($target, '/') && Network::parse($b->ip)?->contains($target) === true)));
    }

    public function block(string $ip, string $reason, ?int $ttl, string $by): Block
    {
        $this->assertManageable();
        $target = self::target($ip) ?? throw new RefusedException("{$ip} is not an IP address or a network");
        $network = str_contains($target, '/') ? Network::parse($target) : null;
        if ($network !== null && $network->isReserved()) {
            throw new RefusedException("{$target} is a private or reserved network; block single addresses there");
        }
        foreach ($this->allowEntries() as $allow) {
            $entry = $allow->entry;
            $allowed = Network::parse($entry);
            $covers = $network === null
                ? Rules::isAllowed($target, [$entry])
                : ($allowed !== null ? $network->overlaps($allowed) : Rules::isAllowed($network->address, [$entry]));
            if ($covers) {
                throw new RefusedException("{$target} covers the whitelist entry {$entry}, which wins over any block; remove the entry first");
            }
        }
        $ttl ??= $this->blockTtl;
        $now = time();
        $block = new Block($target, $now, $ttl > 0 ? $now + $ttl : 0, $this->serverName, '', '', trim($reason) !== '' ? trim($reason) : "manual by {$by}", '', Block::SOURCE_MANUAL);
        if ($this->central !== null) {
            if ($this->central->blocks(true, $target) !== []) {
                throw new RefusedException("{$target} is already blocked");
            }
            $this->central->insertBlocks([$block]);
            $this->syncer()->pull();
        } elseif (!$this->local->addBlock($block, false)) {
            throw new RefusedException("{$target} is already blocked");
        }
        $this->logger?->notice('Scanner trap: {ip} blocked by {by}', ['ip' => $target, 'by' => $by]);
        return $block;
    }

    /** Ships this server's waiting events first, or a later push would bring the block back. */
    public function unblock(string $ip, string $by): int
    {
        $this->assertManageable();
        $target = self::target($ip) ?? throw new RefusedException("{$ip} is not an IP address or a network");
        if ($this->central !== null) {
            $sync = $this->syncer();
            $sync->push();
            $lifted = $this->central->lift($target, $by);
            $this->local->removeBlock($target);
            $sync->pull();
            return $lifted;
        }
        $known = in_array($target, array_map(static fn (Block $b): string => $b->ip, $this->local->blocks()), true);
        $this->local->removeBlock($target);
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

    /** @return array<string, array{networks: int, invalid: int, reserved: int, tooWide: int, error: ?string}> */
    public function import(?string $source = null): array
    {
        $this->assertManageable();
        $sources = array_values(array_filter($this->listSources, static fn (ListSource $s): bool => $source === null || $s->name === $source));
        if ($sources === []) {
            throw new RefusedException($source === null ? 'No list sources are configured (the lists key)' : "No list source {$source} in the config");
        }
        $report = [];
        foreach ($sources as $list) {
            try {
                $result = $this->importer->import($list);
                $this->replaceList($list->name, $result['networks']);
                $report[$list->name] = ['networks' => count($result['networks']), 'invalid' => $result['invalid'], 'reserved' => $result['reserved'], 'tooWide' => $result['tooWide'], 'error' => null];
            } catch (StoreException|RefusedException $e) {
                $report[$list->name] = ['networks' => 0, 'invalid' => 0, 'reserved' => 0, 'tooWide' => 0, 'error' => $e->getMessage()];
            }
        }
        if ($source === null) {
            $configured = array_map(static fn (ListSource $s): string => $s->name, $this->listSources);
            foreach (array_keys($this->storedListStatus()) as $stale) {
                if (!in_array($stale, $configured, true)) {
                    $this->replaceList((string) $stale, []);
                }
            }
        }
        if ($this->central !== null) {
            $this->syncer()->pull();
        }
        return $report;
    }

    /** @return array<string, array{count: int, at: int, configured: bool}> */
    public function lists(): array
    {
        $this->assertManageable();
        $lists = [];
        foreach ($this->storedListStatus() as $name => $status) {
            $lists[$name] = $status + ['configured' => false];
        }
        foreach ($this->listSources as $source) {
            $lists[$source->name] = ['count' => $lists[$source->name]['count'] ?? 0, 'at' => $lists[$source->name]['at'] ?? 0, 'configured' => true];
        }
        ksort($lists);
        return $lists;
    }

    /** @param list<string> $networks */
    private function replaceList(string $name, array $networks): void
    {
        if ($this->central !== null) {
            $this->central->replaceList($name, $networks, time());
        } else {
            $this->local->replaceList($name, $networks, time());
        }
    }

    /** @return array<string, array{count: int, at: int}> */
    private function storedListStatus(): array
    {
        return $this->central !== null ? $this->central->listStatus() : $this->local->listStatus();
    }

    /** An IP or a CIDR as Block stores it, null for anything else. */
    private static function target(string $value): ?string
    {
        $value = trim($value);
        return str_contains($value, '/') ? Network::parse($value)?->cidr() : Rules::normalizeIp($value);
    }

    private function syncer(): Sync
    {
        return new Sync($this->local, $this->central ?? throw new \LogicException('No central store'), $this->logger, $this->subnets);
    }

    /** @return list<string> the stored list, or the config's while none is stored (Decision 1) */
    private function localPatterns(): array
    {
        return $this->local->patterns() ?? array_keys(array_filter($this->configPatternErrors(), static fn (?string $error): bool => $error === null));
    }

    /** @return array<string, ?string> each distinct normalized config pattern with the reason it is invalid, or null */
    private function configPatternErrors(): array
    {
        $errors = [];
        foreach ($this->configPatterns as $pattern) {
            $pattern = Rules::normalizePattern($pattern);
            $errors[$pattern] = Rules::patternError($pattern, $this->ownPaths);
        }
        return $errors;
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
