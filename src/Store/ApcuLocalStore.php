<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Escalation;
use ScannerTrap\Network;
use ScannerTrap\Snapshot;

/** One PHP server only: APCu keys with TTL, no events, so never part of mode 3. */
final class ApcuLocalStore implements LocalStore
{
    public function __construct(private readonly string $prefix = 'scanner-trap:')
    {
    }

    public function read(string $ip): Snapshot
    {
        $family = str_contains($ip, ':') ? 6 : 4;
        $keys = [$this->key('block:' . $ip), $this->key('patterns'), $this->key('allow')];
        for ($prefix = 0; $prefix <= ($family === 4 ? 32 : 128); $prefix++) {
            $keys[] = $this->key("netlen:{$family}/{$prefix}");
        }
        $values = apcu_fetch($keys);
        $values = is_array($values) ? $values : [];
        [$network, $listed] = $this->matchNetworks($ip, $values);
        $patterns = $values[$this->key('patterns')] ?? null;
        $allow = $values[$this->key('allow')] ?? null;
        return Snapshot::decode(
            $network !== null || $this->active($values[$this->key('block:' . $ip)] ?? null) !== null,
            is_string($patterns) ? $patterns : null,
            is_string($allow) ? $allow : null,
            $network,
            $listed,
        );
    }

    public function addBlock(Block $block, bool $recordEvent, ?Escalation $escalation = null): bool
    {
        $key = $this->targetKey($block->ip);
        if (!$block->isActive(time())) {
            return false;
        }
        // apc.use_request_time can keep an expired entry alive inside a long CLI run
        if ($this->active(apcu_fetch($key)) === null) {
            apcu_delete($key);
        }
        $created = apcu_add($key, $this->json($block->toArray()), $block->ttl(time()));
        if ($created && $block->isNetwork()) {
            apcu_store($this->key('netlen:' . Network::parse($block->ip)?->token()), 1);
        }
        if ($created && $escalation !== null && !$block->isNetwork()) {
            $seenKey = $this->key('seen:' . $escalation->network);
            $seen = apcu_fetch($seenKey);
            $seen = is_array($seen) ? array_filter($seen, 'is_int') : [];
            $seen[$block->ip] = $block->blockedAt;
            $seen = array_filter($seen, static fn (int $at): bool => $at > time() - $escalation->window);
            // Read-modify-write: two racing hits may count as one, escalating one hit later
            apcu_store($seenKey, $seen, $escalation->window);
            if (count($seen) >= $escalation->threshold) {
                $this->addBlock(Block::forNetwork($block, $escalation->network), false);
            }
        }
        return $created;
    }

    public function blocks(): array
    {
        $blocks = [];
        foreach (new \APCUIterator('/^' . preg_quote($this->prefix, '/') . '(block|net):/') as $item) {
            $block = is_array($item) ? $this->active($item['value'] ?? null) : null;
            if ($block !== null) {
                $blocks[] = $block;
            }
        }
        return $blocks;
    }

    public function removeBlock(string $target): void
    {
        apcu_delete($this->targetKey($target));
        // A network's escalation counter goes with it, or the next single hit would block the network again
        if (str_contains($target, '/')) {
            apcu_delete($this->key('seen:' . $target));
        }
    }

    public function patterns(): ?array
    {
        $value = apcu_fetch($this->key('patterns'));
        $snapshot = Snapshot::decode(false, is_string($value) ? $value : null, '[]');
        return $snapshot->corrupt ? [] : $snapshot->patterns;
    }

    public function allow(): ?array
    {
        $value = apcu_fetch($this->key('allow'));
        $snapshot = Snapshot::decode(false, '[]', is_string($value) ? $value : null);
        return $snapshot->corrupt ? [] : $snapshot->allow;
    }

    public function replaceLists(array $patterns, array $allow): void
    {
        apcu_store([
            $this->key('patterns') => $this->json($patterns),
            $this->key('allow') => $this->json(array_map(static fn (AllowEntry $e): array => $e->toArray(), $allow)),
        ]);
    }

    public function events(int $limit): array
    {
        return [];
    }

    public function ackEvents(array $ids): void
    {
    }

    public function waitForEvents(int $seconds): bool
    {
        if ($seconds > 0) {
            sleep($seconds);
        }
        return false;
    }

    public function replaceList(string $source, array $networks, int $at): void
    {
        if (preg_match('/^[a-z][a-z0-9-]{0,31}\z/', $source) !== 1) {
            throw new \InvalidArgumentException("Not a list source name: {$source}");
        }
        $wanted = [];
        foreach ($networks as $cidr) {
            $network = Network::parse($cidr);
            if ($network !== null) {
                $wanted[$network->cidr()] = $network;
            }
        }
        // New entries first, removals after: a reader may see a superset for an instant, never a gap
        foreach ($wanted as $cidr => $network) {
            $sources = apcu_fetch($this->key('lnet:' . $cidr));
            $sources = is_array($sources) ? $sources : [];
            if (!in_array($source, $sources, true)) {
                $sources[] = $source;
                apcu_store($this->key('lnet:' . $cidr), $sources);
            }
            apcu_store($this->key('netlen:' . $network->token()), 1);
        }
        $old = apcu_fetch($this->key('list:' . $source));
        foreach (is_array($old) ? $old : [] as $cidr) {
            if (!is_string($cidr) || isset($wanted[$cidr])) {
                continue;
            }
            $sources = apcu_fetch($this->key('lnet:' . $cidr));
            $sources = array_values(array_filter(is_array($sources) ? $sources : [], static fn (mixed $name): bool => $name !== $source));
            if ($sources === []) {
                apcu_delete($this->key('lnet:' . $cidr));
            } else {
                apcu_store($this->key('lnet:' . $cidr), $sources);
            }
        }
        $status = apcu_fetch($this->key('lists'));
        $status = is_array($status) ? $status : [];
        if ($wanted === []) {
            apcu_delete($this->key('list:' . $source));
            unset($status[$source]);
        } else {
            apcu_store($this->key('list:' . $source), array_keys($wanted));
            $status[$source] = ['count' => count($wanted), 'at' => $at];
        }
        apcu_store($this->key('lists'), $status);
    }

    public function listStatus(): array
    {
        $status = apcu_fetch($this->key('lists'));
        $result = [];
        foreach (is_array($status) ? $status : [] as $source => $entry) {
            if (is_string($source) && is_array($entry) && is_int($entry['count'] ?? null) && is_int($entry['at'] ?? null)) {
                $result[$source] = ['count' => $entry['count'], 'at' => $entry['at']];
            }
        }
        ksort($result);
        return $result;
    }

    public function marker(): ?array
    {
        $value = apcu_fetch($this->key('owner'));
        $data = is_string($value) ? json_decode($value, true) : null;
        if (!is_array($data) || !is_string($data['owner'] ?? null) || !is_int($data['version'] ?? null)) {
            return null;
        }
        return ['owner' => $data['owner'], 'version' => $data['version'], 'listsVersion' => is_int($data['listsVersion'] ?? null) ? $data['listsVersion'] : -1];
    }

    public function saveMarker(string $owner, int $version, int $listsVersion = -1): void
    {
        apcu_store($this->key('owner'), $this->json(['owner' => $owner, 'version' => $version, 'listsVersion' => $listsVersion]));
    }

    public function lock(int $seconds): bool
    {
        return apcu_add($this->key('sync-lock'), 1, max(1, $seconds));
    }

    public function unlock(): void
    {
        apcu_delete($this->key('sync-lock'));
    }

    /**
     * @param array<mixed> $values the first fetch, holding the netlen keys that exist
     * @return array{?string, ?string}
     */
    private function matchNetworks(string $ip, array $values): array
    {
        $wanted = [];
        foreach (Network::candidates($ip) as $token => $cidr) {
            if (array_key_exists($this->key("netlen:{$token}"), $values)) {
                $wanted[$cidr] = [$this->key('net:' . $cidr), $this->key('lnet:' . $cidr)];
            }
        }
        if ($wanted === []) {
            return [null, null];
        }
        $found = apcu_fetch(array_merge(...array_values($wanted)));
        $found = is_array($found) ? $found : [];
        $network = null;
        $listed = null;
        foreach ($wanted as $cidr => [$netKey, $listKey]) {
            if ($network === null && $this->active($found[$netKey] ?? null) !== null) {
                $network = $cidr;
            }
            $sources = $found[$listKey] ?? null;
            if ($listed === null && is_array($sources) && is_string(reset($sources))) {
                $listed = reset($sources);
            }
        }
        return [$network, $listed];
    }

    private function targetKey(string $target): string
    {
        return $this->key((str_contains($target, '/') ? 'net:' : 'block:') . $target);
    }

    /** The stored block when it is still in force, else null. */
    private function active(mixed $value): ?Block
    {
        $data = is_string($value) ? json_decode($value, true) : null;
        $block = is_array($data) ? Block::fromArray($data) : null;
        return $block !== null && $block->isActive(time()) ? $block : null;
    }

    private function key(string $name): string
    {
        return $this->prefix . $name;
    }

    /** @param array<mixed> $data */
    private function json(array $data): string
    {
        return (string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
