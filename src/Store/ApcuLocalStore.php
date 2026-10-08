<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Snapshot;

/** One PHP server only: APCu keys with TTL, no events, so never part of mode 3. */
final class ApcuLocalStore implements LocalStore
{
    public function __construct(private readonly string $prefix = 'scanner-trap:')
    {
    }

    public function read(string $ip): Snapshot
    {
        $values = apcu_fetch([$this->key('block:' . $ip), $this->key('patterns'), $this->key('allow')]);
        $values = is_array($values) ? $values : [];
        $patterns = $values[$this->key('patterns')] ?? null;
        $allow = $values[$this->key('allow')] ?? null;
        return Snapshot::decode(
            $this->active($values[$this->key('block:' . $ip)] ?? null) !== null,
            is_string($patterns) ? $patterns : null,
            is_string($allow) ? $allow : null,
        );
    }

    public function addBlock(Block $block, bool $recordEvent): bool
    {
        $key = $this->key('block:' . $block->ip);
        if (!$block->isActive(time())) {
            return false;
        }
        // apc.use_request_time can keep an expired entry alive inside a long CLI run
        if ($this->active(apcu_fetch($key)) === null) {
            apcu_delete($key);
        }
        return apcu_add($key, $this->json($block->toArray()), $block->ttl(time()));
    }

    public function blocks(): array
    {
        $blocks = [];
        foreach (new \APCUIterator('/^' . preg_quote($this->key('block:'), '/') . '/') as $item) {
            $block = is_array($item) ? $this->active($item['value'] ?? null) : null;
            if ($block !== null) {
                $blocks[] = $block;
            }
        }
        return $blocks;
    }

    public function removeBlock(string $ip): void
    {
        apcu_delete($this->key('block:' . $ip));
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

    public function marker(): ?array
    {
        $value = apcu_fetch($this->key('owner'));
        $data = is_string($value) ? json_decode($value, true) : null;
        if (!is_array($data) || !is_string($data['owner'] ?? null) || !is_int($data['version'] ?? null)) {
            return null;
        }
        return ['owner' => $data['owner'], 'version' => $data['version']];
    }

    public function saveMarker(string $owner, int $version): void
    {
        apcu_store($this->key('owner'), $this->json(['owner' => $owner, 'version' => $version]));
    }

    public function lock(int $seconds): bool
    {
        return apcu_add($this->key('sync-lock'), 1, max(1, $seconds));
    }

    public function unlock(): void
    {
        apcu_delete($this->key('sync-lock'));
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
