<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Redis\RedisConnection;
use ScannerTrap\Snapshot;

/** Keys {prefix}block:<ip>, patterns, allow, events (stream), owner, sync-lock. One EVAL per request. */
final class RedisLocalStore implements LocalStore
{
    private const EVENTS_MAX_LENGTH = '10000';
    private const READ_SCRIPT = "return {redis.call('EXISTS', KEYS[1]), redis.call('GET', KEYS[2]), redis.call('GET', KEYS[3])}";
    /** Of a scanner's parallel requests only the one whose SET created the key records an event. */
    private const BLOCK_SCRIPT = "local created "
        . "if tonumber(ARGV[2]) > 0 then created = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2]) "
        . "else created = redis.call('SET', KEYS[1], ARGV[1], 'NX') end "
        . "if not created then return 0 end "
        . "if ARGV[3] == '1' then redis.call('XADD', KEYS[2], 'MAXLEN', '~', ARGV[4], '*', 'data', ARGV[1]) end "
        . "return 1";
    private const UNLOCK_SCRIPT = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0";

    private ?string $lockToken = null;

    public function __construct(private readonly RedisConnection $redis, private readonly string $prefix = 'scanner-trap:')
    {
    }

    public function read(string $ip): Snapshot
    {
        $reply = $this->redis->eval(self::READ_SCRIPT, [$this->key('block:' . $ip), $this->key('patterns'), $this->key('allow')], []);
        if (!is_array($reply) || count($reply) !== 3) {
            throw new StoreException('Unexpected reply to the read script');
        }
        [$blocked, $patterns, $allow] = $reply;
        return Snapshot::decode($blocked === 1, is_string($patterns) ? $patterns : null, is_string($allow) ? $allow : null);
    }

    public function addBlock(Block $block, bool $recordEvent): bool
    {
        $ttl = $block->ttl(time());
        if ($block->expiresAt !== 0 && $block->expiresAt <= time()) {
            return false;
        }
        $created = $this->redis->eval(
            self::BLOCK_SCRIPT,
            [$this->key('block:' . $block->ip), $this->key('events')],
            [$this->json($block->toArray()), (string) $ttl, $recordEvent ? '1' : '0', self::EVENTS_MAX_LENGTH],
        );
        return $created === 1;
    }

    public function blocks(): array
    {
        $blocks = [];
        $cursor = '0';
        do {
            $reply = $this->redis->raw('SCAN', $cursor, 'MATCH', $this->key('block:*'), 'COUNT', '500');
            if (!is_array($reply) || !is_string($reply[0] ?? null) || !is_array($reply[1] ?? null)) {
                throw new StoreException('Unexpected reply to SCAN');
            }
            [$cursor, $keys] = $reply;
            if ($keys !== []) {
                $values = $this->redis->raw('MGET', ...array_filter($keys, 'is_string'));
                foreach (is_array($values) ? $values : [] as $value) {
                    $data = is_string($value) ? json_decode($value, true) : null;
                    $block = is_array($data) ? Block::fromArray($data) : null;
                    if ($block !== null && $block->isActive(time())) {
                        $blocks[] = $block;
                    }
                }
            }
        } while ($cursor !== '0');
        return $blocks;
    }

    public function removeBlock(string $ip): void
    {
        $this->redis->raw('DEL', $this->key('block:' . $ip));
    }

    public function patterns(): ?array
    {
        $value = $this->redis->raw('GET', $this->key('patterns'));
        $snapshot = Snapshot::decode(false, is_string($value) ? $value : null, '[]');
        return $snapshot->corrupt ? [] : $snapshot->patterns;
    }

    public function allow(): ?array
    {
        $value = $this->redis->raw('GET', $this->key('allow'));
        $snapshot = Snapshot::decode(false, '[]', is_string($value) ? $value : null);
        return $snapshot->corrupt ? [] : $snapshot->allow;
    }

    public function replaceLists(array $patterns, array $allow): void
    {
        $this->redis->raw(
            'MSET',
            $this->key('patterns'),
            $this->json($patterns),
            $this->key('allow'),
            $this->json(array_map(static fn (AllowEntry $e): array => $e->toArray(), $allow)),
        );
    }

    public function events(int $limit): array
    {
        $entries = $this->redis->raw('XRANGE', $this->key('events'), '-', '+', 'COUNT', (string) $limit);
        $events = [];
        $broken = [];
        foreach (is_array($entries) ? $entries : [] as $entry) {
            $id = is_array($entry) && is_string($entry[0] ?? null) ? $entry[0] : null;
            $fields = is_array($entry) && is_array($entry[1] ?? null) ? $entry[1] : [];
            $data = ($fields[0] ?? null) === 'data' && is_string($fields[1] ?? null) ? json_decode($fields[1], true) : null;
            $block = is_array($data) ? Block::fromArray($data) : null;
            if ($id === null) {
                continue;
            }
            if ($block === null) {
                $broken[] = $id;
                continue;
            }
            $events[$id] = $block;
        }
        $this->ackEvents($broken);
        return $events;
    }

    public function ackEvents(array $ids): void
    {
        if ($ids !== []) {
            $this->redis->raw('XDEL', $this->key('events'), ...$ids);
        }
    }

    /** Reading from id 0 answers at once while the stream holds anything, and push() empties it, so nothing is missed. */
    public function waitForEvents(int $seconds): bool
    {
        $block = $seconds > 0 ? ['BLOCK', (string) ($seconds * 1000)] : [];
        $reply = $this->redis->raw('XREAD', 'COUNT', '1', ...$block, ...['STREAMS', $this->key('events'), '0']);
        // A timeout is a nil array: Predis returns null, phpredis an empty array.
        return $reply !== null && $reply !== [];
    }

    public function marker(): ?array
    {
        $value = $this->redis->raw('GET', $this->key('owner'));
        $data = is_string($value) ? json_decode($value, true) : null;
        if (!is_array($data) || !is_string($data['owner'] ?? null) || !is_int($data['version'] ?? null)) {
            return null;
        }
        return ['owner' => $data['owner'], 'version' => $data['version']];
    }

    public function saveMarker(string $owner, int $version): void
    {
        $this->redis->raw('SET', $this->key('owner'), $this->json(['owner' => $owner, 'version' => $version]));
    }

    public function lock(int $seconds): bool
    {
        $token = bin2hex(random_bytes(8));
        if ($this->redis->raw('SET', $this->key('sync-lock'), $token, 'NX', 'EX', (string) max(1, $seconds)) === null) {
            return false;
        }
        $this->lockToken = $token;
        return true;
    }

    public function unlock(): void
    {
        if ($this->lockToken !== null) {
            $this->redis->eval(self::UNLOCK_SCRIPT, [$this->key('sync-lock')], [$this->lockToken]);
            $this->lockToken = null;
        }
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
