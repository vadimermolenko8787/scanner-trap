<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Network;
use ScannerTrap\Redis\RedisConnection;
use ScannerTrap\Snapshot;

/** Keys {prefix}block:<ip>, net:<cidr>, netlens (set of prefix tokens), patterns, allow, events (stream), owner, sync-lock. One EVAL per request. */
final class RedisLocalStore implements LocalStore
{
    private const EVENTS_MAX_LENGTH = '10000';
    /** ARGV: prefix, then token/cidr pairs of the IP's networks; only tokens in netlens are looked up. Reply slot 5 (list source) is filled in Task 5. */
    private const READ_SCRIPT = <<<'LUA'
        local reply = {redis.call('EXISTS', KEYS[1]), redis.call('GET', KEYS[2]), redis.call('GET', KEYS[3]), false, false}
        local lens = redis.call('SMEMBERS', KEYS[4])
        if #lens == 0 then return reply end
        local wanted = {}
        for _, token in ipairs(lens) do wanted[token] = true end
        for i = 2, #ARGV, 2 do
            if wanted[ARGV[i]] then
                local cidr = ARGV[i + 1]
                if redis.call('EXISTS', ARGV[1] .. 'net:' .. cidr) == 1 then reply[4] = cidr break end
            end
        end
        return reply
        LUA;
    /** Of a scanner's parallel requests only the one whose SET created the key records an event. ARGV[5]: netlens token or ''. */
    private const BLOCK_SCRIPT = <<<'LUA'
        local created
        if tonumber(ARGV[2]) > 0 then created = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
        else created = redis.call('SET', KEYS[1], ARGV[1], 'NX') end
        if not created then return 0 end
        if ARGV[5] ~= '' then redis.call('SADD', KEYS[3], ARGV[5]) end
        if ARGV[3] == '1' then redis.call('XADD', KEYS[2], 'MAXLEN', '~', ARGV[4], '*', 'data', ARGV[1]) end
        return 1
        LUA;
    private const UNLOCK_SCRIPT = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0";

    private ?string $lockToken = null;

    public function __construct(private readonly RedisConnection $redis, private readonly string $prefix = 'scanner-trap:')
    {
    }

    public function read(string $ip): Snapshot
    {
        $args = [$this->prefix];
        foreach (Network::candidates($ip) as $token => $cidr) {
            $args[] = $token;
            $args[] = $cidr;
        }
        $reply = $this->redis->eval(self::READ_SCRIPT, [$this->key('block:' . $ip), $this->key('patterns'), $this->key('allow'), $this->key('netlens')], $args);
        if (!is_array($reply) || count($reply) !== 5) {
            throw new StoreException('Unexpected reply to the read script');
        }
        [$blocked, $patterns, $allow, $network, $listed] = $reply;
        return Snapshot::decode(
            $blocked === 1 || is_string($network),
            is_string($patterns) ? $patterns : null,
            is_string($allow) ? $allow : null,
            is_string($network) ? $network : null,
            is_string($listed) ? $listed : null,
        );
    }

    public function addBlock(Block $block, bool $recordEvent): bool
    {
        if ($block->expiresAt !== 0 && $block->expiresAt <= time()) {
            return false;
        }
        $created = $this->redis->eval(
            self::BLOCK_SCRIPT,
            [$this->targetKey($block->ip), $this->key('events'), $this->key('netlens')],
            [$this->json($block->toArray()), (string) $block->ttl(time()), $recordEvent ? '1' : '0', self::EVENTS_MAX_LENGTH, $block->isNetwork() ? (string) Network::parse($block->ip)?->token() : ''],
        );
        return $created === 1;
    }

    public function blocks(): array
    {
        return [...$this->scanBlocks($this->key('block:*')), ...$this->scanBlocks($this->key('net:*'))];
    }

    public function removeBlock(string $target): void
    {
        $this->redis->raw('DEL', $this->targetKey($target));
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

    /** @return list<Block> the active blocks under the keys matching $match */
    private function scanBlocks(string $match): array
    {
        $blocks = [];
        $cursor = '0';
        do {
            $reply = $this->redis->raw('SCAN', $cursor, 'MATCH', $match, 'COUNT', '500');
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

    private function targetKey(string $target): string
    {
        return $this->key((str_contains($target, '/') ? 'net:' : 'block:') . $target);
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
