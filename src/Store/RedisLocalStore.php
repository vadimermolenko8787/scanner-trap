<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Escalation;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Network;
use ScannerTrap\Redis\RedisConnection;
use ScannerTrap\Snapshot;

/** Keys {prefix}block:<ip>, net:<cidr>, netlens (set of prefix tokens), lh:<source>:<generation> (list entries), lists (source => status), lists:seq, patterns, allow, events (stream), owner, sync-lock. One EVAL per request. */
final class RedisLocalStore implements LocalStore
{
    private const EVENTS_MAX_LENGTH = '10000';
    /**
     * ARGV: prefix, then token/cidr pairs of the IP's networks. Network blocks are looked up at the lengths in netlens,
     * list entries per active source at that source's lengths.
     */
    private const READ_SCRIPT = <<<'LUA'
        local reply = {redis.call('EXISTS', KEYS[1]), redis.call('GET', KEYS[2]), redis.call('GET', KEYS[3]), false, false}
        local candidates = {}
        for i = 2, #ARGV, 2 do candidates[ARGV[i]] = ARGV[i + 1] end
        for _, token in ipairs(redis.call('SMEMBERS', KEYS[4])) do
            local cidr = candidates[token]
            if cidr and redis.call('EXISTS', ARGV[1] .. 'net:' .. cidr) == 1 then reply[4] = cidr break end
        end
        local lists = redis.call('HGETALL', KEYS[5])
        for j = 1, #lists, 2 do
            local ok, info = pcall(cjson.decode, lists[j + 1])
            if ok and type(info) == 'table' and type(info.lens) == 'table' and info.gen then
                local key = ARGV[1] .. 'lh:' .. lists[j] .. ':' .. info.gen
                for _, token in ipairs(info.lens) do
                    local cidr = candidates[token]
                    if cidr and redis.call('HEXISTS', key, cidr) == 1 then reply[5] = lists[j] break end
                end
            end
            if reply[5] then break end
        end
        return reply
        LUA;
    /**
     * KEYS: lists, the new generation's hash. ARGV: source, status JSON ('' removes the source), prefix, generation.
     * Generations only grow: a switch to one that is not newer than the stored one frees its own hash and changes nothing.
     */
    private const SWITCH_SCRIPT = <<<'LUA'
        local old = redis.call('HGET', KEYS[1], ARGV[1])
        local oldGen
        if old then
            local ok, info = pcall(cjson.decode, old)
            if ok and type(info) == 'table' and tonumber(info.gen) then oldGen = tonumber(info.gen) end
        end
        if oldGen and oldGen >= tonumber(ARGV[4]) then
            redis.call('UNLINK', KEYS[2])
            return 0
        end
        if ARGV[2] == '' then
            redis.call('HDEL', KEYS[1], ARGV[1])
            redis.call('UNLINK', KEYS[2])
        else
            redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
        end
        if oldGen then redis.call('UNLINK', ARGV[3] .. 'lh:' .. ARGV[1] .. ':' .. string.format('%d', oldGen)) end
        return 1
        LUA;
    private const LIST_CHUNK = 5000;
    /** Of a scanner's parallel requests only the one whose SET created the key records an event. ARGV: 1 block JSON, 2 TTL, 3 record event, 4 stream cap, 5 netlens token or '', 6 escalate, 7 IP, 8 now, 9 window, 10 threshold, 11 network block JSON, 12 network TTL, 13 network token; KEYS 4 and 5 (counter, network key) only with escalation. */
    private const BLOCK_SCRIPT = <<<'LUA'
        local created
        if tonumber(ARGV[2]) > 0 then created = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
        else created = redis.call('SET', KEYS[1], ARGV[1], 'NX') end
        if not created then return 0 end
        if ARGV[5] ~= '' then redis.call('SADD', KEYS[3], ARGV[5]) end
        if ARGV[3] == '1' then redis.call('XADD', KEYS[2], 'MAXLEN', '~', ARGV[4], '*', 'data', ARGV[1]) end
        if ARGV[6] == '1' then
            redis.call('ZADD', KEYS[4], ARGV[8], ARGV[7])
            redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', tonumber(ARGV[8]) - tonumber(ARGV[9]))
            redis.call('EXPIRE', KEYS[4], ARGV[9])
            if redis.call('ZCARD', KEYS[4]) >= tonumber(ARGV[10]) then
                local net
                if tonumber(ARGV[12]) > 0 then net = redis.call('SET', KEYS[5], ARGV[11], 'NX', 'EX', ARGV[12])
                else net = redis.call('SET', KEYS[5], ARGV[11], 'NX') end
                if net then
                    redis.call('SADD', KEYS[3], ARGV[13])
                    if ARGV[3] == '1' then redis.call('XADD', KEYS[2], 'MAXLEN', '~', ARGV[4], '*', 'data', ARGV[11]) end
                end
            end
        end
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
        $reply = $this->redis->eval(self::READ_SCRIPT, [$this->key('block:' . $ip), $this->key('patterns'), $this->key('allow'), $this->key('netlens'), $this->key('lists')], $args);
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

    public function addBlock(Block $block, bool $recordEvent, ?Escalation $escalation = null): bool
    {
        $now = time();
        if ($block->expiresAt !== 0 && $block->expiresAt <= $now) {
            return false;
        }
        $keys = [$this->targetKey($block->ip), $this->key('events'), $this->key('netlens')];
        $args = [$this->json($block->toArray()), (string) $block->ttl($now), $recordEvent ? '1' : '0', self::EVENTS_MAX_LENGTH, $block->isNetwork() ? (string) Network::parse($block->ip)?->token() : '', '0'];
        if ($escalation !== null && !$block->isNetwork()) {
            $network = Block::forNetwork($block, $escalation->network);
            $keys[] = $this->key('seen:' . $escalation->network);
            $keys[] = $this->key('net:' . $escalation->network);
            $args[5] = '1';
            array_push($args, $block->ip, (string) $now, (string) $escalation->window, (string) $escalation->threshold, $this->json($network->toArray()), (string) $network->ttl($now), $escalation->token);
        }
        return $this->redis->eval(self::BLOCK_SCRIPT, $keys, $args) === 1;
    }

    public function blocks(): array
    {
        $blocks = [];
        foreach (array_chunk([...$this->scanKeys($this->key('block:*')), ...$this->scanKeys($this->key('net:*'))], 500) as $keys) {
            $values = $this->redis->raw('MGET', ...$keys);
            foreach (is_array($values) ? $values : [] as $value) {
                $data = is_string($value) ? json_decode($value, true) : null;
                $block = is_array($data) ? Block::fromArray($data) : null;
                if ($block !== null && $block->isActive(time())) {
                    $blocks[] = $block;
                }
            }
        }
        return $blocks;
    }

    public function removeBlock(string $target): void
    {
        // A network's escalation counter goes with it, or the next single hit would block the network again
        $this->redis->raw('DEL', $this->targetKey($target), ...(str_contains($target, '/') ? [$this->key('seen:' . $target)] : []));
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

    /** No command holds Redis for long: the new generation is written in chunks, then switched to in one short script. */
    public function replaceList(string $source, array $networks, int $at): void
    {
        if (preg_match('/^[a-z][a-z0-9-]{0,31}\z/', $source) !== 1) {
            throw new \InvalidArgumentException("Not a list source name: {$source}");
        }
        $wanted = [];
        foreach ($networks as $cidr) {
            $network = Network::parse($cidr);
            if ($network !== null) {
                $wanted[$network->cidr()] = $network->token();
            }
        }
        $generation = $this->redis->raw('INCR', $this->key('lists:seq'));
        $generation = is_int($generation) ? $generation : 0;
        $hash = $this->key("lh:{$source}:{$generation}");
        foreach (array_chunk(array_keys($wanted), self::LIST_CHUNK) as $chunk) {
            $fields = [];
            foreach ($chunk as $cidr) {
                array_push($fields, (string) $cidr, '1');
            }
            $this->redis->raw('HSET', $hash, ...$fields);
        }
        $lens = array_values(array_unique($wanted));
        sort($lens);
        $status = $wanted === [] ? '' : $this->json(['gen' => $generation, 'count' => count($wanted), 'at' => $at, 'lens' => $lens]);
        $this->redis->eval(self::SWITCH_SCRIPT, [$this->key('lists'), $hash], [$source, $status, $this->prefix, (string) $generation]);
        // A crashed earlier import may have left a generation behind; a newer one may be another import's active list
        $stem = $this->key("lh:{$source}:");
        foreach ($this->scanKeys($stem . '*') as $key) {
            $older = substr($key, strlen($stem));
            if (ctype_digit($older) && (int) $older < $generation) {
                $this->redis->raw('UNLINK', $key);
            }
        }
    }

    public function listStatus(): array
    {
        $reply = $this->redis->raw('HGETALL', $this->key('lists'));
        $pairs = is_array($reply) ? array_values($reply) : [];
        $status = [];
        for ($i = 0; $i + 1 < count($pairs); $i += 2) {
            $data = is_string($pairs[$i + 1]) ? json_decode($pairs[$i + 1], true) : null;
            if (is_string($pairs[$i]) && is_array($data) && is_int($data['count'] ?? null) && is_int($data['at'] ?? null)) {
                $status[$pairs[$i]] = ['count' => $data['count'], 'at' => $data['at']];
            }
        }
        ksort($status);
        return $status;
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

    /** TTLs expire everything. */
    public function prune(int $before): int
    {
        return 0;
    }

    public function marker(): ?array
    {
        $value = $this->redis->raw('GET', $this->key('owner'));
        $data = is_string($value) ? json_decode($value, true) : null;
        if (!is_array($data) || !is_string($data['owner'] ?? null) || !is_int($data['version'] ?? null)) {
            return null;
        }
        return ['owner' => $data['owner'], 'version' => $data['version'], 'listsVersion' => is_int($data['listsVersion'] ?? null) ? $data['listsVersion'] : -1];
    }

    public function saveMarker(string $owner, int $version, int $listsVersion = -1): void
    {
        $this->redis->raw('SET', $this->key('owner'), $this->json(['owner' => $owner, 'version' => $version, 'listsVersion' => $listsVersion]));
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

    /** @return list<string> the keys matching $match */
    private function scanKeys(string $match): array
    {
        $found = [];
        $cursor = '0';
        do {
            $reply = $this->redis->raw('SCAN', $cursor, 'MATCH', $match, 'COUNT', '500');
            if (!is_array($reply) || !is_string($reply[0] ?? null) || !is_array($reply[1] ?? null)) {
                throw new StoreException('Unexpected reply to SCAN');
            }
            [$cursor, $keys] = $reply;
            array_push($found, ...array_filter($keys, 'is_string'));
        } while ($cursor !== '0');
        return array_values(array_unique($found));
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
