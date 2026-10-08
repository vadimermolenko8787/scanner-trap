<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Network;
use ScannerTrap\Snapshot;

/**
 * A directory: one file per blocked IP, JSON lists, an append-only event log. The lists are decoded once per process
 * and re-read only when the file behind them changes (inode, mtime or size: replaceLists() renames a new file in).
 * Networks live in a PHP file returning an array, renamed under a new name on every write (networks.current points to
 * it): opcache serves it from memory, and a new name is seen even with opcache.validate_timestamps=0.
 *
 * @phpstan-type NetworkData array{blocks: array<int, array<int, array<string, array<mixed>>>>}
 */
final class FileLocalStore implements LocalStore
{
    private const BLOCKS = 'blocks';
    private const LOCKS = 'locks';
    private const PATTERNS = 'patterns.json';
    private const ALLOW = 'allow.json';
    private const EVENTS = 'events.log';
    private const OWNER = 'owner';
    private const LOCK = 'sync.lock';
    private const NETWORKS = 'networks.current';
    private const NETWORKS_LOCK = 'networks.lock';
    private const NETWORKS_KEEP = 600;
    private const NO_NETWORKS = ['blocks' => []];

    /** @var array<string, array{string, ?string}> path => [stat key, contents] */
    private static array $cache = [];
    /** @var resource|null */
    private $lock = null;
    /** @var array{string, NetworkData}|null pointer => data of the last include */
    private ?array $networksCache = null;

    public function __construct(private readonly string $dir)
    {
    }

    public function read(string $ip): Snapshot
    {
        try {
            $network = $this->matchNetworks($this->networks(), $ip);
        } catch (StoreException) {
            return new Snapshot(false, null, null, true);
        }
        return Snapshot::decode($network !== null || $this->isBlocked($ip), $this->cached(self::PATTERNS), $this->cached(self::ALLOW), $network);
    }

    public function addBlock(Block $block, bool $recordEvent): bool
    {
        if ($block->isNetwork()) {
            $created = $this->addNetworkBlock($block);
            if ($created && $recordEvent) {
                $this->appendEvent($block);
            }
            return $created;
        }
        $file = $this->blockFile($block->ip);
        $this->ensureDir($this->dir . '/' . self::BLOCKS);
        $handle = @fopen($file, 'x');
        if ($handle === false && is_file($file) && $this->removeIfExpired($file)) {
            $handle = @fopen($file, 'x');
        }
        if ($handle === false) {
            if (is_file($file)) {
                return false;
            }
            throw new StoreException("Cannot create {$file}");
        }
        fwrite($handle, $this->json($block->toArray()));
        fclose($handle);
        if ($recordEvent) {
            $this->appendEvent($block);
        }
        return true;
    }

    public function blocks(): array
    {
        $blocks = [];
        foreach (glob($this->dir . '/' . self::BLOCKS . '/*') ?: [] as $file) {
            $block = $this->readBlock($file);
            if ($block !== null) {
                $blocks[] = $block;
            }
        }
        foreach ($this->networks()['blocks'] as $byPrefix) {
            foreach ($byPrefix as $entries) {
                foreach ($entries as $data) {
                    $block = Block::fromArray($data);
                    if ($block !== null && $block->isActive(time())) {
                        $blocks[] = $block;
                    }
                }
            }
        }
        return $blocks;
    }

    public function removeBlock(string $target): void
    {
        $network = str_contains($target, '/') ? Network::parse($target) : null;
        if ($network === null) {
            @unlink($this->blockFile($target));
            return;
        }
        $this->updateNetworks(static function (array $data) use ($network): ?array {
            if (!isset($data['blocks'][$network->family][$network->prefix][$network->address])) {
                return null;
            }
            unset($data['blocks'][$network->family][$network->prefix][$network->address]);
            return $data;
        });
    }

    public function patterns(): ?array
    {
        $snapshot = Snapshot::decode(false, $this->cached(self::PATTERNS), '[]');
        return $snapshot->corrupt ? [] : $snapshot->patterns;
    }

    public function allow(): ?array
    {
        $snapshot = Snapshot::decode(false, '[]', $this->cached(self::ALLOW));
        return $snapshot->corrupt ? [] : $snapshot->allow;
    }

    public function replaceLists(array $patterns, array $allow): void
    {
        $this->writeAtomically(self::PATTERNS, $this->json($patterns));
        $this->writeAtomically(self::ALLOW, $this->json(array_map(static fn (AllowEntry $e): array => $e->toArray(), $allow)));
    }

    public function events(int $limit): array
    {
        $events = [];
        $garbage = false;
        foreach ($this->eventLines() as $line) {
            $data = json_decode($line, true);
            $block = is_array($data) ? Block::fromArray($data) : null;
            if ($block === null) {
                $garbage = true;
            } elseif (count($events) < $limit) {
                $events[sha1($line)] = $block;
            }
        }
        if ($garbage) {
            $this->ackEvents([]);
        }
        return $events;
    }

    /** Also drops lines that are no event at all, so a broken line cannot stay forever. */
    public function ackEvents(array $ids): void
    {
        $file = $this->dir . '/' . self::EVENTS;
        $handle = @fopen($file, 'c+');
        if ($handle === false) {
            throw new StoreException("Cannot open {$file}");
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new StoreException("Cannot lock {$file}");
            }
            $acked = array_count_values($ids);
            $kept = [];
            foreach (explode("\n", (string) stream_get_contents($handle)) as $line) {
                $id = sha1($line);
                $data = json_decode($line, true);
                if ($line === '' || !is_array($data) || Block::fromArray($data) === null) {
                    continue;
                }
                if (($acked[$id] ?? 0) > 0) {
                    $acked[$id]--;
                    continue;
                }
                $kept[] = $line . "\n";
            }
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, implode('', $kept));
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    public function waitForEvents(int $seconds): bool
    {
        $deadline = time() + $seconds;
        $file = $this->dir . '/' . self::EVENTS;
        while (true) {
            clearstatcache(true, $file);
            if (is_file($file) && (int) filesize($file) > 0) {
                return true;
            }
            if (time() >= $deadline) {
                return false;
            }
            sleep(1);
        }
    }

    public function marker(): ?array
    {
        $data = json_decode((string) @file_get_contents($this->dir . '/' . self::OWNER), true);
        if (!is_array($data) || !is_string($data['owner'] ?? null) || !is_int($data['version'] ?? null)) {
            return null;
        }
        return ['owner' => $data['owner'], 'version' => $data['version']];
    }

    public function saveMarker(string $owner, int $version): void
    {
        $this->writeAtomically(self::OWNER, $this->json(['owner' => $owner, 'version' => $version]));
    }

    public function lock(int $seconds): bool
    {
        $this->ensureDir($this->dir);
        $handle = @fopen($this->dir . '/' . self::LOCK, 'c');
        if ($handle === false) {
            throw new StoreException("Cannot open the sync lock in {$this->dir}");
        }
        if (!flock($handle, LOCK_EX | LOCK_NB)) {
            fclose($handle);
            return false;
        }
        $this->lock = $handle;
        return true;
    }

    public function unlock(): void
    {
        if ($this->lock !== null) {
            flock($this->lock, LOCK_UN);
            fclose($this->lock);
            $this->lock = null;
        }
    }

    private function addNetworkBlock(Block $block): bool
    {
        $network = Network::parse($block->ip) ?? throw new StoreException("Not a network: {$block->ip}");
        return $this->updateNetworks(static function (array $data) use ($block, $network): ?array {
            $existing = $data['blocks'][$network->family][$network->prefix][$network->address] ?? null;
            if (is_array($existing) && Block::fromArray($existing)?->isActive(time())) {
                return null;
            }
            $data['blocks'][$network->family][$network->prefix][$network->address] = $block->toArray();
            return $data;
        });
    }

    /**
     * @param NetworkData $data
     * @return string|null the blocking network
     */
    private function matchNetworks(array $data, string $ip): ?string
    {
        $family = str_contains($ip, ':') ? 6 : 4;
        $network = null;
        foreach ($data['blocks'][$family] ?? [] as $prefix => $entries) {
            $candidate = Network::of($ip, $prefix);
            $entry = $candidate === null ? null : ($entries[$candidate->address] ?? null);
            if (is_array($entry) && Block::fromArray($entry)?->isActive(time())) {
                $network = $candidate?->cidr();
                break;
            }
        }
        return $network;
    }

    /** @return NetworkData */
    private function networks(bool $fresh = false): array
    {
        $pointer = @file_get_contents($this->dir . '/' . self::NETWORKS);
        if ($pointer === false) {
            return self::NO_NETWORKS;
        }
        $pointer = trim($pointer);
        if (!$fresh && $this->networksCache !== null && $this->networksCache[0] === $pointer) {
            return $this->networksCache[1];
        }
        $file = $this->dir . '/' . $pointer;
        if (preg_match('/^networks-[0-9a-f]{16}\.php$/', $pointer) !== 1 || !is_file($file)) {
            throw new StoreException('networks.current does not name a networks file');
        }
        try {
            $data = include $file;
        } catch (\Throwable $e) {
            throw new StoreException("Cannot read {$file}: {$e->getMessage()}", 0, $e);
        }
        if (!is_array($data) || !is_array($data['blocks'] ?? null)) {
            throw new StoreException("{$file} does not hold networks");
        }
        /** @var NetworkData $data */
        $this->networksCache = [$pointer, $data];
        return $data;
    }

    /**
     * Reads the networks afresh under the lock, applies $change and writes the result under a new name; a null from
     * $change means nothing changed. Expired network blocks are pruned on every write.
     *
     * @param \Closure(NetworkData): (NetworkData|null) $change
     */
    private function updateNetworks(\Closure $change): bool
    {
        $this->ensureDir($this->dir);
        $handle = @fopen($this->dir . '/' . self::NETWORKS_LOCK, 'c');
        if ($handle === false) {
            throw new StoreException("Cannot open the networks lock in {$this->dir}");
        }
        try {
            flock($handle, LOCK_EX);
            $data = $change($this->networks(true));
            if ($data === null) {
                return false;
            }
            foreach ($data['blocks'] as $family => $byPrefix) {
                foreach ($byPrefix as $prefix => $entries) {
                    foreach ($entries as $address => $entry) {
                        if (Block::fromArray($entry)?->isActive(time()) !== true) {
                            unset($data['blocks'][$family][$prefix][$address]);
                        }
                    }
                }
            }
            $previous = trim((string) @file_get_contents($this->dir . '/' . self::NETWORKS));
            $name = 'networks-' . bin2hex(random_bytes(8)) . '.php';
            $this->writeAtomically($name, '<?php return ' . var_export($data, true) . ";\n");
            $this->writeAtomically(self::NETWORKS, $name);
            // The previous file stops being current now: its 10 minutes start here, not when it was written
            @touch($this->dir . '/' . $previous);
            $this->networksCache = null;
            foreach (glob($this->dir . '/networks-*.php') ?: [] as $old) {
                if (basename($old) !== $name && (int) @filemtime($old) < time() - self::NETWORKS_KEEP) {
                    @unlink($old);
                }
            }
            return true;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function isBlocked(string $ip): bool
    {
        $file = $this->blockFile($ip);
        if (!is_file($file)) {
            return false;
        }
        return !$this->isExpired($file) || !$this->removeIfExpired($file);
    }

    private function isExpired(string $file): bool
    {
        $data = json_decode((string) @file_get_contents($file), true);
        // A file being written right now is still empty: it is a block all the same
        $expires = is_array($data) && is_int($data['expiresAt'] ?? null) ? $data['expiresAt'] : 0;
        return $expires !== 0 && $expires <= time();
    }

    /**
     * The only place an expired block file is deleted. Under a per-IP lock the file is read again, so a fresh block
     * another process has created meanwhile is never deleted. True when the file is gone, false when it is a live block.
     */
    private function removeIfExpired(string $file): bool
    {
        $this->ensureDir($this->dir . '/' . self::LOCKS);
        $handle = @fopen($this->dir . '/' . self::LOCKS . '/' . basename($file), 'c');
        if ($handle === false) {
            throw new StoreException("Cannot open a block lock in {$this->dir}");
        }
        try {
            flock($handle, LOCK_EX);
            if (!is_file($file)) {
                return true;
            }
            if (!$this->isExpired($file)) {
                return false;
            }
            @unlink($file);
            return true;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function readBlock(string $file): ?Block
    {
        $data = json_decode((string) @file_get_contents($file), true);
        $block = is_array($data) ? Block::fromArray($data) : null;
        if ($block !== null && !$block->isActive(time())) {
            $this->removeIfExpired($file);
            return null;
        }
        return $block;
    }

    private function blockFile(string $ip): string
    {
        return $this->dir . '/' . self::BLOCKS . '/' . sha1($ip);
    }

    private function appendEvent(Block $block): void
    {
        $file = $this->dir . '/' . self::EVENTS;
        if (@file_put_contents($file, $this->json($block->toArray()) . "\n", FILE_APPEND | LOCK_EX) === false) {
            throw new StoreException("Cannot append to {$file}");
        }
    }

    /** @return list<string> */
    private function eventLines(): array
    {
        $handle = @fopen($this->dir . '/' . self::EVENTS, 'r');
        if ($handle === false) {
            return [];
        }
        try {
            flock($handle, LOCK_SH);
            return array_values(array_filter(explode("\n", (string) stream_get_contents($handle)), static fn (string $l): bool => $l !== ''));
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function cached(string $name): ?string
    {
        $path = $this->dir . '/' . $name;
        clearstatcache(true, $path);
        $stat = @stat($path);
        if ($stat === false) {
            unset(self::$cache[$path]);
            return null;
        }
        $key = $stat['ino'] . ':' . $stat['mtime'] . ':' . $stat['size'];
        if ((self::$cache[$path][0] ?? null) !== $key) {
            $contents = @file_get_contents($path);
            self::$cache[$path] = [$key, $contents === false ? null : $contents];
        }
        return self::$cache[$path][1];
    }

    private function writeAtomically(string $name, string $contents): void
    {
        $this->ensureDir($this->dir);
        $path = $this->dir . '/' . $name;
        $temp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($temp, $contents) === false || !@rename($temp, $path)) {
            @unlink($temp);
            throw new StoreException("Cannot write {$path}");
        }
    }

    private function ensureDir(string $dir): void
    {
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new StoreException("Cannot create the directory {$dir}");
        }
    }

    /** @param array<mixed> $data */
    private function json(array $data): string
    {
        return (string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
