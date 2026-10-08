<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Snapshot;

/**
 * A directory: one file per blocked IP, JSON lists, an append-only event log. The lists are decoded once per process
 * and re-read only when the file behind them changes (inode, mtime or size: replaceLists() renames a new file in).
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

    /** @var array<string, array{string, ?string}> path => [stat key, contents] */
    private static array $cache = [];
    /** @var resource|null */
    private $lock = null;

    public function __construct(private readonly string $dir)
    {
    }

    public function read(string $ip): Snapshot
    {
        return Snapshot::decode($this->isBlocked($ip), $this->cached(self::PATTERNS), $this->cached(self::ALLOW));
    }

    public function addBlock(Block $block, bool $recordEvent): bool
    {
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
        return $blocks;
    }

    public function removeBlock(string $ip): void
    {
        @unlink($this->blockFile($ip));
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
