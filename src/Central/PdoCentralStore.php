<?php

declare(strict_types=1);

namespace ScannerTrap\Central;

use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Exception\StoreException;
use ScannerTrap\Rules;

/**
 * Tables {prefix}block, pattern, allow, meta. One active block per IP, kept portably: an event first looks for the IP's
 * active row and extends it. Two servers racing may leave two active rows; readers treat the IP as blocked if any is.
 */
final class PdoCentralStore implements CentralStore
{
    private readonly string $driver;

    public function __construct(private readonly \PDO $pdo, private readonly string $prefix = 'scanner_trap_')
    {
        if (preg_match('/^[a-z0-9_]*$/i', $prefix) !== 1) {
            throw new \InvalidArgumentException('A table prefix may hold letters, digits and _ only');
        }
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $driver = $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        $this->driver = is_string($driver) ? $driver : '';
        PdoSchema::statements($this->driver, $prefix); // refuses an unsupported driver now rather than at install
    }

    public static function connect(string $dsn, ?string $user, ?string $password, string $prefix = 'scanner_trap_'): self
    {
        try {
            return new self(new \PDO($dsn, $user, $password, [\PDO::ATTR_TIMEOUT => 5]), $prefix);
        } catch (\PDOException $e) {
            throw new StoreException('Central database unreachable: ' . $e->getMessage(), 0, $e);
        }
    }

    public function install(array $patterns, array $allow, string $by): void
    {
        // DDL first and outside the transaction: MySQL commits implicitly on CREATE TABLE
        $this->guarded(function (): void {
            foreach (PdoSchema::statements($this->driver, $this->prefix) as $sql) {
                $this->pdo->exec($sql);
            }
        });
        $this->transaction(function () use ($patterns, $allow, $by): void {
            if ($this->meta('owner') === null) {
                $this->execute("INSERT INTO {$this->prefix}meta (name, value) VALUES ('owner', ?)", [bin2hex(random_bytes(16))]);
            }
            if ($this->meta('version') === null) {
                $this->execute("INSERT INTO {$this->prefix}meta (name, value) VALUES ('version', '0')", []);
            }
            if ((int) $this->scalar("SELECT COUNT(*) FROM {$this->prefix}pattern", []) === 0) {
                foreach ($patterns as $pattern) {
                    $this->insertPattern(Rules::normalizePattern($pattern), $by);
                }
            }
            foreach ($allow as $entry) {
                if ($this->scalar("SELECT id FROM {$this->prefix}allow WHERE entry = ?", [$entry->entry]) === null) {
                    $this->insertAllow($entry, $by);
                }
            }
            $this->bumpVersion();
        });
    }

    public function owner(): string
    {
        return $this->guarded(function (): string {
            $owner = $this->meta('owner');
            if ($owner === null) {
                throw new StoreException('The central store is not installed: run `scanner-trap install`');
            }
            return $owner;
        });
    }

    public function version(): int
    {
        return $this->guarded(fn (): int => (int) ($this->meta('version') ?? 0));
    }

    public function insertBlocks(array $blocks): void
    {
        $this->transaction(function () use ($blocks): void {
            foreach ($blocks as $block) {
                $row = $this->row(
                    "SELECT id, expires_at FROM {$this->prefix}block WHERE ip = ? AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > ?) ORDER BY id LIMIT 1",
                    [$block->ip, time()],
                );
                if ($row === null) {
                    $this->execute(
                        "INSERT INTO {$this->prefix}block (ip, blocked_at, expires_at, server, method, path, pattern, user_agent, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [$block->ip, $block->blockedAt, $block->expiresAt === 0 ? null : $block->expiresAt, $block->server, $block->method, $block->path, $block->pattern, $block->userAgent, $block->source],
                    );
                    continue;
                }
                $current = $row['expires_at'] === null ? 0 : (int) $row['expires_at'];
                $merged = ($current === 0 || $block->expiresAt === 0) ? 0 : max($current, $block->expiresAt);
                if ($merged !== $current) {
                    $this->execute("UPDATE {$this->prefix}block SET expires_at = ? WHERE id = ?", [$merged === 0 ? null : $merged, $row['id']]);
                }
            }
        });
    }

    public function blocks(bool $activeOnly = true, ?string $ip = null, int $limit = 1000): array
    {
        return $this->guarded(function () use ($activeOnly, $ip, $limit): array {
            $where = [];
            $params = [];
            if ($activeOnly) {
                $where[] = 'lifted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)';
                $params[] = time();
            }
            if ($ip !== null) {
                $where[] = 'ip = ?';
                $params[] = Rules::normalizeIp($ip) ?? $ip;
            }
            $sql = "SELECT * FROM {$this->prefix}block" . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . ' ORDER BY id DESC LIMIT ' . max(1, $limit);
            $blocks = [];
            foreach ($this->rows($sql, $params) as $row) {
                $block = Block::fromArray([
                    'ip' => $row['ip'], 'blockedAt' => $row['blocked_at'], 'expiresAt' => $row['expires_at'] ?? 0,
                    'server' => $row['server'], 'method' => $row['method'], 'path' => $row['path'], 'pattern' => $row['pattern'],
                    'userAgent' => $row['user_agent'], 'source' => $row['source'], 'liftedAt' => $row['lifted_at'], 'liftedBy' => $row['lifted_by'],
                ]);
                if ($block !== null) {
                    $blocks[] = $block;
                }
            }
            return $blocks;
        });
    }

    public function lift(string $ip, string $by): int
    {
        return $this->guarded(fn (): int => $this->execute(
            "UPDATE {$this->prefix}block SET lifted_at = ?, lifted_by = ? WHERE ip = ? AND lifted_at IS NULL",
            [time(), mb_substr($by, 0, 255), Rules::normalizeIp($ip) ?? $ip],
        ));
    }

    public function patterns(): array
    {
        return $this->guarded(function (): array {
            $patterns = [];
            foreach ($this->rows("SELECT pattern FROM {$this->prefix}pattern WHERE enabled = 1 ORDER BY id", []) as $row) {
                $pattern = Rules::normalizePattern((string) $row['pattern']);
                if (Rules::patternError($pattern) === null) {
                    $patterns[] = $pattern;
                }
            }
            return $patterns;
        });
    }

    public function addPattern(string $pattern, string $by): bool
    {
        return $this->transaction(function () use ($pattern, $by): bool {
            if ($this->scalar("SELECT id FROM {$this->prefix}pattern WHERE pattern = ?", [$pattern]) !== null) {
                return false;
            }
            $this->insertPattern($pattern, $by);
            $this->bumpVersion();
            return true;
        });
    }

    public function removePattern(string $pattern): bool
    {
        return $this->transaction(function () use ($pattern): bool {
            if ($this->execute("DELETE FROM {$this->prefix}pattern WHERE pattern = ?", [$pattern]) === 0) {
                return false;
            }
            $this->bumpVersion();
            return true;
        });
    }

    public function allowEntries(): array
    {
        return $this->guarded(function (): array {
            $entries = [];
            $rows = $this->rows("SELECT entry, comment, expires_at, created_by FROM {$this->prefix}allow WHERE expires_at IS NULL OR expires_at > ? ORDER BY id", [time()]);
            foreach ($rows as $row) {
                $entry = AllowEntry::fromArray(['entry' => $row['entry'], 'comment' => $row['comment'], 'expires' => $row['expires_at'] ?? 0, 'createdBy' => $row['created_by']]);
                if ($entry !== null) {
                    $entries[] = $entry;
                }
            }
            return $entries;
        });
    }

    public function saveAllow(AllowEntry $entry): void
    {
        $this->transaction(function () use ($entry): void {
            $id = $this->scalar("SELECT id FROM {$this->prefix}allow WHERE entry = ?", [$entry->entry]);
            if ($id === null) {
                $this->insertAllow($entry, $entry->createdBy);
            } else {
                $this->execute(
                    "UPDATE {$this->prefix}allow SET comment = ?, expires_at = ?, created_by = ? WHERE id = ?",
                    [mb_substr($entry->comment, 0, 255), $entry->expiresAt === 0 ? null : $entry->expiresAt, mb_substr($entry->createdBy, 0, 255), $id],
                );
            }
            $this->bumpVersion();
        });
    }

    public function removeAllow(string $entry): bool
    {
        return $this->transaction(function () use ($entry): bool {
            if ($this->execute("DELETE FROM {$this->prefix}allow WHERE entry = ?", [trim($entry)]) === 0) {
                return false;
            }
            $this->bumpVersion();
            return true;
        });
    }

    private function insertPattern(string $pattern, string $by): void
    {
        $this->execute(
            "INSERT INTO {$this->prefix}pattern (pattern, type, enabled, created_at, created_by) VALUES (?, ?, 1, ?, ?)",
            [$pattern, Rules::patternType($pattern), time(), mb_substr($by, 0, 255)],
        );
    }

    private function insertAllow(AllowEntry $entry, string $by): void
    {
        $this->execute(
            "INSERT INTO {$this->prefix}allow (entry, comment, created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?)",
            [$entry->entry, mb_substr($entry->comment, 0, 255), time(), mb_substr($by, 0, 255), $entry->expiresAt === 0 ? null : $entry->expiresAt],
        );
    }

    private function bumpVersion(): void
    {
        $cast = $this->driver === 'mysql' ? 'CAST(CAST(value AS UNSIGNED) + 1 AS CHAR)' : 'CAST(CAST(value AS BIGINT) + 1 AS VARCHAR(255))';
        $this->execute("UPDATE {$this->prefix}meta SET value = {$cast} WHERE name = 'version'", []);
    }

    private function meta(string $name): ?string
    {
        $value = $this->scalar("SELECT value FROM {$this->prefix}meta WHERE name = ?", [$name]);
        return $value === null ? null : (string) $value;
    }

    /** @param list<mixed> $params */
    private function execute(string $sql, array $params): int
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement->rowCount();
    }

    /** @param list<mixed> $params */
    private function scalar(string $sql, array $params): int|string|null
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        /** @var int|string|false $value */
        $value = $statement->fetchColumn();
        return $value === false ? null : $value;
    }

    /**
     * @param list<mixed> $params
     * @return array<string, int|string|null>|null
     */
    private function row(string $sql, array $params): ?array
    {
        return $this->rows($sql, $params)[0] ?? null;
    }

    /**
     * @param list<mixed> $params
     * @return list<array<string, int|string|null>>
     */
    private function rows(string $sql, array $params): array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        /** @var list<array<string, int|string|null>> */
        return $statement->fetchAll(\PDO::FETCH_ASSOC);
    }

    /**
     * @template T
     * @param \Closure(): T $work
     * @return T
     */
    private function transaction(\Closure $work): mixed
    {
        return $this->guarded(function () use ($work): mixed {
            $this->pdo->beginTransaction();
            try {
                $result = $work();
                if ($this->pdo->inTransaction()) {
                    $this->pdo->commit();
                }
                return $result;
            } catch (\Throwable $e) {
                // MySQL has already committed implicitly after a CREATE TABLE
                if ($this->pdo->inTransaction()) {
                    $this->pdo->rollBack();
                }
                throw $e;
            }
        });
    }

    /**
     * @template T
     * @param \Closure(): T $work
     * @return T
     */
    private function guarded(\Closure $work): mixed
    {
        try {
            return $work();
        } catch (\PDOException $e) {
            throw new StoreException('Central database: ' . $e->getMessage(), 0, $e);
        }
    }
}
