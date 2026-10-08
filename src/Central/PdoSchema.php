<?php

declare(strict_types=1);

namespace ScannerTrap\Central;

/** The five tables, per driver; every statement is safe to run again. */
final class PdoSchema
{
    /** @return list<string> */
    public static function statements(string $driver, string $prefix): array
    {
        $p = $prefix;
        return match ($driver) {
            'mysql' => [
                "CREATE TABLE IF NOT EXISTS {$p}block (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(45) NOT NULL, blocked_at BIGINT NOT NULL, expires_at BIGINT NULL, server VARCHAR(255) NOT NULL DEFAULT '', method VARCHAR(16) NOT NULL DEFAULT '', path VARCHAR(1024) NOT NULL DEFAULT '', pattern VARCHAR(255) NOT NULL DEFAULT '', user_agent VARCHAR(512) NOT NULL DEFAULT '', source VARCHAR(16) NOT NULL DEFAULT 'trap', lifted_at BIGINT NULL, lifted_by VARCHAR(255) NULL, INDEX {$p}block_ip (ip, lifted_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
                "CREATE TABLE IF NOT EXISTS {$p}pattern (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, pattern VARCHAR(255) NOT NULL, type VARCHAR(16) NOT NULL, enabled TINYINT(1) NOT NULL DEFAULT 1, created_at BIGINT NOT NULL, created_by VARCHAR(255) NOT NULL DEFAULT '', UNIQUE KEY {$p}pattern_pattern (pattern)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
                "CREATE TABLE IF NOT EXISTS {$p}allow (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, entry VARCHAR(64) NOT NULL, comment VARCHAR(255) NOT NULL DEFAULT '', created_at BIGINT NOT NULL, created_by VARCHAR(255) NOT NULL DEFAULT '', expires_at BIGINT NULL, UNIQUE KEY {$p}allow_entry (entry)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
                "CREATE TABLE IF NOT EXISTS {$p}meta (name VARCHAR(32) NOT NULL PRIMARY KEY, value VARCHAR(255) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
                "CREATE TABLE IF NOT EXISTS {$p}list_entry (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, source VARCHAR(32) NOT NULL, cidr VARCHAR(49) NOT NULL, imported_at BIGINT NOT NULL, UNIQUE KEY {$p}list_entry_source_cidr (source, cidr)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            ],
            'pgsql' => [
                "CREATE TABLE IF NOT EXISTS {$p}block (id BIGSERIAL PRIMARY KEY, ip VARCHAR(45) NOT NULL, blocked_at BIGINT NOT NULL, expires_at BIGINT NULL, server VARCHAR(255) NOT NULL DEFAULT '', method VARCHAR(16) NOT NULL DEFAULT '', path VARCHAR(1024) NOT NULL DEFAULT '', pattern VARCHAR(255) NOT NULL DEFAULT '', user_agent VARCHAR(512) NOT NULL DEFAULT '', source VARCHAR(16) NOT NULL DEFAULT 'trap', lifted_at BIGINT NULL, lifted_by VARCHAR(255) NULL)",
                "CREATE INDEX IF NOT EXISTS {$p}block_ip ON {$p}block (ip, lifted_at)",
                "CREATE TABLE IF NOT EXISTS {$p}pattern (id BIGSERIAL PRIMARY KEY, pattern VARCHAR(255) NOT NULL UNIQUE, type VARCHAR(16) NOT NULL, enabled SMALLINT NOT NULL DEFAULT 1, created_at BIGINT NOT NULL, created_by VARCHAR(255) NOT NULL DEFAULT '')",
                "CREATE TABLE IF NOT EXISTS {$p}allow (id BIGSERIAL PRIMARY KEY, entry VARCHAR(64) NOT NULL UNIQUE, comment VARCHAR(255) NOT NULL DEFAULT '', created_at BIGINT NOT NULL, created_by VARCHAR(255) NOT NULL DEFAULT '', expires_at BIGINT NULL)",
                "CREATE TABLE IF NOT EXISTS {$p}meta (name VARCHAR(32) NOT NULL PRIMARY KEY, value VARCHAR(255) NOT NULL)",
                "CREATE TABLE IF NOT EXISTS {$p}list_entry (id BIGSERIAL PRIMARY KEY, source VARCHAR(32) NOT NULL, cidr VARCHAR(49) NOT NULL, imported_at BIGINT NOT NULL, UNIQUE (source, cidr))",
            ],
            'sqlite' => [
                "CREATE TABLE IF NOT EXISTS {$p}block (id INTEGER PRIMARY KEY AUTOINCREMENT, ip VARCHAR(45) NOT NULL, blocked_at BIGINT NOT NULL, expires_at BIGINT NULL, server VARCHAR(255) NOT NULL DEFAULT '', method VARCHAR(16) NOT NULL DEFAULT '', path VARCHAR(1024) NOT NULL DEFAULT '', pattern VARCHAR(255) NOT NULL DEFAULT '', user_agent VARCHAR(512) NOT NULL DEFAULT '', source VARCHAR(16) NOT NULL DEFAULT 'trap', lifted_at BIGINT NULL, lifted_by VARCHAR(255) NULL)",
                "CREATE INDEX IF NOT EXISTS {$p}block_ip ON {$p}block (ip, lifted_at)",
                "CREATE TABLE IF NOT EXISTS {$p}pattern (id INTEGER PRIMARY KEY AUTOINCREMENT, pattern VARCHAR(255) NOT NULL UNIQUE, type VARCHAR(16) NOT NULL, enabled SMALLINT NOT NULL DEFAULT 1, created_at BIGINT NOT NULL, created_by VARCHAR(255) NOT NULL DEFAULT '')",
                "CREATE TABLE IF NOT EXISTS {$p}allow (id INTEGER PRIMARY KEY AUTOINCREMENT, entry VARCHAR(64) NOT NULL UNIQUE, comment VARCHAR(255) NOT NULL DEFAULT '', created_at BIGINT NOT NULL, created_by VARCHAR(255) NOT NULL DEFAULT '', expires_at BIGINT NULL)",
                "CREATE TABLE IF NOT EXISTS {$p}meta (name VARCHAR(32) NOT NULL PRIMARY KEY, value VARCHAR(255) NOT NULL)",
                "CREATE TABLE IF NOT EXISTS {$p}list_entry (id INTEGER PRIMARY KEY AUTOINCREMENT, source VARCHAR(32) NOT NULL, cidr VARCHAR(49) NOT NULL, imported_at BIGINT NOT NULL, UNIQUE (source, cidr))",
            ],
            default => throw new \InvalidArgumentException("Unsupported PDO driver {$driver}: use mysql, pgsql or sqlite"),
        };
    }
}
