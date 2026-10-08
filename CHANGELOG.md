# Changelog

All notable changes to this project are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

### Added
* Guard for `index.php` (`ScannerTrap::guard()`) and PSR-15 middleware: the first request to a decoy path blacklists the IP.
* Local stores: Redis (phpredis or Predis), files, APCu.
* Central PDO store (MySQL/MariaDB, PostgreSQL, SQLite) and `scanner-trap sync` for several servers.
* `TrapManager` API and the `scanner-trap` CLI: install, sync, list, block, unblock, patterns, whitelist.
* Default decoy patterns, and WordPress probes for sites that are not WordPress.
* Subnet escalation: 3 trapped addresses of one IPv4 /24 within 24 hours, or 1 of an IPv6 /64, block the network.
* Scanner signatures: `@fragment` patterns match the User-Agent; the defaults cover sqlmap, nuclei, zgrab and other tools.
* Imported blocklists: Spamhaus DROP, FireHOL level1, any URL or file; `scanner-trap import` and `lists`.
* `block` and `unblock` accept a CIDR.

### Changed
* The six SQL fragments that search text can contain (`' or '`, `' and '`, `" or "`, `" and "`, `sleep(`, `benchmark(`) moved from `DefaultPatterns::LIST` to `DefaultPatterns::LOOSE_FRAGMENTS`. A stored pattern list keeps them until `scanner-trap pattern:remove`.
* The file store keeps network blocks in `networks.json`; no PHP file is written any more. A leftover `networks.current` and `networks-*.php` are ignored and may be deleted.
