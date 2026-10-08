# Changelog

All notable changes to this project are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

### Added
* Guard for `index.php` (`ScannerTrap::guard()`) and PSR-15 middleware: the first request to a decoy path blacklists the IP.
* Local stores: Redis (phpredis or Predis), files, APCu.
* Central PDO store (MySQL/MariaDB, PostgreSQL, SQLite) and `scanner-trap sync` for several servers.
* `TrapManager` API and the `scanner-trap` CLI: install, sync, list, block, unblock, patterns, whitelist.
* Default decoy patterns, and WordPress probes for sites that are not WordPress.
