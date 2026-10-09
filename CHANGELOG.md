# Changelog

All notable changes to this project are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-09

### Added
* Guard for `index.php` (`ScannerTrap::guard()`) and PSR-15 middleware: the first request to a decoy path blacklists the IP.
* Local stores: Redis (phpredis or Predis), files, APCu.
* Central PDO store (MySQL/MariaDB, PostgreSQL, SQLite) and `scanner-trap sync` for several servers.
* `TrapManager` API and the `scanner-trap` CLI: install, sync, list, block, unblock, patterns, whitelist.
* Default decoy patterns, WordPress probes for sites that are not WordPress, and `DefaultPatterns::LOOSE_FRAGMENTS` for fragments a search box can produce (`" or "`, `sleep(`), opt-in.
* Subnet escalation: 3 trapped addresses of one IPv4 /24 within 24 hours, or 1 of an IPv6 /64, block the network.
* Scanner signatures: `@fragment` patterns match the User-Agent; the defaults cover sqlmap, nuclei, zgrab and other tools.
* Imported blocklists: Spamhaus DROP, FireHOL level1, any URL or file, at most 16 MB per download; `scanner-trap import` and `lists`.
* `block` and `unblock` accept a CIDR.
* `scanner-trap prune` drops old central history and the file store's leftovers.
* Sync pulls only the blocks and lifts made since the previous run, with a full reconciliation once an hour.
* Redis scripts run by their hash (`EVALSHA`); `'persistent' => true` keeps the Redis connection across requests.
* `TrustedProxies::CLOUDFLARE` lists Cloudflare's ranges for `trustedProxies`, for sites behind Cloudflare.
* `docs/architecture.md`: the design decisions and the data layout.

[0.1.0]: https://github.com/vadimermolenko8787/scanner-trap/releases/tag/0.1.0
