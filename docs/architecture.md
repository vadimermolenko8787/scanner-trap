# scanner-trap: architecture

How the package is built and why, for contributors and bridge authors. The configuration reference is in the README.

## Purpose and limits

The first request an address makes to a decoy blacklists it: a path no visitor opens (`/.env`), an SQL injection
fragment in the URI, or a scanning tool's User-Agent. Addresses rotating inside one network escalate to a network
block, and imported blocklists are refused outright.

- It stops reconnaissance, not floods: no rate limiting, `404` counting, CAPTCHA or geo blocking.
- It fails open: any failure lets the request through and goes to an optional PSR-3 logger.
- The whitelist wins over every block and list. `blocking` is off by default (watch mode).
- Not covered: rotation across unrelated networks, reputation services, fingerprints beyond the User-Agent, requests
  that never reach PHP, a web UI, framework integration (separate packages).

## Modes

| Mode | Local store | Central store | Sync |
|---|---|---|---|
| 1. One server | Redis, files or APCu | none | none |
| 2. Several servers, one Redis | `RedisLocalStore`, same address everywhere | none | none |
| 3. Several servers, own stores | Redis or files | `PdoCentralStore` (MySQL/MariaDB, PostgreSQL, SQLite) | `scanner-trap sync` from cron |
| 4. (later) database reachable from one server | Redis or files | an HTTP `CentralStore` | as mode 3 |

In modes 1 and 2 patterns and whitelist come from the config until stored; then the stored lists win. In mode 3 they
live centrally and apply after the first pull. Mode 4 changes nothing in `Sync`, `TrapManager` or `Guard`, which only
know the `CentralStore` interface.

## Components

| Unit | Responsibility |
|---|---|
| `RequestContext` | Client IP (after `trustedProxies`), method, URI, User-Agent, `Sec-Fetch-Site` |
| `Rules` | Normalizing, matching the five pattern forms and the whitelist, validation |
| `Network` | Normalized CIDR value; candidates of an address; reserved ranges |
| `SubnetPolicy` | Escalation network, threshold and window; never a reserved network |
| `Guard` | The decision: one store read, on a decoy one atomic block; store failures propagate |
| `LocalStore` | Interface of this server's copy; `RedisLocalStore`, `FileLocalStore` (with `RangeFile`), `ApcuLocalStore` |
| `RedisConnection` | `raw()` only; `PhpRedisConnection`, `PredisConnection` |
| `CentralStore` | Source of truth in mode 3; `PdoCentralStore`, DDL in `PdoSchema` |
| `Sync` | `push()`, `pull()`, `run()` |
| `TrapManager` | Every management action; with a central store it writes there, then pulls |
| `ListSource`, `ListImporter` | Blocklist sources; fetch (16 MB per location), parse, filter (200 000 networks at most) |
| `ScannerTrap` | Facade: `guard()`, `check()`, `fromConfig()`, `createGuard()`, `middleware()`, `manager()`, `failSafe()` |
| `ScannerTrapMiddleware` | PSR-15: `403` or delegate |
| CLI | `bin/scanner-trap` and `Cli`; exit codes 1 usage, 2 refused, 3 unreachable |
| `DefaultPatterns` | `LIST` (with `SCANNER_AGENTS`), `LOOSE_FRAGMENTS`, `WORDPRESS_PROBES` |
| `TrustedProxies` | `CLOUDFLARE` ranges |

## The decision

`Guard::decide(RequestContext): Decision`:

1. No usable address, or a loopback one: allow without touching the store.
2. One store read: blocked (address or network), listed, patterns, whitelist. A store that cannot be read sensibly
   (lists not JSON, corrupt networks or range file) lets the request through with a warning.
3. Whitelisted: allow.
4. Blocked or listed: refuse if `blocking`; nothing recorded.
5. A `@` signature in the User-Agent traps on any page; `ownPaths` and step 7 do not apply.
6. Path and extension patterns (unless under `ownPaths`), then `~` fragments on the decoded URI. No match: allow.
7. `Sec-Fetch-Site: cross-site`: refuse if `blocking`, record nothing.
8. Trap: block for `blockTtl` with its event and the escalation count, atomically; refuse if `blocking`.

## Data layout

Local names carry the configured prefix (`scanner-trap:`) or live in the configured directory. Blocks and events are
`Block` JSON: `ip` (address or CIDR), `blockedAt`, `expiresAt` (0 = forever), `server`, `method`, `path`, `pattern`,
`userAgent`, `source` (`trap`, `manual`, `subnet`), `liftedAt`, `liftedBy`. The owner marker is
`{owner, version, listsVersion, lastId, fullAt, pulledAt}`.

| Item | Redis | Files | APCu |
|---|---|---|---|
| address block | `block:<ip>`, TTL | `blocks/<sha1(ip)>` | `block:<ip>`, TTL |
| network block | `net:<cidr>`, TTL | `networks.json` | `net:<cidr>`, TTL |
| prefix lengths in use | set `netlens` | keys of `networks.json` | `netlen:<family>/<prefix>` |
| escalation counter | sorted set `seen:<cidr>` | `seen/<sha1(cidr)>` | `seen:<cidr>` |
| list entries | hash `lh:<source>:<gen>` | `lists/<source>.txt`, `lists-<hex>.bin` | `lnet:<cidr>`, `list:<source>` |
| list status | hash `lists`, counter `lists:seq` | `lists/status.json`, `lists.current` | `lists` |
| patterns, whitelist | `patterns`, `allow` | `patterns.json`, `allow.json` | `patterns`, `allow` |
| events | stream `events`, `MAXLEN ~ 10000` | `events.log` | none |
| owner marker | `owner` | `owner` | `owner` |
| locks | `sync-lock` | `sync.lock`, `networks.lock`, `lists.lock`, `locks/<sha1(ip)>` | `sync-lock` |

The JSON lists, `owner`, `lists.current` and the range file are written to a temporary name and renamed;
`patterns.json`, `allow.json` and `networks.json` are re-read only when inode, mtime or size change. The range file
holds a header (`STL1`, IPv4 count, IPv6 count, JSON length), the source names as JSON, then sorted, merged records of
10 bytes (IPv4) or 34 bytes (IPv6); a superseded one stays 10 minutes for readers holding its name.

| Central table (`scanner_trap_`) | Columns |
|---|---|
| `block` | `id`, `ip` (address or CIDR), `blocked_at`, `expires_at` (NULL = forever), `server`, `method`, `path`, `pattern`, `user_agent`, `source`, `lifted_at`, `lifted_by` |
| `pattern` | `id`, `pattern` (unique), `type`, `enabled`, `created_at`, `created_by` |
| `allow` | `id`, `entry` (unique), `comment`, `created_at`, `created_by`, `expires_at` |
| `meta` | `name`, `value`: `owner`, `version`, `lists_version` |
| `list_entry` | `id`, `source`, `cidr`, `imported_at`; unique (`source`, `cidr`) |

An insert extends the target's active row instead of adding one. Block inserts and imports first update the
`version` or `lists_version` row, which serializes concurrent writers.

## Decisions and reasons

- **Fail open, warnings as exceptions.** `ScannerTrap::failSafe()` turns warnings inside the check into exceptions,
  swallows deprecations, logs and lets the request through: a printed warning breaks the response, an outage must not
  spread to the site.
- **One store round trip.** The trap runs on every request: one Redis script call, a few stats and cached reads for
  files, one APCu fetch (two when network lengths are in use).
- **The atomic block.** Of a scanner's parallel requests exactly one records the event: Redis `SET NX` and `XADD` in
  one Lua script, files `fopen(…, 'x')`.
- **Events only with a central store.** Nothing else would drain them.
- **The owner marker.** Two installations with different central databases on one Redis would overwrite each other's
  lists; `push()` and `pull()` refuse a foreign owner.
- **`Sec-Fetch-Site`.** Another site's `<img src="/.env">` must not lock visitors out: cross-site hits are refused
  when blocking is on, never recorded.
- **Loose fragments opt-in.** `~' or '`, `~sleep(` and four others occur in search text; they live in
  `LOOSE_FRAGMENTS`, not `LIST`.
- **The range file.** Measured on PHP 8.3 with a local Redis: 200 000 networks as a PHP array file are 21 MB and cost
  130 ms and 80 MB per request without opcache. A binary search of the range file reads about 18 records, flat
  however long the lists are. Cost: for overlapping lists, the reported source is one of them.
- **Generation switching in Redis.** One script replacing 200 000 entries kept Redis busy 0.3 to 0.4 s. An import
  writes a new generation in chunks of 5 000 fields; one short script switches `lists` to it and `UNLINK`s the old
  generation; leftovers of crashed imports are unlinked afterwards.
- **`networks.json`, not PHP.** Once the lists moved to the range file, a handful of network blocks remained; a PHP
  file that the web server writes and includes would run whatever lands there.
- **Scripts by hash.** `EVALSHA`, and `EVAL` once on `NOSCRIPT`, instead of sending about 0.9 KB with every read and
  about 1 KB with every block. `persistent` reuses the connection, and phpredis then always selects the database.
- **`prune`, keep at least the subnet window and an hour.** It bounds the central history and the file store's
  leftovers. Central escalation ignores hits before a network's latest lift and reads that lift from the history;
  pruning it early would let old hits undo an unblock. A pull reads the lifts since the previous one, and the hourly
  full pass bounds that gap: the keep is the larger of the subnet window and an hour plus the 60 s clock margin.
  Lifted rows go by their lift time, expired rows only when never lifted, so a recent lift of an old block stays.

## Sync

`push()` sends local events in batches of 200 and removes a batch only after it is inserted. After each batch it
counts, per escalation network, the distinct addresses with an active `trap` block within the window and after the
network's latest lift, and inserts a `subnet` block at the threshold: hits on different servers add up.

`pull()`:

1. refuses a foreign owner;
2. replaces patterns and whitelist when `version` changed, the lists (one source at a time) when `lists_version` did;
3. full reconciliation when the marker is absent, `lastId` is -1 or `fullAt` is an hour old: missing central blocks
   are added, local blocks without an active central one removed, a local block with a later central expiry replaced;
   `lastId` becomes the highest central id seen;
4. otherwise incremental: active central blocks with an id above `lastId` are added (`lastId` advances); one whose
   target is already blocked here replaces the local block when it lasts longer (a target lifted and blocked anew
   elsewhere), and this server's own blocks coming back are left as they are; targets lifted since `pulledAt` minus
   60 s (clock margin) and not blocked again are removed;
5. saves the marker.

Ids work as a cursor because inserts hold the `version` row lock, so they commit in id order. An expiry extended by a
merge keeps its id and arrives with the next full pass, at most an hour later; that delay is accepted. No pass removes
the block of an address whose event still waits to be pushed.

`run()` takes the sync lock or returns at once, pushes, pulls, then until `--watch` seconds pass pushes new events as
they come (Redis `XREAD BLOCK`, files polling). Cron runs `sync --watch=50` every minute.

## Testing

Real stores, no mocks: Redis through phpredis and Predis, files, APCu, SQLite, MySQL and PostgreSQL. Contract tests
(`LocalStoreContract`, `PdoCentralStoreContract`, `GuardScenarios`) run on every store. Child processes test
concurrency, the CLI end to end and `guard()`'s output; `Sync` runs two local stores against one central store;
`php -S` serves HTTP downloads. CI runs PHP 8.1 to 8.4 with
`--fail-on-skipped`, PHPStan at level max and PHP-CS-Fixer.

## Integration points for bridge authors

- `RequestContext`'s constructor takes a resolved IP, so a bridge may use its framework's proxy handling.
- `Guard::decide()` returns a `Decision` and lets store failures propagate.
- `ScannerTrap::failSafe()` is the fail-open wrapper, public API from 0.1.0.
- `fromConfig()` builds without connecting; `createGuard()` builds a `Guard`; `manager()` returns the `TrapManager`.
- `TrapManager` throws `RefusedException` and `StoreException`; `Cli` reads its config from a file only.
- `RedisConnection` needs `raw()` only; an instance is passed as `'client'`.

Two facts constrain bridges: Laravel Octane never runs `public/index.php`, so `guard()` there never runs; and with the
Symfony Runtime, `guard()` in `public/index.php` works only when `vendor/autoload.php` is required before
`autoload_runtime.php`. `guard()` also exits after a refusal.
