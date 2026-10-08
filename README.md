# scanner-trap

Shuts out vulnerability scanners. The first request an IP makes to a path no real visitor ever opens (`/.env`,
`/.git/config`, `/phpmyadmin`, `?id=1 UNION SELECT`) blacklists that IP, and every later request from it gets `403`.

It stops reconnaissance, not floods: leave rate limiting to the web server or a CDN.

PHP 8.1 to 8.4, no framework needed. Any failure inside the package lets the request through, and a deprecation or
warning raised inside the check never reaches the response.

## Quick start: one server, files

    composer require vadimermolenko8787/scanner-trap

Put the config in `scanner-trap.php` at the project root:

    <?php
    return ['local' => ['type' => 'file', 'dir' => __DIR__ . '/var/scanner-trap']];

and call it at the very top of `public/index.php`:

    require __DIR__ . '/../vendor/autoload.php';
    \ScannerTrap\ScannerTrap::guard(__DIR__ . '/../scanner-trap.php');

That is all. It starts in **watch mode**: scanners are blacklisted and reported, nobody is refused. Watch it for a few
days (`vendor/bin/scanner-trap list`, run from the project root: the CLI reads `./scanner-trap.php`), then turn
refusing on with `'blocking' => true`.

## File permissions

The web server and the CLI or cron must run as the same user, for example `sudo -u www-data vendor/bin/scanner-trap
sync`, or share a group with `umask 002`. Otherwise the web server cannot write what the CLI created (or the other way
round): the trap silently fails open, or sync fails. Configure a PSR-3 `logger`: it is the only way to learn that the
trap failed open.

If `networks.json` or `lists.current` in that directory is corrupt, the trap fails open on those lookups. Delete the
file: network blocks (or imported lists) are then empty until the next network block is written (or the next
`scanner-trap import`).

## Several servers sharing one Redis

    \ScannerTrap\ScannerTrap::guard(__DIR__ . '/../scanner-trap.php');

with `scanner-trap.php`:

    return [
        'local' => [
            'type' => 'redis', 'host' => '10.0.0.5', 'port' => 6379, 'database' => 0, 'prefix' => 'scanner-trap:',
            // 'password' => '…', when Redis needs one
        ],
        'blocking' => false, // watch first, then switch to true
    ];

Every server reads and writes the same keys; nothing to sync. Pass an existing client with
`'local' => ['type' => 'redis', 'client' => $redis]` (phpredis or Predis).

## Several servers with a central database

Each server keeps its own Redis or file store; a MySQL/MariaDB, PostgreSQL or SQLite database is the source of truth.

    return [
        'local' => ['type' => 'redis', 'host' => '127.0.0.1'],
        'central' => ['dsn' => 'mysql:host=db;dbname=trap', 'user' => 'trap', 'password' => '…', 'tablePrefix' => 'scanner_trap_'],
    ];

Once: `vendor/bin/scanner-trap install` (creates the tables and seeds the patterns and whitelist from the config).
On every server, from cron every minute:

    * * * * * cd /var/www/app && vendor/bin/scanner-trap sync --watch=50

Running `install` again in modes 1 and 2 (no central database) replaces the patterns and whitelist entries added through
the CLI with the config's lists. `install` refuses a config pattern that is invalid and names it. Block events are kept
only with a central database, where they wait for the next sync; without one nothing would ever drain them.

A block made on one server reaches the others within a minute; the `--watch` part ships new blocks at once. A project
with its own worker can call `ScannerTrap::fromConfig($config)->manager()->sync(50)` instead.

## PSR-15

    $trap = \ScannerTrap\ScannerTrap::fromConfig($config);
    $app->add($trap->middleware($responseFactory));

## Command line

`vendor/bin/scanner-trap [--config=path] <command>`, config `./scanner-trap.php` by default.

| Command | Effect |
|---|---|
| `install` | central database: tables, owner id, seeded lists; otherwise the config's lists into the local store |
| `sync [--watch=N]` | push events, pull lists and blocks (central database only) |
| `list [--active] [--ip=…]` | blocks with reason, server, expiry; with `--ip`, the address's own block and every network block covering it |
| `block <ip or cidr> [--reason=…] [--ttl=…]` | manual block; `--ttl=0` is forever; refused for a whitelisted IP, or a network that is reserved or overlaps the whitelist |
| `unblock <ip or cidr>` | lift the block everywhere (a network's escalation count starts afresh); an address still inside a blocked network is reported as such |
| `import [--source=…]` | fetch the configured blocklists (all, or one) |
| `prune [--keep=…]` | drop lifted and expired blocks older than the keep (30 days) from the central database, and expired files from the file store |
| `lists` | each list source with its size and last import |
| `pattern:list`, `pattern:add <p>`, `pattern:remove <p>` | decoy patterns, validated |
| `allow:list`, `allow:add <entry> [--comment=…] [--ttl=…]`, `allow:remove <entry>` | whitelist |

`list` without `--active` shows the history back to the keep.

Exit codes: 0 success, 1 usage error, 2 refused, 3 store unreachable.

The CLI records the operating system user running it, with the host (`deploy@web1`): as `created_by` of patterns and
whitelist entries, as `lifted_by` of an unblock, and, when `block` is given no `--reason`, as the reason of a manual block (`manual by deploy@web1`).

## Patterns

| Form | Example | Matches |
|---|---|---|
| path prefix | `/phpmyadmin` | the path and everything below it, by whole segments |
| open prefix | `/.env*` | everything beginning with the text before `*` |
| extension | `*.sql` | a path ending in the extension |
| SQL fragment | `~union select` | the fragment anywhere in the decoded URI |
| scanner signature | `@sqlmap` | the fragment in the User-Agent, case-insensitively, on any page |

| Constant | Add it when |
|---|---|
| `LIST` | always, the default |
| `WORDPRESS_PROBES` | the site is not WordPress |
| `LOOSE_FRAGMENTS` | no query string carries free text |

`'patterns' => [...DefaultPatterns::LIST, ...DefaultPatterns::WORDPRESS_PROBES]`, or
`'patterns' => [...DefaultPatterns::LIST, ...DefaultPatterns::LOOSE_FRAGMENTS]`.

## Scanners that change address

**Subnet escalation** is on by default. When 3 different addresses of one IPv4 `/24` hit a decoy within 24 hours,
the whole `/24` is blocked; for IPv6 the first hit blocks its `/64` (one host usually owns a whole `/64`). Private and
reserved networks are never escalated. With a central database, hits on different servers add up.

A `/24` can be a mobile carrier's CGNAT pool, where unrelated visitors share a few addresses. If your visitors come
from such networks, raise `v4Threshold`, use a narrower `v4Prefix` (up to `31`), or set `'subnets' => false`; `allow`
entries always win over a network block.

    'subnets' => ['v4Prefix' => 24, 'v4Threshold' => 3, 'v6Prefix' => 64, 'v6Threshold' => 1, 'window' => 86400],
    // or 'subnets' => false

A network block is lifted with `scanner-trap unblock 45.155.205.0/24`; `block` accepts a CIDR too. A manual network
block is refused when the network is private or reserved, or overlaps a whitelist entry (an octet mask such as
`192.168.0.*` counts by its fixed octets).

**Scanner signatures.** A pattern starting with `@` matches the User-Agent, case-insensitively: `@sqlmap`,
`@nuclei`, `@zgrab` and the other tools in `DefaultPatterns::SCANNER_AGENTS` are part of the default list. A matching
request is blacklisted on any page, decoy or not. Fragments of ordinary browser User-Agents (`@mozilla`, `@bot`, ...)
are refused, and so is any fragment that occurs in the User-Agent of a current Chrome, Firefox, Safari or Edge
(`@like gecko`, `@win64; x64`). Installations that already stored their patterns add them with `scanner-trap pattern:add '@sqlmap'`.

## Imported blocklists

    'lists' => [
        'spamhaus-drop',
        'firehol-level1',
        ['name' => 'blocklist-de', 'url' => 'https://lists.blocklist.de/lists/all.txt'],
        ['name' => 'own', 'file' => __DIR__ . '/deny.txt'],
    ],

`scanner-trap import` fetches them (one IP or CIDR per line, `#` and `;` comments; `'format' => 'spamhaus-json'` for
Spamhaus JSON lines), drops private and reserved networks and anything wider than `/8` (IPv4) or `/16` (IPv6), and
replaces each source's entries. Addresses on a list are refused while `blocking` is on; the whitelist still wins.
`scanner-trap lists` shows each source with its size and last import.

A source name is a lowercase letter followed by lowercase letters, digits and `-`, at most 32 characters in all, and
a custom source may not reuse a preset name (`spamhaus-drop`, `firehol-level1`).
`import` prints one line per source, `N networks (was M)` and what each filter skipped (invalid, reserved, too wide).
`import --source=NAME` imports one source; an empty `--source=` is a usage error. When a source fails, the others are
still imported, the failed one keeps its previous entries, and the command exits with 3.

URLs are fetched with ext-curl when it is loaded, else through PHP streams, which need `allow_url_fopen`. Imported
lists need a Redis or file store (or a central database): an APCu store cannot import, because the CLI cannot reach the
web server's APCu. Run the import daily from cron; with a central database on one server only, the others receive the
lists on their next sync:

    17 4 * * * cd /var/www/app && sudo -u www-data vendor/bin/scanner-trap import
    23 3 * * * cd /var/www/app && sudo -u www-data vendor/bin/scanner-trap prune

`prune` drops central history older than 30 days (`--keep=SECONDS`, at least the subnet window and never below 3660)
and, from the file store, expired block files and orphan locks at any age and `seen/` counters older than the keep;
with file stores, run it on every server.

## Web server routing

The trap only sees requests that reach PHP. Common nginx configurations answer two kinds of probes themselves, so
they are never blacklisted:

* missing `.php` files (`/wp-login.php`, `/xmlrpc.php`): PHP-FPM answers "File not found."; add
  `try_files $uri /index.php?$query_string;` to the `location ~ \.php$` block;
* dot paths (`/.env`, `/.git/config`) behind `deny all;`: replace it with `rewrite ^ /index.php last;` (the file is
  still never served).

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `local` | required | `['type' => 'redis', 'host', 'port', 'database', 'password', 'prefix']`, `['type' => 'file', 'dir' => …]` or `['type' => 'apcu']` |
| `central` | `null` | `['dsn' => …, 'user' => …, 'password' => …, 'tablePrefix' => 'scanner_trap_']` |
| `serverName` | `gethostname()` | recorded with every block |
| `blocking` | `false` | refuse blacklisted IPs; `false` only records them |
| `blockTtl` | `604800` | seconds a block lasts, `0` = forever |
| `patterns` | `DefaultPatterns::LIST` | decoys; with a central database they live there and this only seeds `install` |
| `allow` | `[]` | IPs, CIDR ranges, IPv4 masks like `192.168.0.*`; always wins over a block; with a central database this only seeds `install` |
| `subnets` | on: `/24` after 3 addresses, `/64` after 1, 24 h | subnet escalation; `false` turns it off |
| `lists` | `[]` | blocklists to import: preset names (`spamhaus-drop`, `firehol-level1`) or `['name' => …, 'url' or 'file' => …, 'format' => …]` |
| `ownPaths` | `[]` | paths your site really serves; path and extension patterns never apply below them |
| `trustedProxies` | `[]` | CIDR ranges of your load balancers; only then is `X-Forwarded-For` read |
| `logger` | `null` | a PSR-3 logger for failures and new blocks |

Without a central database the config's `patterns` and `allow` apply until `install` or a CLI command stores lists;
from then on the stored lists apply.

## Security notes

* **Start in watch mode.** Leave `blocking` off until `list` shows only scanners.
* **`ownPaths`.** If your application serves a path a pattern covers (a real `/admin`, say), list it; patterns
  covering it are refused, and requests below it never match a path pattern.
* **`trustedProxies`.** Behind a load balancer every request comes from the balancer's address: list its range, or the
  trap would blacklist your own balancer. Never list ranges you do not control; `X-Forwarded-For` is read only from
  them, from the right.
* **Cross-site requests** (`Sec-Fetch-Site: cross-site`) to a decoy are refused but never blacklist the visitor, so
  another site cannot lock your visitors out with an `<img>`.
* **GET search forms.** A search box may legitimately send quote fragments such as `" or "`, or words such as
  `sleep(`. These risky fragments are opt-in through `DefaultPatterns::LOOSE_FRAGMENTS`: add them only if no query
  string carries free text.
* **Fetch Metadata limits.** Same-origin user content such as `<img src="/.env">` in a comment makes the browser send
  `Sec-Fetch-Site: same-origin`, so it blacklists everyone who views it: sanitise user content. Browsers that send no
  `Sec-Fetch-Site` are not protected from the cross-site case.
* **Owner marker.** Each local store remembers which central database it follows. After reinstalling the central
  database, delete the `{prefix}owner` key (Redis) or the `owner` file (file store) on each server, or sync refuses to
  run.
* **APCu** lives inside one PHP server: the CLI cannot reach it, and it cannot follow a central database.
