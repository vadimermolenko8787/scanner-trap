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

## Several servers sharing one Redis

    \ScannerTrap\ScannerTrap::guard(__DIR__ . '/../scanner-trap.php');

with `scanner-trap.php`:

    return [
        'local' => ['type' => 'redis', 'host' => '10.0.0.5', 'port' => 6379, 'database' => 0, 'prefix' => 'scanner-trap:'],
        // 'password' => '…' when Redis needs one
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
| `list [--active] [--ip=…]` | blocks with reason, server, expiry |
| `block <ip> [--reason=…] [--ttl=…]` | manual block; `--ttl=0` is forever; refused for a whitelisted IP |
| `unblock <ip>` | lift the block everywhere |
| `pattern:list`, `pattern:add <p>`, `pattern:remove <p>` | decoy patterns, validated |
| `allow:list`, `allow:add <entry> [--comment=…] [--ttl=…]`, `allow:remove <entry>` | whitelist |

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

`DefaultPatterns::LIST` is safe for any application. Add `DefaultPatterns::WORDPRESS_PROBES` only if the site is not
WordPress: `'patterns' => [...DefaultPatterns::LIST, ...DefaultPatterns::WORDPRESS_PROBES]`.

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
* **GET search forms.** A search box may legitimately send quote fragments such as `" or "`. Review the default `~`
  fragments for sites with a GET search, and drop or adjust the ones your visitors can produce.
* **Fetch Metadata limits.** Same-origin user content such as `<img src="/.env">` in a comment makes the browser send
  `Sec-Fetch-Site: same-origin`, so it blacklists everyone who views it: sanitise user content. Browsers that send no
  `Sec-Fetch-Site` are not protected from the cross-site case.
* **Owner marker.** Each local store remembers which central database it follows. After reinstalling the central
  database, delete the `{prefix}owner` key (Redis) or the `owner` file (file store) on each server, or sync refuses to
  run.
* **APCu** lives inside one PHP server: the CLI cannot reach it, and it cannot follow a central database.
