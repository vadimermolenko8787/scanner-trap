# scanner-trap

[![CI](https://github.com/vadimermolenko8787/scanner-trap/actions/workflows/ci.yml/badge.svg)](https://github.com/vadimermolenko8787/scanner-trap/actions/workflows/ci.yml)
[![PHP](https://img.shields.io/badge/php-8.1%20to%208.4-777bb4)](composer.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Every public PHP site gets probed for `/.env`, `/.git/config`, `/phpmyadmin` and `?id=1 UNION SELECT` many times a
day. No real visitor ever asks for those. scanner-trap treats such a request as a confession: the address that sent
it is blacklisted, and from then on it gets `403 Forbidden` on every page, so the scanner never reaches the rest of
your site.

```text
45.155.205.9  GET /                 200  looks like a visitor
45.155.205.9  GET /.env             403  decoy: the address is blacklisted
45.155.205.9  GET /login            403  refused from now on
```

It is a small Composer package with no framework requirement. One call at the top of `public/index.php` is enough
on a single server, and the same package scales to a fleet behind a load balancer.

## Contents

1. [How it works](#how-it-works)
2. [Quick start](#quick-start)
3. [Going live](#going-live)
4. [Choosing a setup](#choosing-a-setup)
5. [Web server routing](#web-server-routing)
6. [What gets trapped](#what-gets-trapped)
7. [Scanners that change address](#scanners-that-change-address)
8. [Imported blocklists](#imported-blocklists)
9. [Command line](#command-line)
10. [Configuration reference](#configuration-reference)
11. [Things to know](#things-to-know)
12. [Troubleshooting](#troubleshooting)

## How it works

1. The package keeps a list of decoys: paths, query fragments and scanner User-Agents that a person browsing your
   site would never produce.
2. When a request matches a decoy, the client's address is written to a blacklist with an expiry, seven days by
   default.
3. Every request first asks the blacklist, in a single round trip to the store. A blacklisted address gets `403`.
4. When several addresses of one network get caught, the whole network is blocked, because scanners like to rotate
   addresses.
5. Optionally, public blocklists such as Spamhaus DROP are imported and refused as well.

Anything that goes wrong inside the package, an unreachable Redis, a broken file, a PHP warning, lets the request
through and is reported to your logger. The trap can make your site safer, never unavailable.

It is not a rate limiter and it does not stop floods. Leave that to the web server, a CDN or a WAF.

## Quick start

You need PHP 8.1 or newer and Composer.

```bash
composer require vadimermolenko8787/scanner-trap
```

Create `scanner-trap.php` in your project root. A directory the web server can write to is all it needs:

```php
<?php

return [
    'local' => ['type' => 'file', 'dir' => __DIR__ . '/var/scanner-trap'],
];
```

Call the guard at the very top of `public/index.php`, right after the autoloader and before your application boots:

```php
require __DIR__ . '/../vendor/autoload.php';

\ScannerTrap\ScannerTrap::guard(__DIR__ . '/../scanner-trap.php');
```

This works with any application that has a front controller, framework or not. A PSR-15 middleware is available
too, see [PSR-15 middleware](#psr-15-middleware).

Out of the box the trap runs in **watch mode**: it records scanners but refuses nobody. See who it catches:

```bash
vendor/bin/scanner-trap list
```

## Going live

Give watch mode a few days of real traffic, then go through this list before you switch refusing on.

1. Run `vendor/bin/scanner-trap list` and check that every address on it is a scanner. If you find one of your own
   users, the last two columns show which pattern caught them and what they requested.
2. If your application really serves a path that a decoy covers, a genuine `/admin` for example, add it to
   `ownPaths`. Decoys never apply below those paths.
3. If the site sits behind a load balancer, a reverse proxy or a CDN, set `trustedProxies`. Without it every
   request seems to come from the proxy, and the trap would end up blacklisting the proxy itself.
4. Configure a PSR-3 `logger`. It is the only way to find out that the trap failed open, for example because Redis
   was down.
5. Make sure scanner probes actually reach PHP, see [Web server routing](#web-server-routing).

Then turn it on:

```php
return [
    'local' => ['type' => 'file', 'dir' => __DIR__ . '/var/scanner-trap'],
    'blocking' => true,
    'logger' => $logger,
];
```

## Choosing a setup

| Your situation | Local store | Central database | Sync |
|---|---|---|---|
| One server | files, Redis or APCu | none | none |
| Several servers, one Redis they all reach | the shared Redis | none | none |
| Several servers, each with its own Redis or disk | files or Redis per server | MySQL, MariaDB, PostgreSQL or SQLite | `scanner-trap sync` from cron |

Pick the first row that fits. A shared Redis is the simplest way to run several servers. The central database is
for fleets without one, and it also keeps a full history of who was blocked, when and by which server.

### One server

The file store from the quick start needs nothing but a writable directory. Redis works the same way on one server,
and APCu works when you never need the command line (see [Things to know](#things-to-know)).

The web server and the command line must run as the same user, otherwise one cannot write what the other created.
Run the CLI as the web server user:

```bash
sudo -u www-data vendor/bin/scanner-trap list
```

### Several servers sharing one Redis

Point every server at the same Redis:

```php
return [
    'local' => [
        'type' => 'redis',
        'host' => '10.0.0.5',
        'port' => 6379,
        'database' => 0,
        'password' => 'secret',     // only if your Redis needs one
        'prefix' => 'scanner-trap:',
        'persistent' => true,       // reuse the connection between requests
    ],
    'blocking' => true,
];
```

All servers read and write the same keys, so a scanner caught on one server is refused by all of them at once.
There is nothing to sync. If your application already has a Redis client, pass it instead of the connection
settings: `'local' => ['type' => 'redis', 'client' => $redis]` accepts phpredis and Predis.

### Several servers with a central database

Each server keeps its own fast local store, and a database holds the truth for all of them:

```php
return [
    'local' => ['type' => 'redis', 'host' => '127.0.0.1'],
    'central' => [
        'dsn' => 'mysql:host=db.internal;dbname=app',
        'user' => 'trap',
        'password' => 'secret',
        'tablePrefix' => 'scanner_trap_',
    ],
    'blocking' => true,
];
```

Create the tables once, from any server:

```bash
vendor/bin/scanner-trap install
```

Then run the sync on every server from cron:

```cron
* * * * * cd /var/www/app && sudo -u www-data vendor/bin/scanner-trap sync --watch=50
```

Each run sends the blocks made on this server to the database straight away and picks up everything the other
servers did, so a scanner caught anywhere is refused everywhere within a minute. Hits on different servers add up
for [network blocking](#scanners-that-change-address). If your project has its own long-running worker, it can call
`ScannerTrap::fromConfig($config)->manager()->sync(50)` instead of cron.

In this setup patterns and the whitelist live in the database. The `patterns` and `allow` keys of the config only
seed it on `install`, and from then on you manage them with the command line.

### PSR-15 middleware

Applications built on PSR-15 can add the trap as middleware instead of calling `guard()`:

```php
$trap = \ScannerTrap\ScannerTrap::fromConfig(require __DIR__ . '/../scanner-trap.php');

$app->add($trap->middleware($responseFactory));
```

A refused request gets a `403` from the response factory you pass in, every other request goes on to your
application.

## Web server routing

The trap only sees requests that reach PHP. Two common nginx habits answer the most popular probes before PHP ever
sees them, and those scanners then go unnoticed.

Missing `.php` files such as `/wp-login.php` or `/xmlrpc.php` get PHP-FPM's "File not found." page. Send them to your
front controller instead, in the `location ~ \.php$` block:

```nginx
try_files $uri /index.php?$query_string;
```

Dot paths such as `/.env` and `/.git/config` are often closed with `deny all;`. Hand them to PHP instead, the file
itself is still never served:

```nginx
location ~ /\.(?!well-known) {
    rewrite ^ /index.php last;
}
```

## What gets trapped

The default list, `DefaultPatterns::LIST`, is safe for any site. It covers secrets and VCS folders (`/.env`,
`/.git`, `/.aws`, `/.ssh`), admin tools (`/phpmyadmin`, `/pma`, `/server-status`, `/actuator`), backups and dumps
(`*.sql`, `*.bak`, `*.php.old`), well-known exploit paths (`/vendor/phpunit`, `/cgi-bin`, `/boaform`), SQL injection
fragments that only an attack produces (`union select`, `' or 1`, `from information_schema`), and the User-Agents of
scanning tools (`sqlmap`, `nikto`, `nuclei`, `zgrab` and others).

A pattern is written in one of five forms:

| Form | Example | Matches |
|---|---|---|
| path | `/phpmyadmin` | that path and everything below it, `/phpmyadmin/index.php` too, but not `/phpmyadmin-docs` |
| path prefix | `/.env*` | every path starting with `/.env`, such as `/.env.production` |
| extension | `*.sql` | any path ending in `.sql` |
| query fragment | `~union select` | the text anywhere in the decoded URL, ignoring case, comments and extra spaces |
| User-Agent | `@sqlmap` | the text anywhere in the User-Agent, ignoring case, on any page |

Two more lists are opt-in:

| Constant | Add it when |
|---|---|
| `DefaultPatterns::WORDPRESS_PROBES` | your site is **not** WordPress: `/wp-admin`, `/wp-login.php`, `/xmlrpc.php` and friends |
| `DefaultPatterns::LOOSE_FRAGMENTS` | none of your query strings carries free text: fragments such as `" or "` and `sleep(` that a search box can produce |

```php
use ScannerTrap\DefaultPatterns;

return [
    'local' => ['type' => 'file', 'dir' => __DIR__ . '/var/scanner-trap'],
    'patterns' => [...DefaultPatterns::LIST, ...DefaultPatterns::WORDPRESS_PROBES, '/old-admin'],
];
```

Every pattern is validated before it is stored. The package refuses patterns that would hit real visitors, such as
`*.js`, a path covering one of your `ownPaths`, or a User-Agent fragment that every browser sends, like `@mozilla`.

## Scanners that change address

Many scanners switch to a new address as soon as one gets blocked. Three features close that gap.

**Network blocking** is on by default. When three different addresses of one IPv4 `/24` get caught within 24 hours,
the whole `/24` is blocked. For IPv6 the first hit blocks its `/64`, because a single machine usually owns a whole
`/64`. Private and reserved networks are never blocked this way.

```php
'subnets' => ['v4Prefix' => 24, 'v4Threshold' => 3, 'v6Prefix' => 64, 'v6Threshold' => 1, 'window' => 86400],
// or turn it off:
'subnets' => false,
```

Be careful if many of your visitors come through mobile networks. Carriers put thousands of unrelated people behind
a few shared addresses (CGNAT), and a `/24` there can hold real customers. Raise `v4Threshold`, use a narrower
`v4Prefix`, or turn the feature off. A whitelist entry always beats a network block.

**Scanner signatures** catch tools by their User-Agent on any page, decoy or not. The default list knows the usual
suspects, and you can add more with `scanner-trap pattern:add '@mytool'`.

**Imported blocklists** refuse known bad networks before they even try, see the next section.

## Imported blocklists

```php
'lists' => [
    'spamhaus-drop',
    'firehol-level1',
    ['name' => 'blocklist-de', 'url' => 'https://lists.blocklist.de/lists/all.txt'],
    ['name' => 'own', 'file' => __DIR__ . '/deny.txt'],
],
```

`spamhaus-drop` and `firehol-level1` are built in. Any other source is a URL or a local file with one IP or CIDR per
line. Lines starting with `#` or `;` are comments, and `'format' => 'spamhaus-json'` reads Spamhaus' JSON format.

Fetch the lists daily from cron:

```cron
17 4 * * * cd /var/www/app && sudo -u www-data vendor/bin/scanner-trap import
```

The import skips private and reserved networks and anything wider than `/8` for IPv4 or `/16` for IPv6, and it caps
each download at 16 MB. If one source fails, the others are still imported and the failed one keeps its previous
entries. With a central database, run the import on one server only. The others receive the lists with their next
sync.

Listed addresses are refused while `blocking` is on. They are not blacklisted, so they disappear when the list drops
them, and a whitelist entry still wins. `scanner-trap lists` shows each source with its size and the time of its last
import.

## Command line

```text
vendor/bin/scanner-trap [--config=path] <command>
```

The CLI reads `./scanner-trap.php` unless you pass `--config`.

| Command | What it does |
|---|---|
| `list [--active] [--ip=IP]` | Shows blocks with their reason, server and expiry. With `--ip`, the address's own block and any network block covering it. |
| `block <ip or cidr> [--reason=TEXT] [--ttl=SECONDS]` | Blocks an address or a network by hand. `--ttl=0` blocks forever. |
| `unblock <ip or cidr>` | Lifts a block on every server. |
| `allow:list`, `allow:add <entry> [--comment=TEXT] [--ttl=SECONDS]`, `allow:remove <entry>` | Manages the whitelist: IPs, CIDR ranges and masks like `192.168.0.*`. |
| `pattern:list`, `pattern:add <pattern>`, `pattern:remove <pattern>` | Manages the decoy patterns. |
| `import [--source=NAME]` | Fetches all configured blocklists, or one. |
| `lists` | Shows each blocklist source with its size and last import. |
| `install` | Creates the tables with a central database. Without one, writes the config's patterns and whitelist to the store, replacing what was added through the CLI. |
| `sync [--watch=SECONDS]` | Exchanges blocks with the central database, then keeps sending new blocks for the given time. |
| `prune [--keep=SECONDS]` | Deletes history older than 30 days, or the given time, from the central database and expired files from the file store. |

Exit codes are `0` for success, `1` for a usage error, `2` when the action was refused (an invalid pattern, say) and
`3` when a store could not be reached. The CLI notes who acted, as user and host such as `deploy@web1`: as the reason
of a manual block, as the author of whitelist entries, and with a central database also as the author of patterns and
of lifted blocks.

Run `prune` daily. With file stores, run it on every server:

```cron
23 3 * * * cd /var/www/app && sudo -u www-data vendor/bin/scanner-trap prune
```

## Configuration reference

| Key | Default | Meaning |
|---|---|---|
| `local` | required | Where blocks are kept on this server: `['type' => 'file', 'dir' => …]`, `['type' => 'redis', 'host', 'port', 'database', 'password', 'prefix', 'persistent']`, `['type' => 'redis', 'client' => $redis]` or `['type' => 'apcu']`. |
| `central` | `null` | The central database: `['dsn' => …, 'user' => …, 'password' => …, 'tablePrefix' => 'scanner_trap_']`. |
| `blocking` | `false` | `true` refuses blacklisted and listed addresses. `false` is watch mode: everything is recorded, nobody is refused. |
| `blockTtl` | `604800` | How long a block lasts, in seconds. `0` means forever. |
| `patterns` | `DefaultPatterns::LIST` | The decoys. With a central database this only seeds `install`. |
| `allow` | `[]` | Addresses that are never refused: IPs, CIDR ranges, masks like `192.168.0.*`. With a central database this only seeds `install`. |
| `ownPaths` | `[]` | Paths your site really serves. Path and extension decoys never apply below them. |
| `trustedProxies` | `[]` | CIDR ranges of your load balancers or CDN. `X-Forwarded-For` is read only when the request comes from one of them. |
| `subnets` | see above | Network blocking. `false` turns it off. |
| `lists` | `[]` | Blocklists to import. |
| `serverName` | the host name | Recorded with every block, so you can tell which server caught whom. |
| `logger` | `null` | Any PSR-3 logger. Receives new blocks and every failure. |

Without a central database, the config's `patterns` and `allow` are used until you first change either of them with
the CLI. From then on the stored lists are used.

## Things to know

**Behind Cloudflare.** Use the ranges that ship with the package, alone or together with your own:

```php
'trustedProxies' => [...\ScannerTrap\TrustedProxies::CLOUDFLARE, '10.0.0.0/8'],
```

Cloudflare rarely changes its ranges. New releases of the package update the constant.

**Only trust proxies you control.** `X-Forwarded-For` is easy to fake. It is read only for requests coming from
`trustedProxies`, and from the right, so a client cannot pick the address that gets judged.

**Links from other sites.** A hostile page could embed `<img src="https://your-site/.env">` to get its visitors
blacklisted on your site. Browsers mark such requests with `Sec-Fetch-Site: cross-site`, and the trap refuses them
without blacklisting anyone. Older browsers do not send that header.

**Links on your own site.** The same trick works from inside your site, through user content such as a comment
with an image pointing at a decoy. Everyone who views that page would be blacklisted. Sanitise user content, as you
should anyway.

**Search boxes.** Queries like `"rock" or "roll"` look a lot like SQL injection. That is why the fragments a search
box can produce live in the opt-in `LOOSE_FRAGMENTS` list.

**APCu.** An APCu store lives inside one PHP-FPM pool. The command line cannot reach it, so you cannot list, import
or unblock from the CLI, and it cannot follow a central database. Use it only when you need nothing but the guard.

**Overhead.** One store round trip per request. On a test machine with 6 000 imported networks the check took about
half a millisecond with the file store and less with Redis.

## Troubleshooting

**Nobody gets caught.** Check that probes reach PHP at all, see [Web server routing](#web-server-routing), and that
requests do not all come from `127.0.0.1`. Loopback addresses are never judged, so behind a local proxy you need
`trustedProxies`.

**Your load balancer got blacklisted.** Add its range to `trustedProxies` and run
`scanner-trap unblock <its address>`.

**Nothing is refused although blocks are listed.** `blocking` is still `false`, or the logger shows that the trap
failed open.

**Files the CLI created are not writable by the web server, or the other way round.** Run the CLI as the web server
user, or give both the same group and `umask 002`.

**A corrupt `networks.json` or `lists.current` in the file store.** The trap fails open for those lookups and logs
it. Delete the file. Network blocks come back with the next hit, imported lists with the next `scanner-trap import`.

**`sync` refuses to run after you reinstalled the central database.** Each local store remembers which database it
follows, so that two installations can never mix. Delete the `{prefix}owner` key in Redis or the `owner` file in the
file store on every server.

## Design

[docs/architecture.md](docs/architecture.md) explains how the package works inside, its data layout and the reasons
behind its decisions.

## Contributing

Bug reports and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) explains how to run the test suite.
Please report security issues privately, as described in [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
