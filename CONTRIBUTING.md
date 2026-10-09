# Contributing

Thanks for taking the time to improve scanner-trap. Bug reports, fixes and new decoy patterns are all welcome.

## Reporting a bug

Open an issue with the package version, your PHP version, the store you use (files, Redis, APCu, central database)
and what you expected to happen. A config with the secrets removed and a few log lines help a lot. If the bug lets a
scanner through or locks real visitors out, it may be a security issue: please follow [SECURITY.md](SECURITY.md)
instead.

## Suggesting a pattern

A good decoy is something no real visitor of any site ever requests. Please mention where you saw the probe and why
you are sure it cannot be legitimate traffic. Patterns that only make sense for some sites belong in an opt-in list,
like `DefaultPatterns::WORDPRESS_PROBES`.

## Setting up

You need PHP 8.1 or newer, Composer, and for the full test suite the `redis` and `apcu` extensions, a Redis server and
Docker.

```bash
git clone git@github.com:vadimermolenko8787/scanner-trap.git
cd scanner-trap
composer install
```

## Running the tests

```bash
composer test     # PHPUnit
composer stan     # PHPStan at level max
composer cs       # coding style check, `composer cs:fix` fixes it
```

The tests use a Redis server on `127.0.0.1:6379` and **flush database 12** on it. Point them elsewhere with
`SCANNER_TRAP_REDIS_HOST`, `SCANNER_TRAP_REDIS_PORT` and `SCANNER_TRAP_REDIS_DB`.

SQLite tests always run. MySQL and PostgreSQL tests are skipped unless you start the databases and tell the tests
where they are:

```bash
docker compose up -d
SCANNER_TRAP_MYSQL_DSN="mysql:host=127.0.0.1;port=33306;dbname=trap" \
SCANNER_TRAP_PGSQL_DSN="pgsql:host=127.0.0.1;port=55432;dbname=trap" \
composer test
```

CI runs everything on PHP 8.1, 8.2, 8.3 and 8.4 with Redis, MySQL and PostgreSQL, and fails on skipped tests.

## Pull requests

Keep a pull request to one change, and include tests for it. Behaviour that every store must share belongs in the
contract tests under `tests/Integration/Store` and `tests/Integration/Central`, so that it runs against all of them.
Add a line to `CHANGELOG.md` for anything a user would notice.

Commit messages follow the existing history: a type (`feat`, `fix`, `docs`, `test`) and one sentence saying what the
package does now, for example `fix: an expired block file is never deleted while another process recreates it`.

[docs/architecture.md](docs/architecture.md) explains how the package is put together and why. It is worth a read
before larger changes.
