# Security policy

## Supported versions

Security fixes are released for the latest minor version, currently 0.1.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private reporting instead: go to the
[Security tab](https://github.com/vadimermolenko8787/scanner-trap/security) of this repository and click
"Report a vulnerability". Describe the problem, the setup it affects and, if you can, how to reproduce it.

You will get an answer as soon as possible. Once a fix is released, the advisory is published and you are credited,
unless you prefer otherwise.

## What counts

Anything that lets an attacker get a legitimate visitor blacklisted, get around a block, read or change the stored
lists, or run code through the package is a vulnerability.

Failing open is not. When a store is unreachable or broken, the package lets requests through and reports the
failure to the configured logger. That is by design: the trap must never take a site down.
