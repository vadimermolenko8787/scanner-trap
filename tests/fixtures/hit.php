<?php

declare(strict_types=1);

use ScannerTrap\Guard;
use ScannerTrap\Redis\PhpRedisConnection;
use ScannerTrap\RequestContext;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\Store\RedisLocalStore;
use ScannerTrap\SubnetPolicy;

require __DIR__ . '/../../vendor/autoload.php';

// php hit.php <file|redis> <dir or prefix> <start at, unix time with microseconds> [ip] [escalate]
[, $type, $target, $startAt] = $argv;
$ip = $argv[4] ?? '203.0.113.9';
$subnets = ($argv[5] ?? '') === 'escalate' ? new SubnetPolicy() : null;
$store = $type === 'file'
    ? new FileLocalStore($target)
    : new RedisLocalStore(PhpRedisConnection::connect((string) getenv('SCANNER_TRAP_REDIS_HOST'), (int) getenv('SCANNER_TRAP_REDIS_PORT'), (int) getenv('SCANNER_TRAP_REDIS_DB'), null, 1.0, 1.0), $target);
$guard = new Guard($store, true, 600, 'web' . getmypid(), [], ['/.env*'], null, null, true, $subnets);
while (microtime(true) < (float) $startAt) {
    usleep(500);
}
echo $guard->decide(new RequestContext($ip, 'GET', '/.env'))->recorded ? 'recorded' : 'not recorded';
