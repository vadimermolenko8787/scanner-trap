<?php

declare(strict_types=1);

use ScannerTrap\Redis\PhpRedisConnection;
use ScannerTrap\Store\RedisLocalStore;

require __DIR__ . '/../../vendor/autoload.php';

// php import-list.php <count> <start at, unix time with microseconds>: imports the source "big" of <count> networks
[, $count, $startAt] = $argv;
$store = new RedisLocalStore(PhpRedisConnection::connect((string) getenv('SCANNER_TRAP_REDIS_HOST'), (int) getenv('SCANNER_TRAP_REDIS_PORT'), (int) getenv('SCANNER_TRAP_REDIS_DB'), null, 5.0, 30.0));
$networks = [];
for ($i = 0; $i < (int) $count; $i++) {
    $networks[] = sprintf('45.%d.%d.0/24', intdiv($i, 256), $i % 256);
}
while (microtime(true) < (float) $startAt) {
    usleep(500);
}
$store->replaceList('big', $networks, time());
