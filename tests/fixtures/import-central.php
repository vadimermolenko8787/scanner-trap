<?php

declare(strict_types=1);

use ScannerTrap\Central\PdoCentralStore;

require __DIR__ . '/../../vendor/autoload.php';

// php import-central.php <dsn> <user> <password> <count> <start at, unix time with microseconds>:
// imports the source "big" of <count> networks into the central database; a failure goes to stderr, exit 1
[, $dsn, $user, $password, $count, $startAt] = $argv;
$store = new PdoCentralStore(new \PDO($dsn, $user, $password, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]));
$networks = [];
for ($i = 0; $i < (int) $count; $i++) {
    $networks[] = sprintf('45.%d.%d.0/24', intdiv($i, 256), $i % 256);
}
while (microtime(true) < (float) $startAt) {
    usleep(500);
}
try {
    $store->replaceList('big', $networks, time());
} catch (\Throwable $e) {
    fwrite(STDERR, $e->getMessage());
    exit(1);
}
