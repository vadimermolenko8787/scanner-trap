<?php

declare(strict_types=1);

use ScannerTrap\Block;
use ScannerTrap\Central\PdoCentralStore;

require __DIR__ . '/../../vendor/autoload.php';

// php block-central.php <dsn> <user> <password> <count> <second octet> <start at, unix time with microseconds>:
// pushes blocks of <count> addresses in 45.<second octet>.0.0/16 into the central database, as a sync does; a failure goes to stderr, exit 1
[, $dsn, $user, $password, $count, $octet, $startAt] = $argv;
$store = new PdoCentralStore(new \PDO($dsn, $user, $password, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]));
$blocks = [];
for ($i = 0; $i < (int) $count; $i++) {
    $blocks[] = new Block(sprintf('45.%d.%d.%d', (int) $octet, intdiv($i, 250), $i % 250 + 1), time(), time() + 3600);
}
while (microtime(true) < (float) $startAt) {
    usleep(500);
}
try {
    $store->insertBlocks($blocks);
} catch (\Throwable $e) {
    fwrite(STDERR, $e->getMessage());
    exit(1);
}
