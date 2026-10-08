<?php

declare(strict_types=1);

use ScannerTrap\Central\PdoCentralStore;
use ScannerTrap\ListSource;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\TrapManager;

require __DIR__ . '/../../vendor/autoload.php';

// php -d memory_limit=128M import-big.php <sqlite file> <local dir> <list file>: imports the list twice through the TrapManager
[, $database, $dir, $list] = $argv;
$manager = new TrapManager(
    new FileLocalStore($dir),
    new PdoCentralStore(new PDO('sqlite:' . $database)),
    [],
    [],
    listSources: ListSource::fromConfig([['name' => 'big', 'file' => $list]]),
);
$manager->install('test');
for ($run = 0; $run < 2; $run++) {
    $result = $manager->import()['big'];
    if ($result['error'] !== null) {
        fwrite(STDERR, $result['error'] . "\n");
        exit(1);
    }
}
