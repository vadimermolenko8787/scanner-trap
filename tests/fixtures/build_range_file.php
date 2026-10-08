<?php

declare(strict_types=1);

// Builds a RangeFile of 200 000 networks and looks two addresses up; run under a small memory_limit by RangeFileTest.
require dirname(__DIR__, 2) . '/vendor/autoload.php';

use ScannerTrap\Store\RangeFile;

$networks = static function (): \Generator {
    for ($i = 0; $i < 200_000; $i++) {
        yield sprintf('%d.%d.%d.0/24', 45 + intdiv($i, 65536), intdiv($i, 256) % 256, $i % 256);
    }
};
$file = (string) tempnam(sys_get_temp_dir(), 'ranges-');
file_put_contents($file, RangeFile::build(['big' => $networks()]));
$ok = RangeFile::lookup($file, '45.7.9.1') === 'big' && RangeFile::lookup($file, '49.0.0.1') === null;
unlink($file);
exit($ok ? 0 : 1);
