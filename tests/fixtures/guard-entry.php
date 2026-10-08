<?php

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

// php guard-entry.php <config as JSON> <client ip> <uri>: what index.php does, with display_errors on
ini_set('display_errors', '1');
error_reporting(E_ALL);
$config = json_decode($argv[1], true);
$_SERVER['REMOTE_ADDR'] = $argv[2];
$_SERVER['REQUEST_URI'] = $argv[3];
$_SERVER['REQUEST_METHOD'] = 'GET';
\ScannerTrap\ScannerTrap::guard(is_array($config) ? $config : []);
echo 'PASSED';
