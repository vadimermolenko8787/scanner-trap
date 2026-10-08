<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Guard;

use ScannerTrap\Redis\RedisConnection;
use ScannerTrap\Tests\Support\Env;

final class PredisGuardTest extends PhpRedisGuardTest
{
    protected function connect(): RedisConnection
    {
        return Env::predis();
    }
}
