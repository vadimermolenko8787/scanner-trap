<?php

declare(strict_types=1);

namespace ScannerTrap\Redis;

/** The few Redis calls the package needs. A nil reply is null; a Redis error or a lost connection is a StoreException. */
interface RedisConnection
{
    public function raw(string ...$args): mixed;
}
