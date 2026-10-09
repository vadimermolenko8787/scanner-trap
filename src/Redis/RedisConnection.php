<?php

declare(strict_types=1);

namespace ScannerTrap\Redis;

/**
 * The few Redis calls the package needs. A nil reply is null; a Redis error or a lost connection is a StoreException.
 * The message of an error reply must contain the server's error text: scripts run by hash and fall back to EVAL on
 * NOSCRIPT, which is recognized by that text.
 */
interface RedisConnection
{
    public function raw(string ...$args): mixed;
}
