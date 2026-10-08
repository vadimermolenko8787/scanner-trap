<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Store;

use ScannerTrap\Store\ApcuLocalStore;
use ScannerTrap\Store\LocalStore;

final class ApcuLocalStoreTest extends LocalStoreContract
{
    protected function setUp(): void
    {
        if (!extension_loaded('apcu') || !apcu_enabled()) {
            $this->markTestSkipped('ext-apcu with apc.enable_cli=1 is needed.');
        }
        apcu_clear_cache();
    }

    protected function createStore(): LocalStore
    {
        return new ApcuLocalStore();
    }

    protected function supportsEvents(): bool
    {
        return false;
    }
}
