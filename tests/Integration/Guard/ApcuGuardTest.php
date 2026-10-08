<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Guard;

use ScannerTrap\Store\ApcuLocalStore;
use ScannerTrap\Store\LocalStore;

final class ApcuGuardTest extends GuardScenarios
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

    protected function corruptLists(): void
    {
        apcu_store('scanner-trap:patterns', '42');
    }

    protected function supportsEvents(): bool
    {
        return false;
    }
}
