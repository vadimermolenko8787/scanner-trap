<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Guard;

use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\Store\LocalStore;

final class FileGuardTest extends GuardScenarios
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/scanner-trap-guard-' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    protected function createStore(): LocalStore
    {
        return new FileLocalStore($this->dir);
    }

    protected function corruptLists(): void
    {
        @mkdir($this->dir, 0775, true);
        file_put_contents($this->dir . '/patterns.json', '{"not":"a list"}');
    }
}
