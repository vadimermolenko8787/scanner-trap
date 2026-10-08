<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Central;

final class SqliteCentralStoreTest extends PdoCentralStoreContract
{
    protected function driver(): string
    {
        return 'sqlite';
    }
}
