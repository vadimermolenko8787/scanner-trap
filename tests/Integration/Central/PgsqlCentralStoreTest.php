<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Central;

final class PgsqlCentralStoreTest extends PdoCentralStoreContract
{
    protected function driver(): string
    {
        return 'pgsql';
    }
}
