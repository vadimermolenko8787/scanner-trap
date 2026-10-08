<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Support;

use Psr\Log\AbstractLogger;

final class MemoryLogger extends AbstractLogger
{
    /** @var list<array{mixed, string, array<mixed>}> */
    public array $records = [];

    /** @param array<mixed> $context */
    public function log($level, string|\Stringable $message, array $context = []): void
    {
        $this->records[] = [$level, (string) $message, $context];
    }
}
