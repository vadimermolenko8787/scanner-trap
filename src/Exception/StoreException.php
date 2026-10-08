<?php

declare(strict_types=1);

namespace ScannerTrap\Exception;

/** A store is unreachable or answered something unusable. The CLI exits with 3. */
final class StoreException extends \RuntimeException
{
}
