<?php

declare(strict_types=1);

namespace ScannerTrap\Exception;

/** A management action refused by validation; the message says why. The CLI exits with 2. */
final class RefusedException extends \RuntimeException
{
}
