<?php

declare(strict_types=1);

namespace ScannerTrap;

/** When trapped addresses escalate to their network: prefix and threshold per family, the counting window. */
final class SubnetPolicy
{
    public function __construct(
        private readonly int $v4Prefix = 24,
        private readonly int $v4Threshold = 3,
        private readonly int $v6Prefix = 64,
        private readonly int $v6Threshold = 1,
        private readonly int $window = 86400,
    ) {
        if ($v4Prefix < 8 || $v4Prefix > 31 || $v6Prefix < 16 || $v6Prefix > 127) {
            throw new \InvalidArgumentException('subnets: v4Prefix is 8 to 31, v6Prefix 16 to 127');
        }
        if ($v4Threshold < 1 || $v6Threshold < 1 || $window < 60) {
            throw new \InvalidArgumentException('subnets: thresholds are at least 1, the window at least 60 seconds');
        }
    }

    /** The 'subnets' config value: absent (null) = defaults, false = disabled. */
    public static function fromConfig(mixed $value): ?self
    {
        if ($value === false) {
            return null;
        }
        if ($value === null) {
            return new self();
        }
        if (!is_array($value)) {
            throw new \InvalidArgumentException("'subnets' is false or ['v4Prefix' => 24, 'v4Threshold' => 3, 'v6Prefix' => 64, 'v6Threshold' => 1, 'window' => 86400]");
        }
        $int = static function (string $key, int $default) use ($value): int {
            if (!array_key_exists($key, $value)) {
                return $default;
            }
            if (!is_int($value[$key])) {
                throw new \InvalidArgumentException("subnets.{$key} must be an integer");
            }
            return $value[$key];
        };
        return new self($int('v4Prefix', 24), $int('v4Threshold', 3), $int('v6Prefix', 64), $int('v6Threshold', 1), $int('window', 86400));
    }

    public function window(): int
    {
        return $this->window;
    }

    public function escalationFor(string $ip): ?Escalation
    {
        $address = Network::parse($ip);
        if ($address === null) {
            return null;
        }
        $v4 = $address->family === 4;
        $network = Network::of($ip, $v4 ? $this->v4Prefix : $this->v6Prefix);
        if ($network === null || $network->isReserved()) {
            return null;
        }
        return new Escalation($network->cidr(), $network->token(), $v4 ? $this->v4Threshold : $this->v6Threshold, $this->window);
    }
}
