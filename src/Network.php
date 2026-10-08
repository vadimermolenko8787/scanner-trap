<?php

declare(strict_types=1);

namespace ScannerTrap;

/** An IPv4 or IPv6 network in CIDR form, normalized: host bits cleared, IPv6 compressed, IPv4-mapped IPv6 as IPv4. */
final class Network
{
    /** Never escalated to and never imported: private, loopback, link-local, CGNAT, documentation, multicast. */
    private const RESERVED = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
        '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3',
        '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '2001:db8::/32',
    ];

    /** @var list<self>|null */
    private static ?array $reserved = null;

    private function __construct(
        public readonly int $family,
        public readonly int $prefix,
        public readonly string $address,
        private readonly string $packed,
    ) {
    }

    public static function parse(string $value): ?self
    {
        $parts = explode('/', trim($value), 2);
        $raw = @inet_pton($parts[0]);
        $ip = Rules::normalizeIp($parts[0]);
        $packed = $ip === null ? false : inet_pton($ip);
        if ($raw === false || $packed === false) {
            return null;
        }
        $width = strlen($packed) * 8;
        if (count($parts) === 1) {
            return self::fromPacked($packed, $width);
        }
        if (preg_match('/^\d{1,3}$/', $parts[1]) !== 1 || (int) $parts[1] > strlen($raw) * 8) {
            return null;
        }
        $prefix = (int) $parts[1];
        // ::ffff:a.b.c.d/120 is a.b.c.d/24: the mapped prefix counts the 96 bits in front
        if (strlen($raw) === 16 && strlen($packed) === 4) {
            if ($prefix < 96) {
                return null;
            }
            $prefix -= 96;
        }
        return self::fromPacked($packed, $prefix);
    }

    public static function of(string $ip, int $prefix): ?self
    {
        $network = self::parse($ip);
        return $network === null || $prefix < 0 || $prefix > $network->prefix ? null : self::fromPacked($network->packed, $prefix);
    }

    /** @return array<string, string> token => cidr, for every prefix length of the address's family */
    public static function candidates(string $ip): array
    {
        $network = self::parse($ip);
        if ($network === null) {
            return [];
        }
        $candidates = [];
        for ($prefix = 0; $prefix <= $network->prefix; $prefix++) {
            $candidate = self::fromPacked($network->packed, $prefix);
            $candidates[$candidate->token()] = $candidate->cidr();
        }
        return $candidates;
    }

    public function cidr(): string
    {
        return $this->address . '/' . $this->prefix;
    }

    public function token(): string
    {
        return $this->family . '/' . $this->prefix;
    }

    public function contains(string $ip): bool
    {
        $other = self::parse($ip);
        return $other !== null && $other->family === $this->family && self::mask($other->packed, $this->prefix) === $this->packed;
    }

    public function overlaps(self $other): bool
    {
        if ($other->family !== $this->family) {
            return false;
        }
        $prefix = min($this->prefix, $other->prefix);
        return self::mask($this->packed, $prefix) === self::mask($other->packed, $prefix);
    }

    public function isReserved(): bool
    {
        if (self::$reserved === null) {
            self::$reserved = [];
            foreach (self::RESERVED as $cidr) {
                $network = self::parse($cidr);
                if ($network !== null) {
                    self::$reserved[] = $network;
                }
            }
        }
        foreach (self::$reserved as $reserved) {
            if ($this->overlaps($reserved)) {
                return true;
            }
        }
        return false;
    }

    private static function fromPacked(string $packed, int $prefix): self
    {
        $masked = self::mask($packed, $prefix);
        return new self(strlen($masked) === 4 ? 4 : 6, $prefix, (string) inet_ntop($masked), $masked);
    }

    private static function mask(string $packed, int $prefix): string
    {
        $bytes = intdiv($prefix, 8);
        $masked = substr($packed, 0, $bytes);
        $rest = $prefix % 8;
        if ($rest > 0) {
            $masked .= chr(ord($packed[$bytes]) & ((0xff << (8 - $rest)) & 0xff));
        }
        return str_pad($masked, strlen($packed), "\0");
    }
}
