<?php

declare(strict_types=1);

namespace ScannerTrap;

/**
 * Pure matching and validation. Ported from ifbck's ScannerTrap (umnify-master) and scaner-trap-ifbc's Rules: the same
 * normalizing and matching, byte for byte.
 */
final class Rules
{
    public const TYPE_PREFIX = 'prefix';
    public const TYPE_SUFFIX = 'suffix';
    /** `~union select`: a fragment anywhere in the decoded URI, query string included. */
    public const TYPE_CONTAINS = 'contains';
    private const LOOPBACK = ['127.0.0.0/8', '::1'];

    /** One key per address: the IPv6 spellings of one address collapse, so an unblock finds the block. */
    public static function normalizeIp(string $ip): ?string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $packed = inet_pton($ip);
        $normalized = $packed === false ? false : inet_ntop($packed);
        return $normalized === false ? null : $normalized;
    }

    public static function isLoopback(string $ip): bool
    {
        return self::isAllowed($ip, self::LOOPBACK);
    }

    public static function normalizePath(string $path): string
    {
        return (string) preg_replace('#/{2,}#', '/', self::lower(rawurldecode($path)));
    }

    /** Decoded until stable (`%2527` too, `+` is a space), lowercase, SQL comments and whitespace runs as one space. */
    public static function normalizeUri(string $uri): string
    {
        for ($i = 0; $i < 3 && ($decoded = urldecode($uri)) !== $uri; $i++) {
            $uri = $decoded;
        }
        return (string) preg_replace(['#/\*.*?\*/#s', '/\s+/'], ' ', strtolower($uri));
    }

    public static function patternType(string $pattern): string
    {
        return match (true) {
            str_starts_with($pattern, '*.') => self::TYPE_SUFFIX,
            str_starts_with($pattern, '~') => self::TYPE_CONTAINS,
            default => self::TYPE_PREFIX,
        };
    }

    /**
     * The pattern as stored (`/wp-admin`, `/.env*`, `*.php.bak`) that matches the normalized path, null for none.
     *
     * @param array<mixed> $patterns
     */
    public static function matchedPattern(string $path, array $patterns): ?string
    {
        foreach ($patterns as $pattern) {
            if (!is_string($pattern)) {
                continue;
            }
            $type = self::patternType($pattern);
            if ($type === self::TYPE_CONTAINS) {
                continue;
            }
            if ($type === self::TYPE_SUFFIX) {
                $matches = str_ends_with($path, substr($pattern, 1));
            } elseif (str_ends_with($pattern, '*')) {
                $matches = str_starts_with($path, substr($pattern, 0, -1));
            } else {
                $matches = $path === $pattern || str_starts_with($path, $pattern . '/');
            }
            if ($matches) {
                return $pattern;
            }
        }
        return null;
    }

    /**
     * The stored fragment (`~union select`) found in the raw URI, null for none.
     *
     * @param array<mixed> $patterns
     */
    public static function matchedFragment(string $uri, array $patterns): ?string
    {
        $haystack = null;
        foreach ($patterns as $pattern) {
            if (is_string($pattern) && self::patternType($pattern) === self::TYPE_CONTAINS) {
                $haystack ??= self::normalizeUri($uri);
                if (str_contains($haystack, substr($pattern, 1))) {
                    return $pattern;
                }
            }
        }
        return null;
    }

    /**
     * Exact IP, CIDR range, or an IPv4 mask whose every * stands for one whole octet; anything else matches nothing.
     *
     * @param array<mixed> $entries
     */
    public static function isAllowed(string $ip, array $entries): bool
    {
        foreach ($entries as $entry) {
            if (!is_string($entry)) {
                continue;
            }
            if (str_contains($entry, '*') ? self::matchesMask($ip, $entry) : self::inRange($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A path the site serves itself, by whole segments: path and extension patterns do not apply to it.
     *
     * @param array<mixed> $ownPaths
     */
    public static function underOwnPath(string $path, array $ownPaths): bool
    {
        foreach ($ownPaths as $own) {
            $own = rtrim(self::lower(trim((string) (is_scalar($own) ? $own : ''))), '/');
            if ($own !== '' && ($path === $own || str_starts_with($path, $own . '/'))) {
                return true;
            }
        }
        return false;
    }

    private static function inRange(string $ip, string $range): bool
    {
        $parts = explode('/', $range, 2);
        $address = @inet_pton($ip);
        $network = @inet_pton($parts[0]);
        if ($address === false || $network === false || strlen($address) !== strlen($network)) {
            return false;
        }
        $width = strlen($address) * 8;
        $bits = count($parts) === 2 ? $parts[1] : (string) $width;
        if (!preg_match('/^\d{1,3}$/', $bits) || (int) $bits > $width) {
            return false;
        }
        $bytes = intdiv((int) $bits, 8);
        if (substr($address, 0, $bytes) !== substr($network, 0, $bytes)) {
            return false;
        }
        $rest = (int) $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rest)) & 0xff;
        return (ord($address[$bytes]) & $mask) === (ord($network[$bytes]) & $mask);
    }

    private static function matchesMask(string $ip, string $entry): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }
        $octets = explode('.', $entry);
        if (count($octets) !== 4) {
            return false;
        }
        foreach (array_map(null, $octets, explode('.', $ip)) as [$octet, $actual]) {
            if ($octet !== '*' && (int) $octet !== (int) $actual) {
                return false;
            }
        }
        return true;
    }

    private static function lower(string $value): string
    {
        return function_exists('mb_strtolower') ? mb_strtolower($value) : strtolower($value);
    }
}
