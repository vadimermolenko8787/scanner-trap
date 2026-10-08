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

    /** Served by any site: a pattern ending in one of these would block real visitors. */
    private const SITE_EXTENSIONS = [
        'js', 'css', 'map', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'avif', 'ico', 'woff', 'woff2', 'ttf', 'otf', 'eot',
        'php', 'html', 'htm', 'json', 'xml', 'txt', 'pdf',
    ];

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

    /** How a pattern is stored and compared: lowercase, no surrounding spaces, no trailing slash; a fragment's spaces as one. */
    public static function normalizePattern(string $pattern): string
    {
        $pattern = self::lower(trim($pattern));
        if (str_starts_with($pattern, '~')) {
            return '~' . preg_replace('/\s+/', ' ', trim(substr($pattern, 1)));
        }
        return strlen($pattern) > 1 ? rtrim($pattern, '/') : $pattern;
    }

    /**
     * Null when the normalized pattern may be stored, else why not.
     *
     * @param array<mixed> $ownPaths
     */
    public static function patternError(string $pattern, array $ownPaths = []): ?string
    {
        $type = self::patternType($pattern);
        // A word alone or a path piece would match ordinary requests anywhere: it needs SQL punctuation or two words
        if ($type === self::TYPE_CONTAINS) {
            $fragment = substr($pattern, 1);
            return strlen($fragment) >= 6 && !preg_match('#[/?&]#', $fragment) && preg_match('/[\'"()=@;#]|\S \S/', $fragment)
                ? null
                : 'A fragment starts with ~, has at least 6 characters and no / ? or &, and contains a quote, a bracket, =, @, ;, # or two words';
        }
        if ($type === self::TYPE_SUFFIX) {
            if (!preg_match('/^\*\.([a-z0-9_-]{2,}(?:\.[a-z0-9_-]{2,})*)$/', $pattern, $m)) {
                return 'An extension pattern looks like *.bak or *.php.old, at least two characters per part';
            }
            $parts = explode('.', $m[1]);
            return in_array(end($parts), self::SITE_EXTENSIONS, true) ? 'This extension is one sites serve themselves' : null;
        }
        if (!preg_match('#^(/[^/\s?\#*]+)+\*?$#', $pattern)) {
            return 'A path pattern starts with / and is not / alone; a * may only end it';
        }
        // `/.env*`: whatever begins with the part before the *, whole segments or not
        $literal = rtrim($pattern, '*');
        $open = $literal !== $pattern;
        foreach ($ownPaths as $own) {
            $own = rtrim(self::lower(trim((string) (is_scalar($own) ? $own : ''))), '/');
            if ($own !== '' && ($literal === $own || str_starts_with($literal, $own . '/') || str_starts_with($own, $literal . ($open ? '' : '/')))) {
                return 'This pattern covers a path listed in ownPaths';
            }
        }
        return null;
    }

    /** Null when the entry is an IP, a CIDR range or an IPv4 mask with * for whole octets, else why not. */
    public static function allowEntryError(string $entry): ?string
    {
        $valid = str_contains($entry, '*') ? self::isMask($entry) : self::isIpOrRange($entry);
        return $valid ? null : 'Use an IP address, a CIDR range like 192.168.0.0/24, or a mask like 192.168.0.*';
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

    private static function isMask(string $entry): bool
    {
        $octets = explode('.', $entry);
        if (count($octets) !== 4) {
            return false;
        }
        foreach ($octets as $octet) {
            if ($octet !== '*' && !(ctype_digit($octet) && (int) $octet <= 255)) {
                return false;
            }
        }
        return true;
    }

    private static function isIpOrRange(string $entry): bool
    {
        $parts = explode('/', $entry, 2);
        $packed = filter_var($parts[0], FILTER_VALIDATE_IP) === false ? false : inet_pton($parts[0]);
        if ($packed === false) {
            return false;
        }
        return count($parts) === 1 || (preg_match('/^\d{1,3}$/', $parts[1]) === 1 && (int) $parts[1] <= strlen($packed) * 8);
    }

    private static function lower(string $value): string
    {
        return function_exists('mb_strtolower') ? mb_strtolower($value) : strtolower($value);
    }
}
