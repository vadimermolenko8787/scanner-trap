<?php

declare(strict_types=1);

namespace ScannerTrap\Store;

use ScannerTrap\Exception\StoreException;
use ScannerTrap\Network;

/**
 * Imported lists as a sorted file of merged address ranges, searched in place: a request reads about 18 records, so
 * memory and time stay flat however long the lists are, and opcache is not involved.
 * Layout: "STL1", uint32 IPv4 count, uint32 IPv6 count, uint32 JSON length (big-endian), the JSON list of source
 * names, then the IPv4 records (start 4, end 4, source index uint16) and the IPv6 records (16 + 16 + 2).
 */
final class RangeFile
{
    private const MAGIC = 'STL1';
    private const HEADER = 16;

    /** @param array<string, list<string>> $sources source name => CIDRs */
    public static function build(array $sources): string
    {
        $names = array_keys($sources);
        /** @var array<int, list<array{string, string, int}>> $ranges */
        $ranges = [4 => [], 6 => []];
        foreach ($names as $index => $name) {
            foreach ($sources[$name] as $cidr) {
                $network = Network::parse($cidr);
                if ($network !== null) {
                    [$start, $end] = $network->range();
                    $ranges[$network->family][] = [$start, $end, $index];
                }
            }
        }
        $counts = [];
        $body = '';
        foreach ([4, 6] as $family) {
            $list = $ranges[$family];
            // Stable since PHP 8.0: equal starts keep the order of the sources
            usort($list, static fn (array $a, array $b): int => strcmp($a[0], $b[0]));
            /** @var list<array{string, string, int}> $merged */
            $merged = [];
            foreach ($list as $range) {
                $last = count($merged) - 1;
                if ($last >= 0 && strcmp($range[0], $merged[$last][1]) <= 0) {
                    if (strcmp($range[1], $merged[$last][1]) > 0) {
                        $merged[$last] = [$merged[$last][0], $range[1], $merged[$last][2]];
                    }
                    continue;
                }
                $merged[] = $range;
            }
            $counts[$family] = count($merged);
            foreach ($merged as [$start, $end, $index]) {
                $body .= $start . $end . pack('n', $index);
            }
        }
        $json = (string) json_encode($names);
        return self::MAGIC . pack('NNN', $counts[4], $counts[6], strlen($json)) . $json . $body;
    }

    public static function lookup(string $path, string $ip): ?string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            throw new StoreException("Cannot open {$path}");
        }
        try {
            $header = (string) fread($handle, self::HEADER);
            if (strlen($header) !== self::HEADER || !str_starts_with($header, self::MAGIC)) {
                throw new StoreException("{$path} is not a lists file");
            }
            /** @var array{v4: int, v6: int, json: int} $sizes */
            $sizes = unpack('Nv4/Nv6/Njson', substr($header, 4));
            $stat = fstat($handle);
            if ($stat === false || $stat['size'] !== self::HEADER + $sizes['json'] + $sizes['v4'] * 10 + $sizes['v6'] * 34) {
                throw new StoreException("{$path} is truncated or corrupt");
            }
            $width = strlen($packed);
            $record = 2 * $width + 2;
            $offset = self::HEADER + $sizes['json'] + ($width === 16 ? $sizes['v4'] * 10 : 0);
            $count = $width === 4 ? $sizes['v4'] : $sizes['v6'];
            $found = null;
            for ($low = 0, $high = $count - 1; $low <= $high;) {
                $middle = intdiv($low + $high, 2);
                fseek($handle, $offset + $middle * $record);
                $data = (string) fread($handle, $record);
                if (strcmp(substr($data, 0, $width), $packed) <= 0) {
                    $found = $data;
                    $low = $middle + 1;
                } else {
                    $high = $middle - 1;
                }
            }
            if ($found === null || strcmp($packed, substr($found, $width, $width)) > 0) {
                return null;
            }
            /** @var array{1: int} $index */
            $index = unpack('n', substr($found, 2 * $width, 2));
            fseek($handle, self::HEADER);
            $names = json_decode((string) fread($handle, max(1, $sizes['json'])), true);
            $name = is_array($names) ? ($names[$index[1]] ?? null) : null;
            if (!is_string($name)) {
                throw new StoreException("{$path} names no source for a range");
            }
            return $name;
        } finally {
            fclose($handle);
        }
    }
}
