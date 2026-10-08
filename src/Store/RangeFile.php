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

    /**
     * Each range is one packed string (start, end, source index), so 200 000 networks stay far below the default
     * memory limit; the sources are consumed one at a time.
     *
     * @param iterable<string, iterable<string>> $sources source name => CIDRs
     */
    public static function build(iterable $sources): string
    {
        $names = [];
        $records = [4 => [], 6 => []];
        foreach ($sources as $name => $cidrs) {
            $index = count($names);
            $names[] = (string) $name;
            foreach ($cidrs as $cidr) {
                $network = Network::parse($cidr);
                if ($network !== null) {
                    [$start, $end] = $network->range();
                    $records[$network->family][] = $start . $end . pack('n', $index);
                }
            }
        }
        $counts = [];
        $body = '';
        foreach ([4, 6] as $family) {
            $width = $family === 4 ? 4 : 16;
            $list = $records[$family];
            unset($records[$family]);
            // The start comes first in a record: equal starts order by end, then by source index
            sort($list, SORT_STRING);
            $count = 0;
            $open = null;
            foreach ($list as $record) {
                $start = substr($record, 0, $width);
                $end = substr($record, $width, $width);
                if ($open !== null && strcmp($start, substr($open, $width, $width)) <= 0) {
                    if (strcmp($end, substr($open, $width, $width)) > 0) {
                        $open = substr($open, 0, $width) . $end . substr($open, 2 * $width);
                    }
                    continue;
                }
                if ($open !== null) {
                    $body .= $open;
                    $count++;
                }
                $open = $record;
            }
            if ($open !== null) {
                $body .= $open;
                $count++;
            }
            $counts[$family] = $count;
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
