<?php

declare(strict_types=1);

namespace ScannerTrap;

use ScannerTrap\Exception\RefusedException;
use ScannerTrap\Exception\StoreException;

/** Fetches a list source (ext-curl when loaded, else PHP streams) and keeps what is safe to refuse: valid, public, not absurdly wide networks. */
final class ListImporter
{
    public const MAX_ENTRIES = 200_000;
    private const USER_AGENT = 'scanner-trap (+https://github.com/vadimermolenko8787/scanner-trap)';

    public function __construct(private readonly float $timeout = 30.0, private readonly bool $useCurl = true)
    {
    }

    /** @return array{networks: list<string>, invalid: int, reserved: int, tooWide: int} */
    public function import(ListSource $source): array
    {
        $body = '';
        foreach ($source->locations as $location) {
            $body .= $this->fetch($location) . "\n";
        }
        $result = $this->parse($body, $source->format);
        if ($result['networks'] === []) {
            throw new StoreException("{$source->name} parsed to no networks; the previous entries stay");
        }
        if (count($result['networks']) > self::MAX_ENTRIES) {
            throw new RefusedException(sprintf('%s lists more than %d networks; nothing was imported', $source->name, self::MAX_ENTRIES));
        }
        return $result;
    }

    /** @return array{networks: list<string>, invalid: int, reserved: int, tooWide: int} */
    public function parse(string $body, string $format): array
    {
        $networks = [];
        $invalid = $reserved = $tooWide = 0;
        foreach (preg_split('/\r\n|\r|\n/', $body) ?: [] as $line) {
            $value = $format === ListSource::FORMAT_SPAMHAUS ? $this->spamhausValue($line) : $this->textValue($line);
            if ($value === null) {
                continue;
            }
            $network = Network::parse($value);
            if ($network === null) {
                $invalid++;
            } elseif ($network->prefix < ($network->family === 4 ? 8 : 16)) {
                $tooWide++;
            } elseif ($network->isReserved()) {
                $reserved++;
            } else {
                $networks[$network->cidr()] = true;
            }
        }
        $networks = array_keys($networks);
        sort($networks, SORT_STRING);
        return ['networks' => $networks, 'invalid' => $invalid, 'reserved' => $reserved, 'tooWide' => $tooWide];
    }

    /** The network on a text line, '' for garbage, null for a blank or comment line. */
    private function textValue(string $line): ?string
    {
        $line = trim((string) preg_replace('/[#;].*$/', '', $line));
        return $line === '' ? null : (string) strtok($line, " \t");
    }

    /** The cidr of a Spamhaus JSON line, '' for garbage, null for a blank or metadata line. */
    private function spamhausValue(string $line): ?string
    {
        if (trim($line) === '') {
            return null;
        }
        $data = json_decode($line, true);
        if (is_array($data) && ($data['type'] ?? null) === 'metadata') {
            return null;
        }
        return is_array($data) && is_string($data['cidr'] ?? null) ? $data['cidr'] : '';
    }

    private function fetch(string $location): string
    {
        if (preg_match('#^https?://#i', $location) === 1) {
            $body = $this->useCurl && extension_loaded('curl') ? $this->fetchWithCurl($location) : $this->fetchWithStreams($location);
        } else {
            $body = is_file($location) ? @file_get_contents($location) : false;
        }
        if ($body === false || trim($body) === '') {
            throw new StoreException("Cannot fetch {$location}, or it is empty; the previous entries stay");
        }
        return $body;
    }

    private function fetchWithCurl(string $url): string|false
    {
        $curl = curl_init($url);
        if ($curl === false) {
            return false;
        }
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_TIMEOUT_MS => (int) ($this->timeout * 1000),
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_FAILONERROR => true,
        ]);
        $body = curl_exec($curl);
        curl_close($curl);
        return is_string($body) ? $body : false;
    }

    /** Needs allow_url_fopen; a server without it and without ext-curl cannot fetch URLs (files still work). */
    private function fetchWithStreams(string $url): string|false
    {
        if (!filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
            throw new StoreException("Cannot fetch {$url}: neither ext-curl nor allow_url_fopen is available");
        }
        $context = stream_context_create(['http' => [
            'timeout' => $this->timeout,
            'user_agent' => self::USER_AGENT,
            'follow_location' => 1,
            'max_redirects' => 3,
        ]]);
        return @file_get_contents($url, false, $context);
    }
}
