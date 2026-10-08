<?php

declare(strict_types=1);

namespace ScannerTrap;

/** What Guard reads in one round trip. A null list was never stored; a corrupt snapshot lets the request through. */
final class Snapshot
{
    /**
     * @param list<string>|null $patterns
     * @param list<AllowEntry>|null $allow
     */
    public function __construct(
        public readonly bool $blocked,
        public readonly ?array $patterns,
        public readonly ?array $allow,
        public readonly bool $corrupt = false,
    ) {
    }

    /** Decodes the two JSON lists as a store keeps them; null JSON = absent. */
    public static function decode(bool $blocked, ?string $patternsJson, ?string $allowJson): self
    {
        $patterns = self::decodeList($patternsJson);
        $allow = self::decodeList($allowJson);
        if ($patterns === false || $allow === false) {
            return new self($blocked, null, null, true);
        }
        if ($patterns !== null && array_filter($patterns, 'is_string') !== $patterns) {
            return new self($blocked, null, null, true);
        }
        $entries = null;
        if ($allow !== null) {
            $entries = [];
            foreach ($allow as $item) {
                $entry = is_array($item) ? AllowEntry::fromArray($item) : null;
                if ($entry === null) {
                    return new self($blocked, null, null, true);
                }
                $entries[] = $entry;
            }
        }
        /** @var list<string>|null $patterns */
        return new self($blocked, $patterns, $entries);
    }

    /** @return list<string> the whitelist entries still in force */
    public function allowedEntries(int $now): array
    {
        $entries = [];
        foreach ($this->allow ?? [] as $entry) {
            if ($entry->isActive($now)) {
                $entries[] = $entry->entry;
            }
        }
        return $entries;
    }

    /** @return list<mixed>|false|null  null = absent, false = not a JSON list */
    private static function decodeList(?string $json): array|false|null
    {
        if ($json === null) {
            return null;
        }
        $value = json_decode($json, true);
        return is_array($value) && array_is_list($value) ? $value : false;
    }
}
