<?php

declare(strict_types=1);

namespace ScannerTrap;

/** One configured blocklist: a preset name, or a name with one URL or file. */
final class ListSource
{
    public const FORMAT_TEXT = 'text';
    public const FORMAT_SPAMHAUS = 'spamhaus-json';
    private const PRESETS = [
        'spamhaus-drop' => [['https://www.spamhaus.org/drop/drop_v4.json', 'https://www.spamhaus.org/drop/drop_v6.json'], self::FORMAT_SPAMHAUS],
        'firehol-level1' => [['https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset'], self::FORMAT_TEXT],
    ];

    /** @param list<string> $locations */
    public function __construct(
        public readonly string $name,
        public readonly array $locations,
        public readonly string $format,
    ) {
    }

    /** @return list<self> the 'lists' config value; null = none */
    public static function fromConfig(mixed $value): array
    {
        if ($value === null) {
            return [];
        }
        if (!is_array($value) || !array_is_list($value)) {
            throw new \InvalidArgumentException("'lists' is a list of preset names or ['name' => …, 'url' or 'file' => …]");
        }
        $sources = [];
        foreach ($value as $item) {
            $source = is_string($item) ? self::preset($item) : self::custom($item);
            if (isset($sources[$source->name])) {
                throw new \InvalidArgumentException("The list source {$source->name} appears twice");
            }
            $sources[$source->name] = $source;
        }
        return array_values($sources);
    }

    private static function preset(string $name): self
    {
        [$locations, $format] = self::PRESETS[$name] ?? throw new \InvalidArgumentException("Unknown list preset {$name}: use " . implode(' or ', array_keys(self::PRESETS)));
        return new self($name, $locations, $format);
    }

    private static function custom(mixed $item): self
    {
        $name = is_array($item) && is_string($item['name'] ?? null) ? $item['name'] : '';
        if (preg_match('/^[a-z][a-z0-9-]{0,31}$/', $name) !== 1 || isset(self::PRESETS[$name])) {
            throw new \InvalidArgumentException("A list source name is a letter followed by up to 31 of a-z, 0-9 and -, and not a preset name: {$name}");
        }
        /** @var array<mixed> $item */
        $url = is_string($item['url'] ?? null) ? $item['url'] : null;
        $file = is_string($item['file'] ?? null) ? $item['file'] : null;
        if (($url === null) === ($file === null)) {
            throw new \InvalidArgumentException("The list source {$name} needs exactly one of 'url' and 'file'");
        }
        if ($url !== null && preg_match('#^https?://#i', $url) !== 1) {
            throw new \InvalidArgumentException("The list source {$name} needs an http or https URL");
        }
        $format = $item['format'] ?? self::FORMAT_TEXT;
        if ($format !== self::FORMAT_TEXT && $format !== self::FORMAT_SPAMHAUS) {
            throw new \InvalidArgumentException("The list source {$name} has format text or spamhaus-json");
        }
        return new self($name, [(string) ($url ?? $file)], $format);
    }
}
