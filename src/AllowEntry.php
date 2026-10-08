<?php

declare(strict_types=1);

namespace ScannerTrap;

/** One whitelist entry: an IP, a CIDR range or an IPv4 octet mask. */
final class AllowEntry
{
    /** @param int $expiresAt unix time, 0 = forever */
    public function __construct(
        public readonly string $entry,
        public readonly string $comment = '',
        public readonly int $expiresAt = 0,
        public readonly string $createdBy = '',
    ) {
    }

    public function isActive(int $now): bool
    {
        return $this->expiresAt === 0 || $this->expiresAt > $now;
    }

    /** @return array{entry: string, comment: string, expires: int, createdBy: string} */
    public function toArray(): array
    {
        return ['entry' => $this->entry, 'comment' => $this->comment, 'expires' => $this->expiresAt, 'createdBy' => $this->createdBy];
    }

    /** @param array<mixed> $data  Null when the entry is not a valid whitelist entry. */
    public static function fromArray(array $data): ?self
    {
        $entry = is_string($data['entry'] ?? null) ? trim($data['entry']) : '';
        if (Rules::allowEntryError($entry) !== null) {
            return null;
        }
        return new self(
            $entry,
            is_string($data['comment'] ?? null) ? $data['comment'] : '',
            is_numeric($data['expires'] ?? null) ? (int) $data['expires'] : 0,
            is_string($data['createdBy'] ?? null) ? $data['createdBy'] : '',
        );
    }
}
