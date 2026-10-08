<?php

declare(strict_types=1);

namespace ScannerTrap;

/** One block of one IP: the local record, the event pushed to the central store and a central row are this one shape. */
final class Block
{
    public const SOURCE_TRAP = 'trap';
    public const SOURCE_MANUAL = 'manual';
    private const LIMITS = ['server' => 255, 'method' => 16, 'path' => 1024, 'pattern' => 255, 'userAgent' => 512, 'source' => 16];

    public readonly string $ip;
    public readonly string $server;
    public readonly string $method;
    public readonly string $path;
    public readonly string $pattern;
    public readonly string $userAgent;
    public readonly string $source;

    /** @param int $expiresAt unix time, 0 = forever */
    public function __construct(
        string $ip,
        public readonly int $blockedAt,
        public readonly int $expiresAt,
        string $server = '',
        string $method = '',
        string $path = '',
        string $pattern = '',
        string $userAgent = '',
        string $source = self::SOURCE_TRAP,
        public readonly ?int $liftedAt = null,
        public readonly ?string $liftedBy = null,
    ) {
        $this->ip = Rules::normalizeIp($ip) ?? throw new \InvalidArgumentException("Not an IP address: {$ip}");
        $this->server = self::text($server, self::LIMITS['server']);
        $this->method = self::text($method, self::LIMITS['method']);
        $this->path = self::text($path, self::LIMITS['path']);
        $this->pattern = self::text($pattern, self::LIMITS['pattern']);
        $this->userAgent = self::text($userAgent, self::LIMITS['userAgent']);
        $this->source = self::text($source, self::LIMITS['source']);
    }

    public function isActive(int $now): bool
    {
        return $this->liftedAt === null && ($this->expiresAt === 0 || $this->expiresAt > $now);
    }

    /** Seconds left, 0 = forever. Only meaningful for an active block. */
    public function ttl(int $now): int
    {
        return $this->expiresAt === 0 ? 0 : max(1, $this->expiresAt - $now);
    }

    /** @return array{ip: string, blockedAt: int, expiresAt: int, server: string, method: string, path: string, pattern: string, userAgent: string, source: string, liftedAt: ?int, liftedBy: ?string} */
    public function toArray(): array
    {
        return [
            'ip' => $this->ip, 'blockedAt' => $this->blockedAt, 'expiresAt' => $this->expiresAt, 'server' => $this->server,
            'method' => $this->method, 'path' => $this->path, 'pattern' => $this->pattern, 'userAgent' => $this->userAgent,
            'source' => $this->source, 'liftedAt' => $this->liftedAt, 'liftedBy' => $this->liftedBy,
        ];
    }

    /** @param array<mixed> $data  Null when there is no valid IP: such a record cannot block anybody. */
    public static function fromArray(array $data): ?self
    {
        $ip = Rules::normalizeIp(is_string($data['ip'] ?? null) ? $data['ip'] : '');
        if ($ip === null) {
            return null;
        }
        $int = static fn (string $key): int => is_numeric($data[$key] ?? null) ? (int) $data[$key] : 0;
        $str = static fn (string $key): string => is_scalar($data[$key] ?? null) ? (string) $data[$key] : '';
        return new self(
            $ip,
            $int('blockedAt'),
            $int('expiresAt'),
            $str('server'),
            $str('method'),
            $str('path'),
            $str('pattern'),
            $str('userAgent'),
            $str('source') !== '' ? $str('source') : self::SOURCE_TRAP,
            is_numeric($data['liftedAt'] ?? null) ? (int) $data['liftedAt'] : null,
            is_string($data['liftedBy'] ?? null) ? $data['liftedBy'] : null,
        );
    }

    /** Cut to $max bytes and made valid UTF-8, so JSON and a utf8mb4 column both take it. */
    private static function text(string $value, int $max): string
    {
        $value = substr($value, 0, $max);
        if (preg_match('//u', $value) === 1) {
            return $value;
        }
        $decoded = json_decode((string) json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE));
        return substr(is_string($decoded) ? $decoded : '', 0, $max + 2);
    }
}
