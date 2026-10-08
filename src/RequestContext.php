<?php

declare(strict_types=1);

namespace ScannerTrap;

use Psr\Http\Message\ServerRequestInterface;

/** What the decision needs to know about one request, from $_SERVER, PSR-7 or a framework bridge. */
final class RequestContext
{
    public function __construct(
        public readonly ?string $ip,
        public readonly string $method,
        public readonly string $uri,
        public readonly string $userAgent = '',
        public readonly string $secFetchSite = '',
    ) {
    }

    /**
     * @param array<mixed> $server
     * @param list<string> $trustedProxies
     */
    public static function fromGlobals(array $server, array $trustedProxies = []): self
    {
        $get = static fn (string $name): string => is_string($server[$name] ?? null) ? $server[$name] : '';
        return new self(
            self::clientIp($get('REMOTE_ADDR'), $get('HTTP_X_FORWARDED_FOR'), $trustedProxies),
            $get('REQUEST_METHOD'),
            $get('REQUEST_URI'),
            $get('HTTP_USER_AGENT'),
            $get('HTTP_SEC_FETCH_SITE'),
        );
    }

    /** @param list<string> $trustedProxies */
    public static function fromPsr7(ServerRequestInterface $request, array $trustedProxies = []): self
    {
        $remote = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        $query = $request->getUri()->getQuery();
        return new self(
            self::clientIp(is_string($remote) ? $remote : '', $request->getHeaderLine('X-Forwarded-For'), $trustedProxies),
            $request->getMethod(),
            $request->getUri()->getPath() . ($query !== '' ? '?' . $query : ''),
            $request->getHeaderLine('User-Agent'),
            $request->getHeaderLine('Sec-Fetch-Site'),
        );
    }

    /**
     * REMOTE_ADDR, or behind a trusted proxy the rightmost X-Forwarded-For address that is not itself one. Null when
     * there is no usable address, including a proxy speaking for itself, which must never be blocked.
     *
     * @param list<string> $trustedProxies
     */
    public static function clientIp(string $remoteAddr, string $forwardedFor, array $trustedProxies): ?string
    {
        $remote = Rules::normalizeIp(trim($remoteAddr));
        if ($remote === null || $trustedProxies === [] || !Rules::isAllowed($remote, $trustedProxies)) {
            return $remote;
        }
        foreach (array_reverse(explode(',', $forwardedFor)) as $hop) {
            $hop = trim($hop);
            if ($hop === '') {
                continue;
            }
            $ip = Rules::normalizeIp($hop);
            if ($ip === null || !Rules::isAllowed($ip, $trustedProxies)) {
                return $ip;
            }
        }
        return null;
    }

    public function path(): string
    {
        $end = strpos($this->uri, '?');
        return $end === false ? $this->uri : substr($this->uri, 0, $end);
    }
}
