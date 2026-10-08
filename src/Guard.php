<?php

declare(strict_types=1);

namespace ScannerTrap;

use Psr\Log\LoggerInterface;
use ScannerTrap\Store\LocalStore;

/** The decision for one request: one store read and, on a decoy, one atomic block write. Store failures propagate. */
final class Guard
{
    /**
     * @param list<string> $ownPaths
     * @param list<string>|null $fallbackPatterns used while the store has never stored patterns (no central store only)
     * @param list<string>|null $fallbackAllow used while the store has never stored a whitelist (no central store only)
     * @param bool $recordEvents false without a central store: nobody would ever drain the events
     */
    public function __construct(
        private readonly LocalStore $store,
        private readonly bool $blocking = false,
        private readonly int $blockTtl = 604800,
        private readonly string $serverName = '',
        private readonly array $ownPaths = [],
        private readonly ?array $fallbackPatterns = null,
        private readonly ?array $fallbackAllow = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly bool $recordEvents = true,
    ) {
    }

    public function decide(RequestContext $request): Decision
    {
        $ip = $request->ip;
        if ($ip === null || Rules::isLoopback($ip)) {
            return new Decision(false, Decision::NO_CLIENT);
        }
        $snapshot = $this->store->read($ip);
        if ($snapshot->corrupt) {
            $this->logger?->warning('Scanner trap: the local store holds lists that are not JSON lists; every request passes until they are rewritten');
            return new Decision(false, Decision::UNUSABLE);
        }
        $now = time();
        $allow = $snapshot->allow !== null ? $snapshot->allowedEntries($now) : ($this->fallbackAllow ?? []);
        if (Rules::isAllowed($ip, $allow)) {
            return new Decision(false, Decision::WHITELISTED);
        }
        if ($snapshot->blocked) {
            return new Decision($this->blocking, Decision::BLOCKED);
        }
        $patterns = $snapshot->patterns ?? $this->fallbackPatterns ?? [];
        $path = Rules::normalizePath($request->path());
        $pattern = Rules::underOwnPath($path, $this->ownPaths) ? null : Rules::matchedPattern($path, $patterns);
        $pattern ??= Rules::matchedFragment($request->uri, $patterns);
        if ($pattern === null) {
            return new Decision(false, Decision::NO_MATCH);
        }
        // A browser sent here by another site's <img> or link: blocking would let any page lock its visitors out
        if ($request->secFetchSite === 'cross-site') {
            return new Decision($this->blocking, Decision::CROSS_SITE, $pattern);
        }
        $recorded = $this->store->addBlock(new Block(
            $ip,
            $now,
            $this->blockTtl > 0 ? $now + $this->blockTtl : 0,
            $this->serverName,
            $request->method,
            // A fragment is mostly found in the query, which is the evidence then
            Rules::patternType($pattern) === Rules::TYPE_CONTAINS ? $request->uri : $request->path(),
            $pattern,
            $request->userAgent,
        ), $this->recordEvents);
        if ($recorded) {
            $this->logger?->info('Scanner trap: {ip} blacklisted for {pattern}', ['ip' => $ip, 'pattern' => $pattern, 'uri' => $request->uri]);
        }
        return new Decision($this->blocking, Decision::TRAPPED, $pattern, $recorded);
    }
}
