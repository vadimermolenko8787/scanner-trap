<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration\Guard;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use ScannerTrap\AllowEntry;
use ScannerTrap\Block;
use ScannerTrap\Decision;
use ScannerTrap\Guard;
use ScannerTrap\RequestContext;
use ScannerTrap\Store\LocalStore;
use ScannerTrap\Tests\Support\MemoryLogger;

/** The spec's Guard scenarios; every local store runs them. createStore() returns a handle on an emptied backend. */
abstract class GuardScenarios extends TestCase
{
    protected const SCANNER = '203.0.113.7';
    protected const PATTERNS = ['/.env*', '/wp-admin', '*.sql', '~union select'];

    abstract protected function createStore(): LocalStore;

    /** Writes something into the stored patterns list that is not a JSON list of strings. */
    abstract protected function corruptLists(): void;

    protected function supportsEvents(): bool
    {
        return true;
    }

    /** @param array{blocking?: bool, blockTtl?: int, ownPaths?: list<string>, fallbackPatterns?: list<string>, logger?: LoggerInterface} $options */
    protected function guard(LocalStore $store, array $options = []): Guard
    {
        return new Guard(
            $store,
            $options['blocking'] ?? true,
            $options['blockTtl'] ?? 600,
            'web1',
            $options['ownPaths'] ?? [],
            $options['fallbackPatterns'] ?? null,
            null,
            $options['logger'] ?? null,
        );
    }

    protected function request(string $uri, string $ip = self::SCANNER, string $secFetchSite = ''): RequestContext
    {
        return RequestContext::fromGlobals(['REMOTE_ADDR' => $ip, 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $uri, 'HTTP_USER_AGENT' => 'zgrab', 'HTTP_SEC_FETCH_SITE' => $secFetchSite]);
    }

    protected function storeWithPatterns(): LocalStore
    {
        $store = $this->createStore();
        $store->replaceLists(self::PATTERNS, []);
        return $store;
    }

    public function test_a_decoy_blocks_the_ip_and_records_the_event(): void
    {
        $store = $this->storeWithPatterns();

        $decision = $this->guard($store)->decide($this->request('/.env.production'));

        $this->assertTrue($decision->refuse);
        $this->assertSame(Decision::TRAPPED, $decision->reason);
        $this->assertSame('/.env*', $decision->pattern);
        $this->assertTrue($decision->recorded);
        $this->assertTrue($store->read(self::SCANNER)->blocked);
        if ($this->supportsEvents()) {
            $events = array_values($store->events(10));
            $this->assertCount(1, $events);
            $this->assertSame(['203.0.113.7', 'web1', 'GET', '/.env.production', '/.env*', 'zgrab', Block::SOURCE_TRAP], [
                $events[0]->ip, $events[0]->server, $events[0]->method, $events[0]->path, $events[0]->pattern, $events[0]->userAgent, $events[0]->source,
            ]);
            $this->assertEqualsWithDelta(time() + 600, $events[0]->expiresAt, 2);
        }
    }

    public function test_a_fragment_records_the_whole_uri(): void
    {
        $store = $this->storeWithPatterns();

        $decision = $this->guard($store)->decide($this->request('/search?q=1%20UNION%20SELECT%202'));

        $this->assertSame('~union select', $decision->pattern);
        if ($this->supportsEvents()) {
            $this->assertSame('/search?q=1%20UNION%20SELECT%202', array_values($store->events(10))[0]->path);
        }
    }

    public function test_a_blocked_ip_is_refused_on_every_path_and_records_nothing_more(): void
    {
        $store = $this->storeWithPatterns();
        $guard = $this->guard($store);
        $guard->decide($this->request('/wp-admin'));

        $decision = $guard->decide($this->request('/'));
        $again = $guard->decide($this->request('/.env'));

        $this->assertTrue($decision->refuse);
        $this->assertSame(Decision::BLOCKED, $decision->reason);
        $this->assertFalse($again->recorded);
        if ($this->supportsEvents()) {
            $this->assertCount(1, $store->events(10));
        }
    }

    public function test_a_cross_site_decoy_is_refused_without_a_block(): void
    {
        $store = $this->storeWithPatterns();

        $decision = $this->guard($store)->decide($this->request('/.env', self::SCANNER, 'cross-site'));

        $this->assertTrue($decision->refuse);
        $this->assertSame(Decision::CROSS_SITE, $decision->reason);
        $this->assertFalse($store->read(self::SCANNER)->blocked);
    }

    public function test_watch_mode_blacklists_but_refuses_nobody(): void
    {
        $store = $this->storeWithPatterns();
        $guard = $this->guard($store, ['blocking' => false]);

        $first = $guard->decide($this->request('/.env'));
        $later = $guard->decide($this->request('/'));

        $this->assertFalse($first->refuse);
        $this->assertTrue($first->recorded);
        $this->assertTrue($store->read(self::SCANNER)->blocked);
        $this->assertFalse($later->refuse);
        $this->assertSame(Decision::BLOCKED, $later->reason);
    }

    public function test_the_whitelist_wins_over_a_block_and_over_a_decoy(): void
    {
        $store = $this->createStore();
        $store->addBlock(new Block(self::SCANNER, time(), 0), false);
        $store->replaceLists(self::PATTERNS, [new AllowEntry('203.0.113.0/24')]);
        $guard = $this->guard($store);

        $this->assertSame(Decision::WHITELISTED, $guard->decide($this->request('/'))->reason);
        $this->assertFalse($guard->decide($this->request('/.env'))->refuse);
        $this->assertFalse($guard->decide($this->request('/.env', '203.0.113.99'))->refuse);
        $this->assertFalse($store->read('203.0.113.99')->blocked);
    }

    public function test_an_expired_whitelist_entry_no_longer_protects(): void
    {
        $store = $this->createStore();
        $store->replaceLists(self::PATTERNS, [new AllowEntry(self::SCANNER, '', time() - 1)]);

        $this->assertTrue($this->guard($store)->decide($this->request('/.env'))->refuse);
    }

    public function test_loopback_and_unusable_addresses_never_touch_the_store(): void
    {
        $store = $this->storeWithPatterns();
        $guard = $this->guard($store);

        $this->assertSame(Decision::NO_CLIENT, $guard->decide($this->request('/.env', '127.0.0.1'))->reason);
        $this->assertSame(Decision::NO_CLIENT, $guard->decide($this->request('/.env', '::1'))->reason);
        $this->assertSame(Decision::NO_CLIENT, $guard->decide($this->request('/.env', 'garbage'))->reason);
        $this->assertSame([], $store->blocks());
    }

    public function test_ipv6_spellings_share_one_block(): void
    {
        $store = $this->storeWithPatterns();
        $guard = $this->guard($store);
        $guard->decide($this->request('/.env', '2001:DB8:0:0::7'));

        $this->assertTrue($guard->decide($this->request('/', '2001:db8::7'))->refuse);
        $this->assertSame('2001:db8::7', $store->blocks()[0]->ip);
    }

    public function test_an_empty_store_blocks_nobody_without_fallback_lists(): void
    {
        $store = $this->createStore();

        $decision = $this->guard($store)->decide($this->request('/.env'));

        $this->assertFalse($decision->refuse);
        $this->assertSame(Decision::NO_MATCH, $decision->reason);
    }

    public function test_an_empty_store_uses_the_fallback_lists_until_lists_are_stored(): void
    {
        $store = $this->createStore();
        $guard = $this->guard($store, ['fallbackPatterns' => ['/.git']]);

        $this->assertTrue($guard->decide($this->request('/.git/config'))->refuse);

        $store->replaceLists([], []);
        $this->assertFalse($guard->decide($this->request('/.git/config', '203.0.113.8'))->refuse);
    }

    public function test_own_paths_shield_path_patterns_but_not_fragments(): void
    {
        $store = $this->storeWithPatterns();
        $guard = $this->guard($store, ['ownPaths' => ['/wp-admin']]);

        $this->assertFalse($guard->decide($this->request('/wp-admin/install.php'))->refuse);
        $this->assertTrue($guard->decide($this->request('/wp-admin/x?q=union%20select'))->refuse);
    }

    public function test_an_expired_block_lets_the_ip_back_in(): void
    {
        $store = $this->storeWithPatterns();
        $guard = $this->guard($store, ['blockTtl' => 1]);
        $guard->decide($this->request('/.env'));
        sleep(2);

        $this->assertFalse($guard->decide($this->request('/'))->refuse);
    }

    public function test_a_forever_block_has_no_expiry(): void
    {
        $store = $this->storeWithPatterns();
        $this->guard($store, ['blockTtl' => 0])->decide($this->request('/.env'));

        $this->assertSame(0, $store->blocks()[0]->expiresAt);
    }

    public function test_corrupted_lists_let_the_request_through_and_are_logged(): void
    {
        $store = $this->createStore();
        $this->corruptLists();
        $logger = new MemoryLogger();

        $decision = $this->guard($store, ['logger' => $logger, 'fallbackPatterns' => ['/.env*']])->decide($this->request('/.env'));

        $this->assertFalse($decision->refuse);
        $this->assertSame(Decision::UNUSABLE, $decision->reason);
        $this->assertSame([], $store->blocks());
        $this->assertNotSame([], $logger->records);
    }

    public function test_a_long_path_with_broken_utf8_is_still_blocked_and_recorded(): void
    {
        $store = $this->storeWithPatterns();
        $uri = '/.env' . str_repeat('x', 3000) . "\xff\xfe";

        $this->assertTrue($this->guard($store)->decide($this->request($uri))->refuse);
        $this->assertTrue($store->read(self::SCANNER)->blocked);
        if ($this->supportsEvents()) {
            $path = array_values($store->events(10))[0]->path;
            $this->assertLessThanOrEqual(1024, mb_strlen($path));
            $this->assertTrue(mb_check_encoding($path, 'UTF-8'));
        }
    }

    public function test_an_ordinary_request_writes_nothing(): void
    {
        $store = $this->storeWithPatterns();

        $decision = $this->guard($store)->decide($this->request('/products?id=5'));

        $this->assertSame(Decision::NO_MATCH, $decision->reason);
        $this->assertSame([], $store->blocks());
    }
}
