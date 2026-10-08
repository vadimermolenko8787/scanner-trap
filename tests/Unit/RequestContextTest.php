<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ScannerTrap\RequestContext;

final class RequestContextTest extends TestCase
{
    private const PROXIES = ['10.0.0.0/8', '2001:db8:ffff::/48'];

    /** @return array<string, array{string, string, list<string>, ?string}> */
    public static function clients(): array
    {
        return [
            'no proxies configured, header ignored' => ['203.0.113.7', '198.51.100.1', [], '203.0.113.7'],
            'untrusted remote, header ignored (spoofing)' => ['203.0.113.7', '198.51.100.1', self::PROXIES, '203.0.113.7'],
            'trusted remote, client from the header' => ['10.0.0.2', '198.51.100.1', self::PROXIES, '198.51.100.1'],
            'rightmost untrusted wins over a spoofed left part' => ['10.0.0.2', '1.1.1.1, 198.51.100.1, 10.0.0.3', self::PROXIES, '198.51.100.1'],
            'v6 client collapsed' => ['10.0.0.2', '2001:DB8:0:0::7', self::PROXIES, '2001:db8::7'],
            'v6 proxy' => ['2001:db8:ffff::1', '198.51.100.1', self::PROXIES, '198.51.100.1'],
            'empty elements skipped' => ['10.0.0.2', '198.51.100.1, , ', self::PROXIES, '198.51.100.1'],
            'garbage element is unusable' => ['10.0.0.2', 'unknown', self::PROXIES, null],
            'address with a port is unusable' => ['10.0.0.2', '198.51.100.1:5678', self::PROXIES, null],
            'only proxies in the header: the proxy itself, never blocked' => ['10.0.0.2', '10.0.0.3', self::PROXIES, null],
            'trusted remote without a header' => ['10.0.0.2', '', self::PROXIES, null],
            'garbage remote' => ['nonsense', '', [], null],
            'empty remote' => ['', '198.51.100.1', self::PROXIES, null],
        ];
    }

    /** @param list<string> $proxies */
    #[DataProvider('clients')]
    public function test_client_ip_honours_trusted_proxies_only(string $remote, string $forwarded, array $proxies, ?string $expected): void
    {
        $this->assertSame($expected, RequestContext::clientIp($remote, $forwarded, $proxies));
    }

    public function test_from_globals_reads_server_array(): void
    {
        $context = RequestContext::fromGlobals([
            'REMOTE_ADDR' => '10.0.0.2',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.1',
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/.env?x=1',
            'HTTP_USER_AGENT' => 'curl/8',
            'HTTP_SEC_FETCH_SITE' => 'cross-site',
        ], self::PROXIES);

        $this->assertSame('198.51.100.1', $context->ip);
        $this->assertSame('POST', $context->method);
        $this->assertSame('/.env?x=1', $context->uri);
        $this->assertSame('/.env', $context->path());
        $this->assertSame('curl/8', $context->userAgent);
        $this->assertSame('cross-site', $context->secFetchSite);
    }

    public function test_from_globals_tolerates_a_bare_server_array(): void
    {
        $context = RequestContext::fromGlobals([]);

        $this->assertNull($context->ip);
        $this->assertSame('', $context->uri);
        $this->assertSame('', $context->path());
    }

    public function test_from_psr7_reads_the_request(): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/%2Eenv?id=1%20union%20select', ['User-Agent' => 'scanner'], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withHeader('X-Forwarded-For', '198.51.100.1')
            ->withHeader('Sec-Fetch-Site', 'same-origin');

        $context = RequestContext::fromPsr7($request, self::PROXIES);

        $this->assertSame('198.51.100.1', $context->ip);
        $this->assertSame('GET', $context->method);
        $this->assertSame('/%2Eenv?id=1%20union%20select', $context->uri);
        $this->assertSame('scanner', $context->userAgent);
        $this->assertSame('same-origin', $context->secFetchSite);
    }
}
