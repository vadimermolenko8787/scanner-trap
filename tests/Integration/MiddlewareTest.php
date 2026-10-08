<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Integration;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ScannerTrap\Guard;
use ScannerTrap\ScannerTrap;
use ScannerTrap\ScannerTrapMiddleware;
use ScannerTrap\Snapshot;
use ScannerTrap\Store\LocalStore;
use ScannerTrap\Tests\Support\MemoryLogger;

final class MiddlewareTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/scanner-trap-mw-' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    private function handler(): RequestHandlerInterface
    {
        return new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new Psr17Factory())->createResponse(200);
            }
        };
    }

    private function request(string $uri, string $ip = '203.0.113.7'): ServerRequest
    {
        return new ServerRequest('GET', $uri, [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }

    public function test_a_scanner_gets_403_and_others_reach_the_application(): void
    {
        $middleware = ScannerTrap::fromConfig(['local' => ['type' => 'file', 'dir' => $this->dir], 'blocking' => true])->middleware(new Psr17Factory());

        $refused = $middleware->process($this->request('https://example.com/.env'), $this->handler());
        $again = $middleware->process($this->request('https://example.com/'), $this->handler());
        $other = $middleware->process($this->request('https://example.com/', '203.0.113.8'), $this->handler());

        $this->assertSame(403, $refused->getStatusCode());
        $this->assertSame('Forbidden', (string) $refused->getBody());
        $this->assertSame(403, $again->getStatusCode());
        $this->assertSame(200, $other->getStatusCode());
    }

    public function test_a_failure_or_a_warning_inside_lets_the_request_through_and_is_logged(): void
    {
        $store = $this->createStub(LocalStore::class);
        $store->method('read')->willReturnCallback(static function (): Snapshot {
            trigger_error('simulated warning', E_USER_WARNING);
            return new Snapshot(true, [], []);
        });
        $logger = new MemoryLogger();
        $middleware = new ScannerTrapMiddleware(new Guard($store, true), new Psr17Factory(), [], $logger);

        $response = $middleware->process($this->request('https://example.com/'), $this->handler());

        $this->assertSame(200, $response->getStatusCode());
        $context = $logger->records[0][2];
        $this->assertSame('simulated warning', $context['message'] ?? null);
    }
}
