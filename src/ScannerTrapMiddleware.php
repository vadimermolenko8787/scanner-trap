<?php

declare(strict_types=1);

namespace ScannerTrap;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/** PSR-15: 403 for a refused request, the application for everybody else, and for every failure inside. */
final class ScannerTrapMiddleware implements MiddlewareInterface
{
    /** @param list<string> $trustedProxies */
    public function __construct(
        private readonly Guard $guard,
        private readonly ResponseFactoryInterface $responses,
        private readonly array $trustedProxies = [],
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $refuse = ScannerTrap::failSafe(
            fn (): bool => $this->guard->decide(RequestContext::fromPsr7($request, $this->trustedProxies))->refuse,
            false,
            $this->logger,
        );
        if ($refuse !== true) {
            return $handler->handle($request);
        }
        $response = $this->responses->createResponse(403);
        $response->getBody()->write('Forbidden');
        return $response->withHeader('Content-Type', 'text/plain; charset=utf-8');
    }
}
