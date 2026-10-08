<?php

declare(strict_types=1);

namespace ScannerTrap;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use ScannerTrap\Central\PdoCentralStore;
use ScannerTrap\Redis\PhpRedisConnection;
use ScannerTrap\Redis\PredisConnection;
use ScannerTrap\Redis\RedisConnection;
use ScannerTrap\Store\ApcuLocalStore;
use ScannerTrap\Store\FileLocalStore;
use ScannerTrap\Store\LocalStore;
use ScannerTrap\Store\RedisLocalStore;

/** The package's front door: one config array for index.php, the PSR-15 middleware and the CLI. */
final class ScannerTrap
{
    private const REQUEST_TIMEOUT = 0.5;
    // Deprecations never fail a request; an @-suppressed call leaves only these levels in error_reporting()
    private const FATAL_LEVELS = E_ERROR | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR | E_PARSE;

    private ?TrapManager $manager = null;

    /** @param array<mixed> $config */
    private function __construct(private readonly array $config, private readonly LocalStore $local)
    {
    }

    /**
     * Builds the stores without connecting to anything; a broken config is an \InvalidArgumentException.
     *
     * @param array<mixed> $config
     */
    public static function fromConfig(array $config, float $readTimeout = self::REQUEST_TIMEOUT): self
    {
        $local = $config['local'] ?? null;
        if (!is_array($local)) {
            throw new \InvalidArgumentException("The config needs 'local' => ['type' => 'redis' | 'file' | 'apcu', …]");
        }
        $central = $config['central'] ?? null;
        if ($central !== null && (!is_array($central) || !is_string($central['dsn'] ?? null))) {
            throw new \InvalidArgumentException("'central' is null or ['dsn' => …, 'user' => …, 'password' => …, 'tablePrefix' => …]");
        }
        $type = $local['type'] ?? null;
        if ($type === 'apcu' && $central !== null) {
            throw new \InvalidArgumentException('An APCu store keeps no events and cannot follow a central store; use redis or file');
        }
        $prefix = is_string($local['prefix'] ?? null) ? $local['prefix'] : 'scanner-trap:';
        $store = match ($type) {
            'redis' => new RedisLocalStore(self::redis($local, $readTimeout), $prefix),
            'file' => new FileLocalStore(is_string($local['dir'] ?? null) && $local['dir'] !== '' ? $local['dir'] : throw new \InvalidArgumentException("A file store needs 'dir'")),
            'apcu' => new ApcuLocalStore($prefix),
            default => throw new \InvalidArgumentException('Unknown local store type: use redis, file or apcu'),
        };
        return new self($config, $store);
    }

    /**
     * For the top of index.php: answers 403 and exits when the request is refused, otherwise returns. Any failure lets
     * the request through and goes to the configured logger.
     *
     * @param array<mixed>|string $config the array, or the path of a PHP file returning it
     */
    public static function guard(array|string $config): void
    {
        if (!self::check($config, $_SERVER)) {
            return;
        }
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
        }
        echo 'Forbidden';
        exit;
    }

    /**
     * True when the request described by $server must be refused. Never throws and never prints.
     *
     * @param array<mixed>|string $config
     * @param array<mixed> $server
     */
    public static function check(array|string $config, array $server): bool
    {
        $loaded = is_string($config) ? self::failSafe(static fn (): array => self::load($config), null, null) : $config;
        if (!is_array($loaded)) {
            return false;
        }
        $logger = ($loaded['logger'] ?? null) instanceof LoggerInterface ? $loaded['logger'] : null;
        return (bool) self::failSafe(static function () use ($loaded, $server): bool {
            $request = RequestContext::fromGlobals($server, self::stringList($loaded, 'trustedProxies', []));
            // Health checks, CLI runs and the server talking to itself must not pay for a store round trip
            if ($request->ip === null || Rules::isLoopback($request->ip)) {
                return false;
            }
            return self::fromConfig($loaded)->createGuard()->decide($request)->refuse;
        }, false, $logger);
    }

    /**
     * Runs $work with PHP warnings turned into exceptions; any Throwable is logged and gives $fallback.
     *
     * @internal
     * @param \Closure(): mixed $work
     */
    public static function failSafe(\Closure $work, mixed $fallback, ?LoggerInterface $logger): mixed
    {
        set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
            // Swallowed, so PHP's own handler cannot print them into the response
            if (($severity & (E_DEPRECATED | E_USER_DEPRECATED)) !== 0) {
                return true;
            }
            if ((error_reporting() & ~self::FATAL_LEVELS) === 0) {
                return false;
            }
            throw new \ErrorException($message, 0, $severity, $file, $line);
        });
        try {
            return $work();
        } catch (\Throwable $e) {
            try {
                $logger?->error('Scanner trap failed, the request was let through: {message}', ['message' => $e->getMessage(), 'exception' => $e]);
            } catch (\Throwable) {
                // A broken logger must not turn a fail-open into an error
            }
            return $fallback;
        } finally {
            restore_error_handler();
        }
    }

    public function createGuard(): Guard
    {
        $standalone = !is_array($this->config['central'] ?? null);
        $patterns = [];
        foreach (self::stringList($this->config, 'patterns', DefaultPatterns::LIST) as $pattern) {
            $pattern = Rules::normalizePattern($pattern);
            if (Rules::patternError($pattern) === null) {
                $patterns[] = $pattern;
            }
        }
        return new Guard(
            $this->local,
            (bool) ($this->config['blocking'] ?? false),
            max(0, is_int($this->config['blockTtl'] ?? null) ? $this->config['blockTtl'] : 604800),
            $this->serverName(),
            self::stringList($this->config, 'ownPaths', []),
            $standalone ? $patterns : null,
            $standalone ? self::stringList($this->config, 'allow', []) : null,
            $this->logger(),
        );
    }

    public function middleware(ResponseFactoryInterface $responses): ScannerTrapMiddleware
    {
        return new ScannerTrapMiddleware($this->createGuard(), $responses, $this->trustedProxies(), $this->logger());
    }

    public function manager(): TrapManager
    {
        if ($this->manager === null) {
            $central = $this->config['central'] ?? null;
            $this->manager = new TrapManager(
                $this->local,
                is_array($central) && is_string($central['dsn'] ?? null) ? PdoCentralStore::connect(
                    $central['dsn'],
                    is_string($central['user'] ?? null) ? $central['user'] : null,
                    is_string($central['password'] ?? null) ? $central['password'] : null,
                    is_string($central['tablePrefix'] ?? null) ? $central['tablePrefix'] : 'scanner_trap_',
                ) : null,
                self::stringList($this->config, 'patterns', DefaultPatterns::LIST),
                self::stringList($this->config, 'allow', []),
                self::stringList($this->config, 'ownPaths', []),
                $this->serverName(),
                max(0, is_int($this->config['blockTtl'] ?? null) ? $this->config['blockTtl'] : 604800),
                $this->logger(),
            );
        }
        return $this->manager;
    }

    /** @return list<string> */
    public function trustedProxies(): array
    {
        return self::stringList($this->config, 'trustedProxies', []);
    }

    public function logger(): ?LoggerInterface
    {
        $logger = $this->config['logger'] ?? null;
        return $logger instanceof LoggerInterface ? $logger : null;
    }

    /** @return array<mixed> */
    public static function load(string $path): array
    {
        if (!is_file($path)) {
            throw new \InvalidArgumentException("No scanner trap config at {$path}");
        }
        $config = require $path;
        if (!is_array($config)) {
            throw new \InvalidArgumentException("{$path} must return an array");
        }
        return $config;
    }

    private function serverName(): string
    {
        $name = $this->config['serverName'] ?? null;
        return is_string($name) ? $name : (string) gethostname();
    }

    /** @param array<mixed> $local */
    private static function redis(array $local, float $readTimeout): RedisConnection
    {
        $client = $local['client'] ?? null;
        if ($client instanceof RedisConnection) {
            return $client;
        }
        if ($client instanceof \Redis) {
            return PhpRedisConnection::wrap($client);
        }
        if ($client instanceof \Predis\Client) {
            return new PredisConnection($client);
        }
        if ($client !== null) {
            throw new \InvalidArgumentException("'client' must be a \\Redis, a \\Predis\\Client or a RedisConnection");
        }
        $host = is_string($local['host'] ?? null) ? $local['host'] : '127.0.0.1';
        $port = is_int($local['port'] ?? null) ? $local['port'] : 6379;
        $database = is_int($local['database'] ?? null) ? $local['database'] : 0;
        $password = is_string($local['password'] ?? null) ? $local['password'] : null;
        if (extension_loaded('redis')) {
            return PhpRedisConnection::connect($host, $port, $database, $password, self::REQUEST_TIMEOUT, $readTimeout);
        }
        if (class_exists(\Predis\Client::class)) {
            return PredisConnection::connect($host, $port, $database, $password, self::REQUEST_TIMEOUT, $readTimeout);
        }
        throw new \InvalidArgumentException('A Redis store needs ext-redis or predis/predis');
    }

    /**
     * @param array<mixed> $config
     * @param list<string> $default
     * @return list<string>
     */
    private static function stringList(array $config, string $key, array $default): array
    {
        $value = $config[$key] ?? $default;
        return is_array($value) ? array_values(array_filter($value, 'is_string')) : $default;
    }
}
