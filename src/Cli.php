<?php

declare(strict_types=1);

namespace ScannerTrap;

use ScannerTrap\Exception\RefusedException;
use ScannerTrap\Exception\StoreException;

/** bin/scanner-trap: parses arguments, calls TrapManager, prints results. No console framework. */
final class Cli
{
    public const OK = 0;
    public const USAGE = 1;
    public const REFUSED = 2;
    public const UNREACHABLE = 3;

    private const COMMANDS = [
        'install' => [0, []],
        'sync' => [0, ['watch']],
        'list' => [0, ['active', 'ip']],
        'block' => [1, ['reason', 'ttl']],
        'unblock' => [1, []],
        'import' => [0, ['source']],
        'lists' => [0, []],
        'pattern:list' => [0, []],
        'pattern:add' => [1, []],
        'pattern:remove' => [1, []],
        'allow:list' => [0, []],
        'allow:add' => [1, ['comment', 'ttl']],
        'allow:remove' => [1, []],
    ];
    private const USAGE_TEXT = <<<'TXT'
        Usage: scanner-trap [--config=path] <command> [arguments]

          install                                   create tables or write the config's lists
          sync [--watch=N]                          push events, pull lists; keep pushing for N seconds
          list [--active] [--ip=IP]                 blocks with reason, server, expiry
          block <ip or cidr> [--reason=TEXT] [--ttl=SECONDS]   manual block (0 = forever)
          unblock <ip or cidr>
          import [--source=NAME]                    fetch the configured lists (all, or one)
          lists                                     list sources: entries, last import
          pattern:list | pattern:add <p> | pattern:remove <p>
          allow:list | allow:add <entry> [--comment=TEXT] [--ttl=SECONDS] | allow:remove <entry>

        The config defaults to ./scanner-trap.php. Exit codes: 0 ok, 1 usage, 2 refused, 3 store unreachable.

        TXT;

    /**
     * @param resource $out
     * @param resource $err
     */
    public function __construct(private $out, private $err, private readonly string $cwd)
    {
    }

    /** @param list<string> $argv */
    public static function main(array $argv): int
    {
        return (new self(STDOUT, STDERR, (string) getcwd()))->run(array_slice($argv, 1));
    }

    /** @param list<string> $args */
    public function run(array $args): int
    {
        try {
            [$command, $positional, $options] = $this->parse($args);
            if ($command === 'help') {
                fwrite($this->out, self::USAGE_TEXT);
                return self::OK;
            }
            $config = ScannerTrap::load(is_string($options['config'] ?? null) ? $options['config'] : $this->cwd . '/scanner-trap.php');
            $watch = $this->intOption($options, 'watch') ?? 0;
            $manager = ScannerTrap::fromConfig($config, max(2.0, $watch + 5.0))->manager();
            $this->execute($manager, $command, $positional, $options, $watch);
            return self::OK;
        } catch (\InvalidArgumentException $e) {
            fwrite($this->err, $e->getMessage() . "\n\n" . self::USAGE_TEXT);
            return self::USAGE;
        } catch (RefusedException $e) {
            fwrite($this->err, $e->getMessage() . "\n");
            return self::REFUSED;
        } catch (\Throwable $e) {
            fwrite($this->err, 'scanner-trap: ' . $e->getMessage() . "\n");
            return self::UNREACHABLE;
        }
    }

    /**
     * @param list<string> $positional
     * @param array<string, string|true> $options
     */
    private function execute(TrapManager $manager, string $command, array $positional, array $options, int $watch): void
    {
        $by = $this->operator() . '@' . (gethostname() ?: 'localhost');
        $text = static fn (string $name): string => is_string($options[$name] ?? null) ? $options[$name] : '';
        switch ($command) {
            case 'install':
                $manager->install($by);
                $this->say('Installed.');
                break;
            case 'sync':
                $this->say($manager->sync($watch) ? 'Synced.' : 'Another sync is running; nothing done.');
                break;
            case 'list':
                foreach ($manager->blocks(isset($options['active']), $text('ip') !== '' ? $text('ip') : null) as $block) {
                    $this->say(implode("\t", [
                        $block->ip,
                        $block->expiresAt === 0 ? 'forever' : date('Y-m-d H:i:s', $block->expiresAt),
                        $block->liftedAt !== null ? 'lifted by ' . ($block->liftedBy ?? '?') : $block->source,
                        $block->server,
                        $block->pattern,
                        $block->path,
                    ]));
                }
                break;
            case 'block':
                $block = $manager->block($positional[0], $text('reason'), $this->intOption($options, 'ttl'), $by);
                $this->say("Blocked {$block->ip}.");
                break;
            case 'unblock':
                $this->say($manager->unblock($positional[0], $by) > 0 ? 'Unblocked.' : 'That address was not blocked.');
                break;
            case 'import':
                if (isset($options['source']) && $text('source') === '') {
                    throw new \InvalidArgumentException('--source needs a list source name.');
                }
                $failed = 0;
                foreach ($manager->import($text('source') !== '' ? $text('source') : null) as $name => $result) {
                    if ($result['error'] !== null) {
                        $failed++;
                        $this->say("{$name}\tFAILED\t{$result['error']}");
                        continue;
                    }
                    $this->say(sprintf("%s\t%d networks (was %d)\tskipped %d invalid, %d reserved, %d too wide", $name, $result['networks'], $result['previous'], $result['invalid'], $result['reserved'], $result['tooWide']));
                }
                if ($failed > 0) {
                    throw new StoreException("{$failed} list source(s) failed; their previous entries stay");
                }
                break;
            case 'lists':
                foreach ($manager->lists() as $name => $list) {
                    $this->say(implode("\t", [$name, (string) $list['count'], $list['at'] > 0 ? date('Y-m-d H:i:s', $list['at']) : 'never', $list['configured'] ? 'configured' : 'not configured']));
                }
                break;
            case 'pattern:list':
                foreach ($manager->patterns() as $pattern) {
                    $this->say($pattern);
                }
                break;
            case 'pattern:add':
                $this->say('Added ' . $manager->addPattern($positional[0], $by) . '.');
                break;
            case 'pattern:remove':
                $manager->removePattern($positional[0]);
                $this->say('Removed.');
                break;
            case 'allow:list':
                foreach ($manager->allowEntries() as $entry) {
                    $this->say(implode("\t", [$entry->entry, $entry->expiresAt === 0 ? 'forever' : date('Y-m-d H:i:s', $entry->expiresAt), $entry->comment]));
                }
                break;
            case 'allow:add':
                $this->say('Allowed ' . $manager->addAllow($positional[0], $text('comment'), $this->intOption($options, 'ttl'), $by)->entry . '.');
                break;
            case 'allow:remove':
                $manager->removeAllow($positional[0]);
                $this->say('Removed.');
                break;
        }
    }

    /**
     * @param list<string> $args
     * @return array{string, list<string>, array<string, string|true>}
     */
    private function parse(array $args): array
    {
        $options = [];
        $positional = [];
        foreach ($args as $arg) {
            if (str_starts_with($arg, '--')) {
                $parts = explode('=', substr($arg, 2), 2);
                $options[$parts[0]] = $parts[1] ?? true;
            } else {
                $positional[] = $arg;
            }
        }
        $command = array_shift($positional);
        if ($command === null || ($command !== 'help' && !isset(self::COMMANDS[$command]))) {
            throw new \InvalidArgumentException($command === null ? 'No command given.' : "Unknown command {$command}.");
        }
        if ($command === 'help') {
            return [$command, [], $options];
        }
        [$arguments, $allowed] = self::COMMANDS[$command];
        if (count($positional) !== $arguments) {
            throw new \InvalidArgumentException("{$command} takes {$arguments} argument(s).");
        }
        foreach (array_keys($options) as $name) {
            if ($name !== 'config' && !in_array($name, $allowed, true)) {
                throw new \InvalidArgumentException("{$command} has no option --{$name}.");
            }
        }
        if (($options['config'] ?? '') === true) {
            throw new \InvalidArgumentException('--config needs a path.');
        }
        /** @var array<string, string|true> $options */
        return [$command, $positional, $options];
    }

    /** @param array<string, string|true> $options */
    private function intOption(array $options, string $name): ?int
    {
        if (!isset($options[$name])) {
            return null;
        }
        if (!is_string($options[$name]) || preg_match('/^\d+$/', $options[$name]) !== 1) {
            throw new \InvalidArgumentException("--{$name} takes a number of seconds.");
        }
        return (int) $options[$name];
    }

    /** The user running this process (get_current_user() would name the script's owner). */
    private function operator(): string
    {
        if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
            $entry = posix_getpwuid(posix_geteuid());
            if ($entry !== false && $entry['name'] !== '') {
                return $entry['name'];
            }
        }
        foreach (['USER', 'USERNAME'] as $variable) {
            $value = getenv($variable);
            if (is_string($value) && $value !== '') {
                return $value;
            }
        }
        return 'cli';
    }

    private function say(string $line): void
    {
        fwrite($this->out, $line . "\n");
    }
}
