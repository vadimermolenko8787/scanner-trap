<?php

declare(strict_types=1);

namespace ScannerTrap;

/** Decoy patterns shipped with the package. */
final class DefaultPatterns
{
    /** Safe for any application: no real site serves these paths and no browser sends these User-Agents. */
    public const LIST = [
        '/.env*', '*.env', '/.git', '/.aws', '/.ssh', '/.ds_store', '/.htpasswd', '/.bashrc', '/phpmyadmin', '/pma',
        '/myadmin', '/phpinfo.php', '/vendor/phpunit', '/cgi-bin', '/server-status', '/actuator', '/boaform', '/hnap1',
        '/..', '*.sql', '*.bak', '*.php.bak', '*.php.old',
        '~union select', '~union all select', '~waitfor delay', '~@@version', '~extractvalue(',
        '~updatexml(', '~load_file(', '~into outfile', '~from information_schema',
        "~' or 1", "~' and 1", '~or 1=1', '~and 1=1', "~'1'='1",
        ...self::SCANNER_AGENTS,
    ];

    /** User-Agent fragments of scanning tools; no browser sends these. */
    public const SCANNER_AGENTS = [
        '@sqlmap', '@nikto', '@nuclei', '@zgrab', '@masscan', '@wpscan', '@gobuster', '@ffuf', '@feroxbuster',
        '@dirbuster', '@nmap scripting engine', '@acunetix', '@netsparker',
    ];

    /**
     * SQL fragments that ordinary text can contain, a GET search box or a comment preview ("rock" or "roll", php sleep(1)).
     * Add them only when no query string of the site carries free text.
     */
    public const LOOSE_FRAGMENTS = ["~' or '", "~' and '", '~" or "', '~" and "', '~sleep(', '~benchmark('];

    /** Only for sites that are not WordPress. */
    public const WORDPRESS_PROBES = [
        '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes', '/wp-json', '/xmlrpc.php', '/wordpress',
        '/wp-links-opml.php',
    ];
}
