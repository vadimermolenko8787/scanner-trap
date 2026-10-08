<?php

declare(strict_types=1);

namespace ScannerTrap;

/** Decoy patterns shipped with the package. */
final class DefaultPatterns
{
    /** Safe for any application: no real site serves these. */
    public const LIST = [
        '/.env*', '*.env', '/.git', '/.aws', '/.ssh', '/.ds_store', '/.htpasswd', '/.bashrc', '/phpmyadmin', '/pma',
        '/myadmin', '/phpinfo.php', '/vendor/phpunit', '/cgi-bin', '/server-status', '/actuator', '/boaform', '/hnap1',
        '/..', '*.sql', '*.bak', '*.php.bak', '*.php.old',
        '~union select', '~union all select', '~sleep(', '~benchmark(', '~waitfor delay', '~@@version', '~extractvalue(',
        '~updatexml(', '~load_file(', '~into outfile', '~from information_schema', "~' or '", "~' and '", '~" or "',
        '~" and "', "~' or 1", "~' and 1", '~or 1=1', '~and 1=1', "~'1'='1",
    ];

    /** Only for sites that are not WordPress. */
    public const WORDPRESS_PROBES = [
        '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes', '/wp-json', '/xmlrpc.php', '/wordpress',
        '/wp-links-opml.php',
    ];
}
