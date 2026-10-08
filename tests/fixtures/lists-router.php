<?php

declare(strict_types=1);

// Router for ListImporterHttpTest: /bytes/N answers N bytes of list lines (?announce=1 sends a Content-Length),
// everything else is a file of tests/fixtures/lists.
if (preg_match('#^/bytes/(\d+)$#', (string) parse_url(is_string($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH), $match) === 1) {
    if (isset($_GET['announce'])) {
        header('Content-Length: ' . $match[1]);
    }
    echo str_pad('', (int) $match[1], "45.155.205.1\n");
    return true;
}
return false;
