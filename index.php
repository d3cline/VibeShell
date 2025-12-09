<?php
declare(strict_types=1);

ini_set('display_errors', '0');
error_reporting(0);

// Simple rate limiting: max requests per IP per minute
define('RATE_LIMIT_REQUESTS', 120);
define('RATE_LIMIT_WINDOW', 60);

/**
 * Simple file-based rate limiter.
 * Returns true if request is allowed, false if rate limited.
 */
function check_rate_limit(): bool
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $hash = md5($ip);
    $tmpDir = sys_get_temp_dir();
    $rateFile = $tmpDir . '/mcp_rate_' . $hash;
    
    $now = time();
    $requests = [];
    
    if (file_exists($rateFile)) {
        $data = @file_get_contents($rateFile);
        if ($data !== false) {
            $requests = @json_decode($data, true) ?: [];
        }
    }
    
    // Filter out old requests outside the window
    $requests = array_filter($requests, fn($t) => $t > ($now - RATE_LIMIT_WINDOW));
    
    if (count($requests) >= RATE_LIMIT_REQUESTS) {
        return false;
    }
    
    $requests[] = $now;
    @file_put_contents($rateFile, json_encode(array_values($requests)), LOCK_EX);
    
    return true;
}

/**
 * Set common security headers for all responses.
 */
function set_security_headers(): void
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Cache-Control: no-store, no-cache, must-revalidate, private');
    header('Pragma: no-cache');
}

/**
 * Send a JSON-RPC result response and exit.
 *
 * @param mixed $id
 * @param array $result
 * @return never
 */
function jsonrpc_response($id, array $result): void
{
    set_security_headers();
    header('Content-Type: application/json');
    http_response_code(200);

    echo json_encode(
        [
            'jsonrpc' => '2.0',
            'id'      => $id,
            'result'  => $result,
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

    exit;
}

/**
 * Send a JSON-RPC error response and exit.
 *
 * @param mixed       $id
 * @param int         $code
 * @param string      $message
 * @param array|null  $data
 * @return never
 */
function jsonrpc_error($id, int $code, string $message, ?array $data = null): void
{
    set_security_headers();
    header('Content-Type: application/json');
    http_response_code(200);

    $error = [
        'code'    => $code,
        'message' => $message,
    ];
    if ($data !== null) {
        $error['data'] = $data;
    }

    echo json_encode(
        [
            'jsonrpc' => '2.0',
            'id'      => $id,
            'error'   => $error,
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

    exit;
}

/**
 * Canonicalize a filesystem path (remove ".", "..", duplicate slashes).
 */
function canonicalize_path(string $path): string
{
    $path = str_replace('\\', '/', $path);
    $isAbsolute = strlen($path) > 0 && $path[0] === '/';
    $segments = preg_split('~/+~', $path);
    $parts = [];

    foreach ($segments as $seg) {
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($seg === '..') {
            if (!empty($parts)) {
                array_pop($parts);
            }
            continue;
        }
        $parts[] = $seg;
    }

    $normalized = ($isAbsolute ? '/' : '') . implode('/', $parts);

    if ($normalized === '') {
        return $isAbsolute ? '/' : '.';
    }

    return $normalized;
}

/**
 * Determine the current OS user's home directory.
 */
function determine_home_dir(): string
{
    $home = getenv('HOME');
    if (is_string($home) && $home !== '' && is_dir($home)) {
        return rtrim($home, '/');
    }

    $candidate = realpath(__DIR__ . '/..');
    if ($candidate === false) {
        $candidate = dirname(__DIR__);
    }

    return rtrim($candidate, '/');
}

/**
 * Resolve base_dir from config, ensuring it stays within home.
 */
function resolve_base_dir(string $baseSetting, string $homeDir): string
{
    $homeDir = rtrim($homeDir, '/');
    $baseSetting = trim($baseSetting);

    if ($baseSetting === '' || $baseSetting === '~') {
        return $homeDir;
    }

    if ($baseSetting[0] === '~') {
        $rest = ltrim(substr($baseSetting, 1), '/');
        $full = $homeDir . ($rest !== '' ? '/' . $rest : '');
    } elseif ($baseSetting[0] === '/') {
        $full = $baseSetting;
    } else {
        $full = $homeDir . '/' . $baseSetting;
    }

    $full = canonicalize_path($full);

    // Enforce that base_dir cannot escape the home directory.
    if (strpos($full, $homeDir . '/') !== 0 && $full !== $homeDir) {
        // Fail closed: snap back to home if misconfigured.
        return $homeDir;
    }

    return $full;
}

/**
 * Resolve a user-supplied path (may be relative, "~", or absolute) into an
 * absolute path within the user's home directory.
 *
 * Uses realpath() on existing paths to resolve symlinks and prevent symlink attacks.
 *
 * @throws RuntimeException if the resolved path escapes the home dir.
 */
function resolve_path(string $input, string $baseDir, string $homeDir): string
{
    $input = trim($input);
    $homeDir = rtrim($homeDir, '/');
    $baseDir = rtrim($baseDir, '/');

    if ($input === '' || $input === '.') {
        $full = $baseDir;
    } else {
        $first = $input[0];
        if ($first === '~') {
            $rest = ltrim(substr($input, 1), '/');
            $full = $homeDir . ($rest !== '' ? '/' . $rest : '');
        } elseif ($first === '/') {
            $full = $input;
        } else {
            $full = $baseDir . '/' . $input;
        }
    }

    $full = canonicalize_path($full);

    // For existing paths, use realpath() to resolve symlinks and verify true location
    if (file_exists($full) || is_link($full)) {
        $real = realpath($full);
        if ($real !== false) {
            $full = $real;
        } else {
            // If realpath fails on a symlink, it might be a broken symlink
            // or pointing outside accessible areas - reject it
            if (is_link($full)) {
                throw new RuntimeException('Cannot resolve symlink target');
            }
        }
    }

    if (strpos($full, $homeDir . '/') !== 0 && $full !== $homeDir) {
        throw new RuntimeException('Resolved path escapes home directory');
    }

    return $full;
}

/**
 * Load config from ~/.mcp_vibeshell.ini and return [homeDir, baseDir, token].
 *
 * The config file is stored in the user's home directory, outside the webroot,
 * following the standard Unix dotfile convention for security.
 *
 * @param mixed $id JSON-RPC id for error responses.
 * @return array{0:string,1:string,2:string}
 */
function load_config_or_fail($id): array
{
    $homeDir = determine_home_dir();
    $configFile = $homeDir . '/.mcp_vibeshell.ini';

    if (!is_readable($configFile)) {
        jsonrpc_error(
            $id,
            -32000,
            'CONFIG_MISSING: ~/.mcp_vibeshell.ini not found or not readable. ' .
            'Create it in your home directory with [vibeshell] section containing token and base_dir.'
        );
    }

    $config = @parse_ini_file($configFile, true, INI_SCANNER_TYPED);
    if ($config === false || !isset($config['vibeshell']) || !is_array($config['vibeshell'])) {
        jsonrpc_error(
            $id,
            -32001,
            'CONFIG_PARSE_ERROR: missing [vibeshell] section or invalid INI'
        );
    }

    $section = $config['vibeshell'];
    $token = isset($section['token']) ? trim((string)$section['token']) : '';
    $baseSetting = isset($section['base_dir']) ? trim((string)$section['base_dir']) : '~';

    $homeDir = determine_home_dir();
    $baseDir = resolve_base_dir($baseSetting, $homeDir);

    return [$homeDir, $baseDir, $token];
}

/**
 * Enforce Bearer token auth if token is configured.
 *
 * @param string $expectedToken
 * @param mixed  $id
 */
function enforce_auth_or_fail(string $expectedToken, $id): void
{
    $expectedToken = trim($expectedToken);
    if ($expectedToken === '') {
        // No token configured => auth disabled.
        return;
    }

    $authHeader = null;

    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $authHeader = trim((string)$_SERVER['HTTP_AUTHORIZATION']);
    } elseif (function_exists('getallheaders')) {
        $headers = getallheaders();
        foreach ($headers as $name => $value) {
            if (strcasecmp((string)$name, 'Authorization') === 0) {
                $authHeader = trim((string)$value);
                break;
            }
        }
    }

    if ($authHeader === null || $authHeader === '') {
        jsonrpc_error($id, -32001, 'Unauthorized: missing Authorization header');
    }

    if (!preg_match('/^Bearer\s+(.+)$/i', $authHeader, $m)) {
        jsonrpc_error($id, -32001, 'Unauthorized: expected Bearer token in Authorization header');
    }

    $token = trim($m[1]);

    if (!hash_equals($expectedToken, $token)) {
        jsonrpc_error($id, -32001, 'Unauthorized: invalid token');
    }
}

/**
 * Minimal SSE handler for GET requests.
 * We don't actually send JSON-RPC on this stream; it just satisfies MCP clients
 * that try to open an SSE connection to the MCP endpoint.
 */
function handle_sse_get(): void
{
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');

    // Harmless comment event.
    echo ": mcp vibeshell idle stream\n\n";
    @flush();
}

/**
 * Build initialize result payload.
 */
function handle_initialize($id, array $params): void
{
    $protocol = isset($params['protocolVersion']) && is_string($params['protocolVersion'])
        ? $params['protocolVersion']
        : '2024-11-05';

    $result = [
        'protocolVersion' => $protocol,
        'capabilities'    => [
            'tools' => [
                // We do not send tools/list_changed notifications.
                'listChanged' => false,
            ],
        ],
        'serverInfo'      => [
            'name'    => 'mcp-vibeshell',
            'version' => '0.1.0',
        ],
    ];

    jsonrpc_response($id, $result);
}

/**
 * Describe all tools exposed by this MCP server.
 */

function get_tools_definition(): array
{
    return [
        [
            'name'        => 'fs_info',
            'description' => 'Get information about the home, base, apps, and logs directories for this Opalstack user.',
            'inputSchema' => [
                'type'                 => 'object',
                // IMPORTANT: empty object, not empty array
                'properties'           => (object)[],
                'additionalProperties' => false,
            ],
        ],
        [
            'name'        => 'fs_list',
            'description' => 'List files and directories under a given path (relative to base_dir or home).',
            'inputSchema' => [
                'type'       => 'object',
                'properties' => [
                    'path'      => [
                        'type'        => 'string',
                        'description' => 'Path to list; relative like "apps" or absolute like "~/apps"; defaults to base_dir.',
                    ],
                    'recursive' => [
                        'type'        => 'boolean',
                        'description' => 'Whether to recurse into subdirectories.',
                    ],
                    'max_items' => [
                        'type'        => 'integer',
                        'description' => 'Maximum number of entries to return (default 200; max 5000).',
                        'minimum'     => 1,
                        'maximum'     => 5000,
                    ],
                ],
                'additionalProperties' => false,
            ],
        ],
        [
            'name'        => 'fs_read',
            'description' => 'Read a slice of a file.',
            'inputSchema' => [
                'type'       => 'object',
                'properties' => [
                    'path'      => [
                        'type'        => 'string',
                        'description' => 'File path to read; relative or absolute ("~/...").',
                    ],
                    'offset'    => [
                        'type'        => 'integer',
                        'description' => 'Byte offset to start reading from (default 0).',
                        'minimum'     => 0,
                    ],
                    'max_bytes' => [
                        'type'        => 'integer',
                        'description' => 'Maximum number of bytes to read (default 65536, max 1048576).',
                        'minimum'     => 1,
                        'maximum'     => 1048576,
                    ],
                ],
                'required'             => ['path'],
                'additionalProperties' => false,
            ],
        ],
        [
            'name'        => 'fs_write',
            'description' => 'Write text content to a file within the home directory.',
            'inputSchema' => [
                'type'       => 'object',
                'properties' => [
                    'path'   => [
                        'type'        => 'string',
                        'description' => 'Target file path; relative to base_dir or absolute within home (e.g. "apps/foo/config.php" or "~/notes.txt").',
                    ],
                    'content' => [
                        'type'        => 'string',
                        'description' => 'Text content to write.',
                    ],
                    'mode'    => [
                        'type'        => 'string',
                        'description' => 'One of "overwrite", "append", or "create".',
                        'enum'        => ['overwrite', 'append', 'create'],
                    ],
                    'mkdirs'  => [
                        'type'        => 'boolean',
                        'description' => 'If true, create parent directories as needed.',
                    ],
                ],
                'required'             => ['path', 'content'],
                'additionalProperties' => false,
            ],
        ],
        [
            'name'        => 'fs_tail',
            'description' => 'Tail the last N lines of a file (useful for logs).',
            'inputSchema' => [
                'type'       => 'object',
                'properties' => [
                    'path'  => [
                        'type'        => 'string',
                        'description' => 'File path to tail; usually something under "~/logs".',
                    ],
                    'lines' => [
                        'type'        => 'integer',
                        'description' => 'Number of lines from the end (default 200, max 2000).',
                        'minimum'     => 1,
                        'maximum'     => 2000,
                    ],
                ],
                'required'             => ['path'],
                'additionalProperties' => false,
            ],
        ],
        [
            'name'        => 'fs_search',
            'description' => 'Search for a text query within files under a given path (like a safe recursive grep).',
            'inputSchema' => [
                'type'       => 'object',
                'properties' => [
                    'path'       => [
                        'type'        => 'string',
                        'description' => 'Root path to search; defaults to base_dir.',
                    ],
                    'query'      => [
                        'type'        => 'string',
                        'description' => 'Text to search for (case-sensitive substring match).',
                    ],
                    'max_results' => [
                        'type'        => 'integer',
                        'description' => 'Maximum number of matches to return (default 50, max 500).',
                        'minimum'     => 1,
                        'maximum'     => 500,
                    ],
                    'extensions' => [
                        'type'        => 'array',
                        'description' => 'Optional list of file extensions (e.g. ["log","txt","php"]).',
                        'items'       => ['type' => 'string'],
                    ],
                ],
                'required'             => ['query'],
                'additionalProperties' => false,
            ],
        ],

        [
            'name'        => 'fs_move',
            'description' => 'Move or rename a file or directory within the user home (uses POSIX rename).',
            'inputSchema' => [
                'type'       => 'object',
                'properties' => [
                    'from' => [
                        'type'        => 'string',
                        'description' => 'Source path; relative to base_dir or absolute within home (e.g. "apps/foo" or "~/apps/foo").',
                    ],
                    'to'   => [
                        'type'        => 'string',
                        'description' => 'Destination path; relative to base_dir or absolute within home.',
                    ],
                    'overwrite' => [
                        'type'        => 'boolean',
                        'description' => 'If true, allow overwriting an existing file/dir at the destination.',
                    ],
                    'mkdirs' => [
                        'type'        => 'boolean',
                        'description' => 'If true, create parent directories for the destination as needed.',
                    ],
                ],
                'required'             => ['from', 'to'],
                'additionalProperties' => false,
            ],
        ],

	[
    'name'        => 'fs_delete',
    'description' => 'Delete a file, symlink, or directory within the user home (like rm). Optionally recursive for directories.',
    'inputSchema' => [
        'type'       => 'object',
        'properties' => [
            'path' => [
                'type'        => 'string',
                'description' => 'Target to delete; relative to base_dir or absolute within home (e.g. "apps/foo" or "~/logs/foo.log").',
            ],
            'recursive' => [
                'type'        => 'boolean',
                'description' => 'If true, recursively delete directories and contents (use with care).',
            ],
        ],
        'required'             => ['path'],
        'additionalProperties' => false,
    ],
],

    ];
}



/**
 * Wrap a successful tool payload into an MCP tools/call result.
 */
function tool_ok_result(array $payload): array
{
    return [
        'content' => [
            [
                'type' => 'text',
                'text' => json_encode(
                    $payload,
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                ),
            ],
        ],
        'isError' => false,
    ];
}

/**
 * Wrap a tool error into an MCP tools/call result.
 */
function tool_error_result(string $message, ?array $payload = null): array
{
    $body = ['error' => $message];
    if ($payload !== null) {
        $body['details'] = $payload;
    }

    return [
        'content' => [
            [
                'type' => 'text',
                'text' => json_encode(
                    $body,
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                ),
            ],
        ],
        'isError' => true,
    ];
}

/**
 * Implement fs_info tool.
 */
function fs_info_tool(string $homeDir, string $baseDir): array
{
    $homeDir = rtrim($homeDir, '/');
    $baseDir = rtrim($baseDir, '/');
    $appsDir = $homeDir . '/apps';
    $logsDir = $homeDir . '/logs';

    return [
        'home_dir' => $homeDir,
        'base_dir' => $baseDir,
        'apps_dir' => $appsDir,
        'logs_dir' => $logsDir,
        'notes'    => [
            '~/apps/ is where Opalstack app directories live for this OS user.',
            '~/logs/ is where Opalstack app logs live (e.g. logs/apps/<appname>/...).',
            'To create more apps, use the Opalstack control panel or its MCP/HTTP API endpoints.',
        ],
    ];
}

/**
 * Implement fs_list tool.
 */
function fs_list_tool(string $homeDir, string $baseDir, array $args): array
{
    $pathArg = isset($args['path']) && is_string($args['path']) ? $args['path'] : '.';
    $recursive = isset($args['recursive']) ? (bool)$args['recursive'] : false;

    $maxItems = isset($args['max_items']) ? (int)$args['max_items'] : 200;
    if ($maxItems <= 0) {
        $maxItems = 50;
    } elseif ($maxItems > 5000) {
        $maxItems = 5000;
    }

    try {
        $root = resolve_path($pathArg, $baseDir, $homeDir);
    } catch (RuntimeException $e) {
        return tool_error_result($e->getMessage(), ['path' => $pathArg]);
    }

    if (!is_dir($root)) {
        return tool_error_result('Not a directory', [
            'path'    => $pathArg,
            'resolved'=> $root,
        ]);
    }

    $items = [];
    $stack = [$root];
    $homeLen = strlen($homeDir);

    while (!empty($stack) && count($items) < $maxItems) {
        $dir = array_pop($stack);
        $dh = @opendir($dir);
        if ($dh === false) {
            continue;
        }

        while (($entry = readdir($dh)) !== false) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $fullEntry = $dir . '/' . $entry;
            $isDir = is_dir($fullEntry);
            $stat = @stat($fullEntry) ?: [];

            $rel = substr($fullEntry, $homeLen);
            if ($rel === false) {
                $rel = $fullEntry;
            }
            $rel = ltrim((string)$rel, '/');

            $items[] = [
                'name'          => $entry,
                'type'          => $isDir ? 'dir' : 'file',
                'relative_path' => $rel,
                'absolute_path' => $fullEntry,
                'size'          => $stat['size'] ?? null,
                'modified'      => isset($stat['mtime'])
                    ? date('c', (int)$stat['mtime'])
                    : null,
            ];

            if ($isDir && $recursive && count($items) < $maxItems) {
                $stack[] = $fullEntry;
            }

            if (count($items) >= $maxItems) {
                break;
            }
        }

        closedir($dh);
    }

    return [
        'root'         => $pathArg,
        'resolved_root'=> $root,
        'recursive'    => $recursive,
        'max_items'    => $maxItems,
        'count'        => count($items),
        'items'        => $items,
    ];
}

/**
 * Implement fs_read tool.
 */
function fs_read_tool(string $homeDir, string $baseDir, array $args): array
{
    $pathArg = isset($args['path']) && is_string($args['path']) ? $args['path'] : '';
    if ($pathArg === '') {
        return tool_error_result('path is required', []);
    }

    $offset = isset($args['offset']) ? (int)$args['offset'] : 0;
    if ($offset < 0) {
        $offset = 0;
    }

    $maxBytes = isset($args['max_bytes']) ? (int)$args['max_bytes'] : 65536;
    if ($maxBytes <= 0) {
        $maxBytes = 65536;
    } elseif ($maxBytes > 1048576) { // 1 MB cap
        $maxBytes = 1048576;
    }

    try {
        $full = resolve_path($pathArg, $baseDir, $homeDir);
    } catch (RuntimeException $e) {
        return tool_error_result($e->getMessage(), ['path' => $pathArg]);
    }

    if (!is_file($full)) {
        return tool_error_result('Not a file or not found', [
            'path'    => $pathArg,
            'resolved'=> $full,
        ]);
    }

    if (!is_readable($full)) {
        return tool_error_result('File not readable', [
            'path'    => $pathArg,
            'resolved'=> $full,
        ]);
    }

    $content = @file_get_contents($full, false, null, $offset, $maxBytes);
    if ($content === false) {
        return tool_error_result('Failed to read file', [
            'path'    => $pathArg,
            'resolved'=> $full,
        ]);
    }

    // Check for binary content (contains null bytes)
    $isBinary = strpos($content, "\0") !== false;

    return [
        'path'          => $pathArg,
        'resolved_path' => $full,
        'offset'        => $offset,
        'max_bytes'     => $maxBytes,
        'bytes'         => strlen($content),
        'is_binary'     => $isBinary,
        'content'       => $isBinary ? '[Binary file - content omitted]' : $content,
    ];
}

/**
 * Check if a path is a protected/sensitive file that shouldn't be modified.
 */
function is_protected_path(string $path, string $homeDir): bool
{
    $homeDir = rtrim($homeDir, '/');
    $protected = [
        $homeDir . '/.mcp_vibeshell.ini',
        $homeDir . '/.bashrc',
        $homeDir . '/.bash_profile',
        $homeDir . '/.profile',
        $homeDir . '/.ssh',
        $homeDir . '/.gnupg',
    ];
    
    foreach ($protected as $p) {
        if ($path === $p || strpos($path, $p . '/') === 0) {
            return true;
        }
    }
    
    return false;
}

/**
 * Implement fs_write tool.
 */
function fs_write_tool(string $homeDir, string $baseDir, array $args): array
{
    $pathArg = isset($args['path']) && is_string($args['path']) ? $args['path'] : '';
    if ($pathArg === '') {
        return tool_error_result('path is required for write', []);
    }

    $content = isset($args['content']) && is_string($args['content']) ? $args['content'] : '';
    $mode = isset($args['mode']) && is_string($args['mode']) ? strtolower($args['mode']) : 'overwrite';
    if (!in_array($mode, ['overwrite', 'append', 'create'], true)) {
        $mode = 'overwrite';
    }
    $mkdirs = isset($args['mkdirs']) ? (bool)$args['mkdirs'] : false;

    try {
        $full = resolve_path($pathArg, $baseDir, $homeDir);
    } catch (RuntimeException $e) {
        return tool_error_result($e->getMessage(), ['path' => $pathArg]);
    }

    // Protect sensitive files
    if (is_protected_path($full, $homeDir)) {
        return tool_error_result('Cannot modify protected file', [
            'path' => $pathArg,
        ]);
    }

    $dir = dirname($full);
    if (!is_dir($dir)) {
        if ($mkdirs) {
            if (!@mkdir($dir, 0770, true) && !is_dir($dir)) {
                return tool_error_result('Failed to create parent directory', ['dir' => $dir]);
            }
        } else {
            return tool_error_result('Parent directory does not exist', ['dir' => $dir]);
        }
    }

    $flags = LOCK_EX;
    if ($mode === 'append') {
        $flags |= FILE_APPEND;
    } elseif ($mode === 'create') {
        if (file_exists($full)) {
            return tool_error_result('File already exists and mode=create', [
                'path'    => $pathArg,
                'resolved'=> $full,
            ]);
        }
    }

    $bytes = @file_put_contents($full, $content, $flags);
    if ($bytes === false) {
        return tool_error_result('Failed to write file', [
            'path'    => $pathArg,
            'resolved'=> $full,
        ]);
    }

    return [
        'path'          => $pathArg,
        'resolved_path' => $full,
        'bytes_written' => $bytes,
        'mode'          => $mode,
    ];
}



function fs_move_tool(string $homeDir, string $baseDir, array $args): array
{
    $fromArg = isset($args['from']) && is_string($args['from']) ? $args['from'] : '';
    $toArg   = isset($args['to'])   && is_string($args['to'])   ? $args['to']   : '';

    if ($fromArg === '' || $toArg === '') {
        return tool_error_result('from and to are required', [
            'from' => $fromArg,
            'to'   => $toArg,
        ]);
    }

    $overwrite = isset($args['overwrite']) ? (bool)$args['overwrite'] : false;
    $mkdirs    = isset($args['mkdirs'])    ? (bool)$args['mkdirs']    : false;

    try {
        $src = resolve_path($fromArg, $baseDir, $homeDir);
        $dst = resolve_path($toArg,   $baseDir, $homeDir);
    } catch (RuntimeException $e) {
        return tool_error_result($e->getMessage(), [
            'from' => $fromArg,
            'to'   => $toArg,
        ]);
    }

    // Protect sensitive files from being moved or overwritten
    if (is_protected_path($src, $homeDir) || is_protected_path($dst, $homeDir)) {
        return tool_error_result('Cannot move to/from protected path', [
            'from' => $fromArg,
            'to'   => $toArg,
        ]);
    }

    if (!file_exists($src)) {
        return tool_error_result('Source does not exist', [
            'from'          => $fromArg,
            'resolved_from' => $src,
        ]);
    }

    if (file_exists($dst) && !$overwrite) {
        return tool_error_result('Destination exists and overwrite=false', [
            'to'           => $toArg,
            'resolved_to'  => $dst,
        ]);
    }

    $dstDir = dirname($dst);
    if (!is_dir($dstDir)) {
        if ($mkdirs) {
            if (!@mkdir($dstDir, 0770, true) && !is_dir($dstDir)) {
                return tool_error_result('Failed to create destination parent directory', [
                    'parent' => $dstDir,
                ]);
            }
        } else {
            return tool_error_result('Destination parent directory does not exist', [
                'parent' => $dstDir,
            ]);
        }
    }

    if (!@rename($src, $dst)) {
        return tool_error_result('Failed to move/rename (rename() returned false)', [
            'from'          => $fromArg,
            'to'            => $toArg,
            'resolved_from' => $src,
            'resolved_to'   => $dst,
        ]);
    }

    return [
        'from'          => $fromArg,
        'to'            => $toArg,
        'resolved_from' => $src,
        'resolved_to'   => $dst,
        'overwrite'     => $overwrite,
        'mkdirs'        => $mkdirs,
        'moved'         => true,
    ];
}




/**
 * Recursively delete a path (dir tree or single file/symlink).
 * Assumes the path is already validated to be inside home.
 */
function delete_path_recursive(string $path): bool
{
    // If it's a symlink or regular file, just unlink.
    if (is_link($path) || is_file($path)) {
        return @unlink($path);
    }

    if (!is_dir($path)) {
        // Nothing to do / unknown type.
        return @unlink($path);
    }

    $items = @scandir($path);
    if ($items === false) {
        return false;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $child = $path . '/' . $item;

        if (!delete_path_recursive($child)) {
            return false;
        }
    }

    return @rmdir($path);
}

/**
 * Implement fs_delete tool.
 */
function fs_delete_tool(string $homeDir, string $baseDir, array $args): array
{
    $pathArg = isset($args['path']) && is_string($args['path']) ? $args['path'] : '';
    if ($pathArg === '') {
        return tool_error_result('path is required', []);
    }

    $recursive = isset($args['recursive']) ? (bool)$args['recursive'] : false;

    try {
        $full = resolve_path($pathArg, $baseDir, $homeDir);
    } catch (RuntimeException $e) {
        return tool_error_result($e->getMessage(), ['path' => $pathArg]);
    }

    // Protect sensitive files from deletion
    if (is_protected_path($full, $homeDir)) {
        return tool_error_result('Cannot delete protected path', [
            'path' => $pathArg,
        ]);
    }

    // If it doesn't exist at all.
    if (!file_exists($full) && !is_link($full)) {
        return tool_error_result('Path does not exist', [
            'path'          => $pathArg,
            'resolved_path' => $full,
        ]);
    }

    $isDir  = is_dir($full);
    $isFile = is_file($full) || is_link($full);

    if ($isDir && !$recursive) {
        // Only allow empty dir when recursive=false.
        $items = @scandir($full);
        if ($items === false) {
            return tool_error_result('Failed to read directory', [
                'path'          => $pathArg,
                'resolved_path' => $full,
            ]);
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            return tool_error_result(
                'Directory is not empty (set recursive=true to delete contents)',
                [
                    'path'          => $pathArg,
                    'resolved_path' => $full,
                ]
            );
        }

        if (!@rmdir($full)) {
            return tool_error_result('Failed to remove directory', [
                'path'          => $pathArg,
                'resolved_path' => $full,
            ]);
        }

        return [
            'path'          => $pathArg,
            'resolved_path' => $full,
            'type'          => 'dir',
            'recursive'     => false,
            'deleted'       => true,
        ];
    }

    // File/symlink or recursive directory delete.
    if ($recursive) {
        $ok = delete_path_recursive($full);
    } else {
        $ok = @unlink($full);
    }

    if (!$ok) {
        return tool_error_result('Failed to delete path', [
            'path'          => $pathArg,
            'resolved_path' => $full,
            'recursive'     => $recursive,
        ]);
    }

    return [
        'path'          => $pathArg,
        'resolved_path' => $full,
        'type'          => $isDir ? 'dir' : 'file',
        'recursive'     => $recursive,
        'deleted'       => true,
    ];
}



/**
 * Tail the last N lines of a file (simple implementation).
 */
function tail_file_last_lines(string $file, int $lines): string
{
    $lines = max(1, $lines);
    $buffer = 4096;

    $fh = @fopen($file, 'rb');
    if ($fh === false) {
        return '';
    }

    fseek($fh, 0, SEEK_END);
    $pos = ftell($fh);
    $chunk = '';
    $lineCount = 0;

    while ($pos > 0 && $lineCount <= $lines) {
        $readSize = ($pos >= $buffer) ? $buffer : $pos;
        $pos -= $readSize;
        fseek($fh, $pos);
        $data = fread($fh, $readSize);
        if ($data === false) {
            break;
        }
        $chunk = $data . $chunk;
        $lineCount = substr_count($chunk, "\n");
    }

    fclose($fh);

    $allLines = explode("\n", $chunk);
    $lastLines = array_slice($allLines, -$lines);

    return implode("\n", $lastLines);
}

/**
 * Implement fs_tail tool.
 */
function fs_tail_tool(string $homeDir, string $baseDir, array $args): array
{
    $pathArg = isset($args['path']) && is_string($args['path']) ? $args['path'] : '';
    if ($pathArg === '') {
        return tool_error_result('path is required', []);
    }

    $lines = isset($args['lines']) ? (int)$args['lines'] : 200;
    if ($lines <= 0) {
        $lines = 200;
    } elseif ($lines > 2000) {
        $lines = 2000;
    }

    try {
        $full = resolve_path($pathArg, $baseDir, $homeDir);
    } catch (RuntimeException $e) {
        return tool_error_result($e->getMessage(), ['path' => $pathArg]);
    }

    if (!is_file($full)) {
        return tool_error_result('Not a file or not found', [
            'path'    => $pathArg,
            'resolved'=> $full,
        ]);
    }

    if (!is_readable($full)) {
        return tool_error_result('File not readable', [
            'path'    => $pathArg,
            'resolved'=> $full,
        ]);
    }

    $content = tail_file_last_lines($full, $lines);

    return [
        'path'          => $pathArg,
        'resolved_path' => $full,
        'lines'         => $lines,
        'content'       => $content,
    ];
}

/**
 * Helper: search for query in a single file, appending to $matches.
 *
 * @param array<int,array<string,mixed>> $matches
 */
function search_in_file(string $file, string $query, int $maxResults, array &$matches, string $homeDir): void
{
    $fh = @fopen($file, 'rb');
    if ($fh === false) {
        return;
    }

    $lineNo = 0;
    $homeLen = strlen($homeDir);
    $rel = substr($file, $homeLen);
    if ($rel === false) {
        $rel = $file;
    }
    $rel = ltrim((string)$rel, '/');

    while (!feof($fh) && count($matches) < $maxResults) {
        $line = fgets($fh);
        if ($line === false) {
            break;
        }
        $lineNo++;
        if (strpos($line, $query) !== false) {
            $matches[] = [
                'path'    => $rel,
                'line'    => $lineNo,
                'snippet' => trim($line),
            ];
        }
    }

    fclose($fh);
}

/**
 * Implement fs_search tool.
 */
function fs_search_tool(string $homeDir, string $baseDir, array $args): array
{
    $query = isset($args['query']) && is_string($args['query']) ? $args['query'] : '';
    if ($query === '') {
        return tool_error_result('query is required', []);
    }

    $pathArg = isset($args['path']) && is_string($args['path']) ? $args['path'] : '.';

    $maxResults = isset($args['max_results']) ? (int)$args['max_results'] : 50;
    if ($maxResults <= 0) {
        $maxResults = 10;
    } elseif ($maxResults > 500) {
        $maxResults = 500;
    }

    $extensions = [];
    if (isset($args['extensions']) && is_array($args['extensions'])) {
        foreach ($args['extensions'] as $ext) {
            if (is_string($ext) && $ext !== '') {
                $extensions[] = ltrim(strtolower($ext), '.');
            }
        }
    }

    try {
        $root = resolve_path($pathArg, $baseDir, $homeDir);
    } catch (RuntimeException $e) {
        return tool_error_result($e->getMessage(), ['path' => $pathArg]);
    }

    $matches = [];

    if (is_dir($root)) {
        $stack = [$root];

        while (!empty($stack) && count($matches) < $maxResults) {
            $dir = array_pop($stack);
            $dh = @opendir($dir);
            if ($dh === false) {
                continue;
            }

            while (($entry = readdir($dh)) !== false && count($matches) < $maxResults) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                $fullEntry = $dir . '/' . $entry;
                if (is_dir($fullEntry)) {
                    $stack[] = $fullEntry;
                    continue;
                }

                if (!empty($extensions)) {
                    $ext = strtolower((string)pathinfo($fullEntry, PATHINFO_EXTENSION));
                    if ($ext === '' || !in_array($ext, $extensions, true)) {
                        continue;
                    }
                }

                search_in_file($fullEntry, $query, $maxResults, $matches, $homeDir);
            }

            closedir($dh);
        }
    } elseif (is_file($root)) {
        search_in_file($root, $query, $maxResults, $matches, $homeDir);
    } else {
        return tool_error_result('Path not found', [
            'path'    => $pathArg,
            'resolved'=> $root,
        ]);
    }

    return [
        'path'         => $pathArg,
        'resolved_root'=> $root,
        'query'        => $query,
        'max_results'  => $maxResults,
        'count'        => count($matches),
        'matches'      => $matches,
    ];
}

/**
 * Handle a JSON-RPC MCP request (single object, not batch).
 */
function handle_mcp_jsonrpc(array $rpc): void
{
    $hasId = array_key_exists('id', $rpc);
    $id = $hasId ? $rpc['id'] : null;

    if (!isset($rpc['jsonrpc']) || $rpc['jsonrpc'] !== '2.0') {
        jsonrpc_error($id, -32600, 'Invalid Request: jsonrpc must be "2.0"');
    }

    if (!isset($rpc['method']) || !is_string($rpc['method'])) {
        jsonrpc_error($id, -32600, 'Invalid Request: method must be a string');
    }

    $method = $rpc['method'];
    $params = isset($rpc['params']) && is_array($rpc['params']) ? $rpc['params'] : [];

    // Notifications (no id): we just accept and return HTTP 202 with no body.
    if (!$hasId) {
        // We specifically support notifications/initialized but ignore others.
        // Per spec, this is enough to let clients proceed. :contentReference[oaicite:1]{index=1}
        http_response_code(202);
        header('Content-Length: 0');
        return;
    }

    // For all requests with an id, we enforce config + auth (including initialize).
    [$homeDir, $baseDir, $token] = load_config_or_fail($id);
    enforce_auth_or_fail($token, $id);

    switch ($method) {
        case 'initialize':
            handle_initialize($id, $params);
            return;

        case 'ping':
            jsonrpc_response($id, [
                'pong' => true,
                'time' => gmdate('c'),
            ]);
            return;

        case 'tools/list':
            $tools = get_tools_definition();
            jsonrpc_response($id, ['tools' => $tools]);
            return;

        case 'tools/call':
            if (!isset($params['name']) || !is_string($params['name'])) {
                jsonrpc_error($id, -32602, 'tools/call: name must be a string');
            }
            $toolName = $params['name'];
            $args = isset($params['arguments']) && is_array($params['arguments'])
                ? $params['arguments']
                : [];

            $resultPayload = null;

            switch ($toolName) {
                case 'fs_info':
                    $resultPayload = tool_ok_result(
                        fs_info_tool($homeDir, $baseDir)
                    );
                    break;

                case 'fs_list':
                    $resultPayload = tool_ok_result(
                        fs_list_tool($homeDir, $baseDir, $args)
                    );
                    break;

                case 'fs_read':
                    $resultPayload = tool_ok_result(
                        fs_read_tool($homeDir, $baseDir, $args)
                    );
                    break;

                case 'fs_write':
                    $resultPayload = tool_ok_result(
                        fs_write_tool($homeDir, $baseDir, $args)
                    );
                    break;

                case 'fs_tail':
                    $resultPayload = tool_ok_result(
                        fs_tail_tool($homeDir, $baseDir, $args)
                    );
                    break;

                case 'fs_search':
                    $resultPayload = tool_ok_result(
                        fs_search_tool($homeDir, $baseDir, $args)
                    );
                    break;

                case 'fs_move':
                    $resultPayload = tool_ok_result(
                        fs_move_tool($homeDir, $baseDir, $args)
                    );
                    break;

                case 'fs_delete':
                case 'fs_rm':
                    $resultPayload = tool_ok_result(
                        fs_delete_tool($homeDir, $baseDir, $args)
                    );
                    break;

                default:
                    jsonrpc_error($id, -32601, 'Unknown tool: ' . $toolName);
            }

            jsonrpc_response($id, $resultPayload);
            return;

        default:
            // Methods we do not implement (resources/*, prompts/*, logging/*, etc.).
            jsonrpc_error($id, -32601, 'Method not found: ' . $method);
    }
}

// ========================== MAIN ENTRYPOINT ==========================

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Rate limiting check (skip for SSE idle stream)
if ($method === 'POST' && !check_rate_limit()) {
    http_response_code(429);
    header('Content-Type: application/json');
    header('Retry-After: 60');
    echo json_encode([
        'jsonrpc' => '2.0',
        'id'      => null,
        'error'   => [
            'code'    => -32000,
            'message' => 'Rate limit exceeded. Try again later.',
        ],
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

if ($method === 'GET') {
    // Satisfy SSE-capable MCP clients that try to open a GET stream.
    handle_sse_get();
    exit;
}

if ($method !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json');
    echo json_encode(
        [
            'jsonrpc' => '2.0',
            'id'      => null,
            'error'   => [
                'code'    => -32600,
                'message' => 'Only POST is supported for JSON-RPC requests',
            ],
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
    exit;
}

// Maximum request body size (2MB should be plenty for MCP requests)
define('MAX_REQUEST_SIZE', 2 * 1024 * 1024);

$raw = file_get_contents('php://input', false, null, 0, MAX_REQUEST_SIZE + 1);

if ($raw === false) {
    jsonrpc_error(null, -32700, 'Failed to read request body');
}

if (strlen($raw) > MAX_REQUEST_SIZE) {
    jsonrpc_error(null, -32600, 'Request body too large');
}

$data = json_decode($raw, true);

if (!is_array($data)) {
    jsonrpc_error(null, -32700, 'Parse error: invalid JSON body');
}

if (!isset($data['jsonrpc'])) {
    jsonrpc_error($data['id'] ?? null, -32600, 'Invalid Request: expected JSON-RPC 2.0 payload');
}

handle_mcp_jsonrpc($data);
