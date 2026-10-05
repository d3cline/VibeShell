# MCP VibeShell

A lightweight, single-file PHP implementation of the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables AI assistants to securely interact with files on any LAMP stack.

**Drop it on any PHP host. Instant AI-powered file access. No dependencies.**

---

## ✨ Features

- **Zero Dependencies** — Single `index.php` file, pure PHP 7.4+
- **Universal Compatibility** — Works on any LAMP/LEMP stack (shared hosting, VPS, cloud)
- **Secure by Design** — Path traversal protection, symlink resolution, protected file guards
- **MCP 2024-11-05 Compliant** — Full JSON-RPC 2.0 over HTTP transport
- **Rate Limited** — Built-in protection against abuse (120 requests/minute per IP)
- **Bearer Token Auth** — Simple, secure API authentication
- **Bounded Command Execution** — Opt-in commands with timeouts, output caps, stdin, environment overrides, and structured failures

---

## 🚀 Quick Start

### 1. Deploy

Upload `index.php` to your web server:

```bash
# Example: deploy to your app directory
scp index.php user@yourserver:~/apps/mcp/
```

### 2. Configure

Create the config file in your home directory:

```bash
# On your server
cat > ~/.mcp_vibeshell.ini << 'EOF'
[vibeshell]
token = "your-secure-token-here"
base_dir = "~"
EOF

# Generate a secure random token
openssl rand -hex 20
# Copy the output and paste it as your token value

# Set secure permissions
chmod 600 ~/.mcp_vibeshell.ini
```

### 3. Connect

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "vibeshell": {
      "type": "http",
      "url": "https://your-domain.com/mcp/",
      "headers": {
        "Authorization": "Bearer your-secure-token-here"
      }
    }
  }
}
```

---

## 🛠️ Available Tools

| Tool | Description |
|------|-------------|
| `fs_info` | Get home, base, apps, and logs directory paths |
| `fs_list` | List files and directories (with optional recursion) |
| `fs_read` | Read file contents (with offset/limit support) |
| `fs_write` | Write or append to files (with auto-mkdir) |
| `fs_tail` | Tail the last N lines of a file (great for logs) |
| `fs_search` | Search for text within files (recursive grep) |
| `fs_move` | Move or rename files and directories |
| `fs_delete` | Delete files or directories (with recursive option) |
| `fs_read_lines` | Read a line range with optional context |
| `fs_patch` | Apply line or exact-string patches, with dry-run and backup modes |
| `fs_diff` | Compare files or a file against supplied content |
| `shell_exec` | Run argv or shell commands with bounded time, output, stdin, cwd, and environment |

---

## 🔒 Security Features

### Path Protection
- All paths are jailed to the user's home directory
- Symlinks are resolved via `realpath()` to prevent escape attacks
- Path traversal attempts (`../`) are blocked

### Protected Files
The following paths cannot be modified or deleted:
- `~/.mcp_vibeshell.ini` (the config file itself)
- `~/.bashrc`, `~/.bash_profile`, `~/.profile`
- `~/.ssh/` and `~/.gnupg/`

### Additional Hardening
- Binary file detection (prevents leaking binary data)
- Rate limiting (120 requests/minute per IP)
- Request size limits (2MB max)
- Security headers on all responses
- Timing-safe token comparison
- Command execution is disabled by default and refuses to run without a non-empty Bearer token
- Command working directories are confined to `base_dir`
- Timed-out commands receive SIGTERM, then SIGKILL; process groups are used when supported
- Standard output, standard error, standard input, command size, and runtime are bounded

---

## ⚙️ Configuration

The config file `~/.mcp_vibeshell.ini` supports these options:

```ini
[vibeshell]
; Required: Bearer token for authentication
; Generate with: openssl rand -hex 20
; Leave empty to disable auth (NOT recommended)
token = "your-40-character-hex-token"

; Optional: Restrict file operations to a subdirectory
; "~" = full home directory access (default)
; "~/apps" = limit to apps folder only
base_dir = "~"

; Optional: enable remote command execution. Keep false on file-only endpoints.
shell_enabled = false

; Optional command limits. Hard caps are 900 seconds and 16 MiB.
shell_max_timeout = 120
shell_max_output_bytes = 1048576
shell_max_stdin_bytes = 1048576
```

Enabling `shell_exec` grants authenticated clients the same command authority as the PHP worker's OS user. Use HTTPS, a long unique token, restrictive config permissions, and a dedicated least-privilege account. Set `base_dir` to the narrowest useful directory; it confines the working directory but is not an OS sandbox, so commands may still access anything permitted to that OS user.

`shell_exec` accepts `command` as an argv array or a string. Arrays execute directly and avoid shell interpretation; strings run through `/bin/sh -c` for pipelines, redirects, and compound commands. Optional fields are `cwd`, `stdin`, `env`, and `timeout_seconds`.

```json
{
  "name": "shell_exec",
  "arguments": {
    "command": ["php", "-v"],
    "cwd": "apps/example",
    "timeout_seconds": 10,
    "env": {"APP_ENV": "production"}
  }
}
```

Results include `exit_code`, separate `stdout` and `stderr`, encodings, duration, timeout state, and truncation byte counts. Expected command failures return `failure: "nonzero_exit"`; validation and host failures are MCP tool errors with a stable `failure` value such as `disabled`, `invalid_cwd`, `stdin_limit`, `spawn_failed`, or `unsupported_host`.

---

## 📋 Requirements

- PHP 7.4 or higher
- PHP `proc_open` enabled when using `shell_exec`
- Nginx or Apache (any web server that can serve PHP)
- HTTPS strongly recommended for production

---

## 🧪 Testing

Test with curl:

```bash
# Initialize connection
curl -X POST https://your-domain.com/mcp/ \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}'

# List tools
curl -X POST https://your-domain.com/mcp/ \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# List files in home directory
curl -X POST https://your-domain.com/mcp/ \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fs_list","arguments":{"path":"~"}}}'
```

---

## 🤝 Use Cases

- **Opalstack / cPanel / Shared Hosting** — Add AI file access to managed hosting
- **Legacy LAMP Apps** — Enable AI assistants to help maintain older PHP projects  
- **Development Servers** — Quick MCP endpoint for testing
- **Edge Deployments** — Lightweight AI integration anywhere PHP runs

---

## 📜 License

GNU General Public License v3.0

---

## 🙏 Acknowledgments

Built for the [Model Context Protocol](https://modelcontextprotocol.io/) ecosystem.

Designed for [Opalstack](https://www.opalstack.com/) and any LAMP environment.
