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
```

---

## 📋 Requirements

- PHP 7.4 or higher
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

MIT License — Use it, modify it, ship it.

---

## 🙏 Acknowledgments

Built for the [Model Context Protocol](https://modelcontextprotocol.io/) ecosystem.

Designed for [Opalstack](https://www.opalstack.com/) and any LAMP environment.
