# NovaShield Terminal 3.1.0 — JARVIS Edition

**Secure, encrypted terminal environment with real web dashboard, PTY terminal, and advanced security features**

## Features

### 🚀 What's New in 3.1.0

- **Real Web Terminal (PTY over WebSockets)** - Full terminal access through your browser with idle timeout and audit logging
- **Enhanced Security** - 2FA/TOTP support, CSRF protection, rate limiting, IP allow/deny lists, optional TLS with self-signed certs
- **Advanced File Manager** - Clickable interface with file viewer, mkdir, and save operations
- **Security-First Defaults** - Authentication enabled by default (`security.auth_enabled: true`)
- **Comprehensive Audit Logging** - Track login, control, terminal, file operations, and more
- **Improved Termux Support** - Better monitor stability, no netlink dependencies, automatic disk mount detection

### 🔐 Security Features

- **Authentication & Authorization** - User login system with session management
- **Two-Factor Authentication (2FA/TOTP)** - Compatible with Google Authenticator, Authy, etc.
- **TLS Support** - Optional HTTPS with auto-generated self-signed certificates
- **Rate Limiting** - Configurable request limits per minute
- **Account Lockout** - Temporary lockouts after failed login attempts
- **CSRF Protection** - Cross-site request forgery protection for POST requests
- **Secure Headers** - X-Frame-Options, X-XSS-Protection, Content-Security-Policy, etc.
- **IP Allow/Deny Lists** - Control access by IP address
- **Audit Logging** - Complete audit trail of security-sensitive actions

### 🖥️ Terminal Features

- **Real PTY Terminal** - Full pseudo-terminal with WebSocket streaming
- **Multiple Sessions** - Support for multiple concurrent terminal sessions
- **Idle Timeout** - Automatic session cleanup after inactivity
- **Command Auditing** - Optional logging of all terminal commands
- **Auto Shell Detection** - Termux-aware shell selection (`/data/data/.../bash` or system shell)

### 📁 File Management

- **Interactive File Browser** - Click to navigate directories and open files
- **File Editor** - Built-in editor for text files
- **Directory Operations** - Create new folders with mkdir
- **File Operations** - Create and save files directly through the web interface
- **Permission Aware** - Respects file system permissions

## Quick Start

### 1. Install NovaShield

```bash
# Download and make executable
curl -O https://raw.githubusercontent.com/MrNova420/NovaShield/main/novashield.sh
chmod +x novashield.sh

# One-shot install (creates ~/.novashield and all components)
./novashield.sh --install
```

### 2. Set Up Security

```bash
# Add a user (required since auth is enabled by default)
./novashield.sh --add-user

# Optional: Enable 2FA for enhanced security
./novashield.sh --enable-2fa
```

### 3. Start NovaShield

```bash
# Start all services (monitors + web dashboard)
./novashield.sh --start

# Open the dashboard
open http://127.0.0.1:8765
```

## Commands

```bash
./novashield.sh --install        # Initial setup and installation
./novashield.sh --start          # Start all services
./novashield.sh --stop           # Stop all services
./novashield.sh --status         # Show system status
./novashield.sh --add-user       # Add web dashboard user
./novashield.sh --enable-2fa     # Enable 2FA for a user
./novashield.sh --backup         # Create encrypted backup
./novashield.sh --restart-monitors # Restart monitoring services
./novashield.sh --menu           # Interactive TUI menu
```

## Security Configuration

### Enable TLS (HTTPS)

```yaml
# In ~/.novashield/config.yaml
security:
  tls_enabled: true
  tls_cert_file: "keys/server.crt"
  tls_key_file: "keys/server.key"
```

NovaShield will automatically generate self-signed certificates when TLS is enabled.

### Configure Rate Limiting

```yaml
security:
  rate_limit_per_min: 60
  lockout_threshold: 5
  lockout_duration_min: 15
```

### IP Access Control

```yaml
security:
  ip_allow_list: ["192.168.1.0/24", "10.0.0.0/8"]
  ip_deny_list: ["192.168.1.100"]
```

### Terminal Settings

```yaml
terminal:
  enabled: true
  idle_timeout_min: 30
  max_sessions: 5
  shell_command: "/bin/bash"  # Auto-detected if empty
  audit_commands: true
```

### Audit Logging

```yaml
audit:
  enabled: true
  log_file: "logs/audit.log"
  actions: ["login", "logout", "control", "terminal", "file_ops", "webgen", "backup"]
```

## Platform Support

### Linux
- **Distributions**: Debian, Ubuntu, Arch, Fedora, CentOS
- **Services**: systemd-user integration
- **Networking**: Full feature support

### Termux (Android)
- **Dependencies**: Auto-installs `openssl-tool`, `termux-services`
- **Services**: Termux services integration (`sv-enable novashield`)
- **Monitoring**: Termux-optimized monitors (no netlink dependencies)
- **Storage**: Auto-detects Termux paths and permissions

## Security Best Practices

### For Production Use

1. **Enable TLS**: Set `security.tls_enabled: true`
2. **Use Strong Authentication**: Enable 2FA for all users
3. **Restrict Network Access**: Use IP allow lists or firewall rules
4. **Regular Backups**: Set up automated encrypted backups
5. **Monitor Logs**: Review audit logs regularly
6. **Update Regularly**: Keep NovaShield updated to the latest version

### For LAN Access

```yaml
# In ~/.novashield/config.yaml
http:
  allow_lan: true  # Binds to 0.0.0.0 instead of 127.0.0.1

# Recommended with LAN access:
security:
  auth_enabled: true
  tls_enabled: true
  rate_limit_per_min: 30
```

⚠️ **Warning**: Only enable LAN access with proper authentication and preferably TLS enabled.

## Dashboard Features

### Status Tab
- Real-time system metrics (CPU, memory, disk, network)
- Color-coded alerts (OK/WARN/CRIT)
- Monitor control toggles

### Terminal Tab
- Full PTY terminal access
- Multiple session support
- Connection status indicator
- Session management controls

### Files Tab
- Directory navigation
- File/folder creation
- Built-in text editor
- Permission-aware operations

### Jarvis AI Assistant
- Context-aware help
- System status queries
- IP address lookup
- Command assistance

### Web Builder
- Simple webpage creation
- HTML content editor
- Static site generation

## Architecture

NovaShield uses a single-file design that generates all components at runtime:

```
~/.novashield/
├── config.yaml          # Main configuration
├── keys/                 # RSA, AES, and TLS keys
├── www/                  # Generated web assets
│   ├── server.py        # Python web server
│   ├── index.html       # Dashboard interface
│   ├── style.css        # Styling
│   └── app.js          # Frontend logic
├── logs/                # System and audit logs
├── control/             # Monitor control flags
└── sessions.json        # User sessions and 2FA secrets
```

## License

MIT License - see the repository for full license text.

## Contributing

This project welcomes contributions! Please see the GitHub repository for contributing guidelines.

---

**NovaShield 3.1.0** - Secure, feature-rich terminal environment for Termux and Linux