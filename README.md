# NovaShield Terminal v3.1.0 — Enhanced Security Edition

**NovaShield** is a comprehensive, self-contained security monitoring and management platform featuring real-time terminal access, advanced file management, and enterprise-grade security controls. This single-script solution provides complete system monitoring with an intuitive web dashboard.

## 🚀 New in v3.1.0

- **Real Web Terminal**: Full PTY over WebSocket with live shell interaction
- **Enhanced Security**: 2FA/TOTP, CSRF protection, rate limiting, IP filtering, optional TLS
- **Advanced File Manager**: Sandboxed CRUD operations with real-time editing
- **Audit Logging**: Comprehensive activity tracking for security compliance
- **Self-Signed TLS**: Automatic certificate generation for secure connections
- **Improved UX**: Modern dashboard with responsive design and enhanced monitoring

## ⚡ Quick Start

NovaShield is delivered as a single, executable script that handles installation, configuration, and runtime management automatically. It detects your platform (Termux/Linux) and sets up everything needed.

### Installation

```bash
# 1) Download and make executable
curl -o novashield.sh https://raw.githubusercontent.com/MrNova420/NovaShield/main/novashield.sh
chmod +x novashield.sh

# 2) One-shot install (creates ~/.novashield and all components)
./novashield.sh --install

# 3) Start everything (monitors + web dashboard)
./novashield.sh --start

# 4) Open the dashboard
# Default: http://127.0.0.1:8765
# With TLS: https://127.0.0.1:8765
```

## 🎯 Core Features

### Security & Authentication
- **Multi-factor Authentication**: Username/password + optional TOTP 2FA
- **CSRF Protection**: Token-based request validation
- **Rate Limiting**: Configurable request throttling with auto-lockout
- **IP Filtering**: Allow/deny lists for network access control
- **TLS Support**: Self-signed certificate generation for encrypted connections
- **Session Management**: Secure cookie-based sessions with configurable timeouts

### Real-Time Terminal
- **WebSocket PTY**: Full terminal access through the web interface
- **Live Shell Interaction**: Real-time command execution with output streaming
- **Multiple Sessions**: Support for concurrent terminal connections
- **Security Auditing**: All terminal activity logged for compliance

### Advanced File Manager
- **Sandboxed Access**: Restricted to ~/.novashield directory tree
- **Full CRUD Operations**: Create, read, update, delete files and directories
- **Real-time Editing**: Built-in text editor with syntax awareness
- **File Type Filtering**: Configurable allowed file extensions
- **Size Limits**: Configurable maximum file size protection

### System Monitoring
- **Real-time Metrics**: CPU, memory, disk, network monitoring
- **Security Scanning**: Process monitoring, integrity checking
- **Alert System**: Configurable thresholds with multiple notification methods
- **Log Analysis**: Automated log parsing and anomaly detection
- **User Activity**: Login tracking and session monitoring

## 🔧 Configuration

NovaShield uses a comprehensive YAML configuration file located at `~/.novashield/config.yaml`. Key sections include:

### Security Settings
```yaml
security:
  auth_enabled: true
  totp_enabled: true
  tls_enabled: true
  csrf_enabled: true
  rate_limit_enabled: true
  ip_filtering_enabled: false
```

### Terminal Configuration
```yaml
terminal:
  enabled: true
  idle_timeout: 1800
  max_connections: 3
  shell: "/bin/bash"
  working_directory: "projects"
```

### File Manager Settings
```yaml
file_manager:
  enabled: true
  sandbox_root: ".novashield"
  max_file_size: 10485760
  allowed_extensions: [".txt", ".md", ".py", ".sh", ".yaml", ".yml", ".json", ".log"]
```

## 🛠️ Management Commands

```bash
# User & Security Management
./novashield.sh --add-user          # Add web dashboard user
./novashield.sh --enable-2fa         # Setup TOTP 2FA for user

# System Control
./novashield.sh --start             # Start all services
./novashield.sh --stop              # Stop all services
./novashield.sh --restart-monitors  # Restart monitoring services
./novashield.sh --status            # Show system status

# Data Management
./novashield.sh --backup            # Create encrypted backup
./novashield.sh --version-snapshot  # Create version snapshot
./novashield.sh --encrypt <path>    # Encrypt file/directory
./novashield.sh --decrypt <file>    # Decrypt file

# Interface
./novashield.sh --menu              # Interactive menu
./novashield.sh --web-start         # Start web server only
./novashield.sh --web-stop          # Stop web server only
```

## 🖥️ Dashboard Features

The web dashboard provides comprehensive system management through an intuitive interface:

- **Status Overview**: Real-time system metrics with health indicators
- **Terminal Access**: Full shell access with WebSocket-based PTY
- **File Manager**: Browse, edit, and manage files within the sandbox
- **Alert Monitoring**: View and manage system alerts and notifications
- **AI Assistant**: Jarvis integration for system queries and automation
- **Configuration**: Live configuration management and monitoring controls

## 🔒 Security Architecture

### Multi-layered Protection
1. **Authentication Layer**: Username/password + optional TOTP
2. **Session Layer**: Secure cookies with CSRF protection
3. **Network Layer**: Rate limiting and IP filtering
4. **Transport Layer**: Optional TLS encryption
5. **Application Layer**: Sandboxed operations and audit logging

### Audit Trail
All sensitive operations are logged to `~/.novashield/logs/audit.log`:
- User authentication events
- File system operations
- Terminal session activity
- Configuration changes
- Security events

## 📱 Platform Support

### Termux (Android)
- Automatic package installation via `pkg`
- Termux-services integration for background operation
- Android-specific optimizations and compatibility

### Linux (Debian/Ubuntu/Arch/Fedora)
- Multi-distro package manager support
- systemd user service integration
- Standard Linux security model compatibility

## 🚀 Advanced Features

### Background Services
- **Termux**: `sv-enable novashield` / `sv-disable novashield`
- **Linux**: `systemctl --user enable --now novashield`

### Network Configuration
```yaml
web:
  host: "127.0.0.1"     # Bind address
  port: 8765            # Service port
  allow_lan: false      # LAN access control
```

### Backup & Encryption
- Automated encrypted backups with rotation
- AES-256 encryption for sensitive data
- RSA keypair generation for secure operations
- Version snapshots for rollback capability

## 🔍 Monitoring & Alerts

NovaShield continuously monitors system health and security:

- **CPU/Memory/Disk**: Resource utilization with configurable thresholds
- **Network**: Connectivity monitoring and traffic analysis
- **Security**: Process monitoring and integrity verification
- **Logs**: Real-time log analysis with pattern detection
- **Users**: Login tracking and session management

## 📋 Requirements

**Minimal Requirements:**
- Bash 4.0+ (usually available by default)
- Python 3.6+ (auto-installed if missing)
- OpenSSL (auto-installed if missing)

**Platform-Specific:**
- **Termux**: Latest version recommended
- **Linux**: Any modern distribution with package manager

## 🤝 Contributing

NovaShield is designed as a comprehensive, single-file solution. The entire platform is contained within `novashield.sh` for maximum portability and ease of deployment.

## 📄 License

MIT License - See LICENSE file for details.

---

**NovaShield v3.1.0** - Professional security monitoring and management platform by niteas aka MrNova420