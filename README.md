# NovaShield — JARVIS Edition

**Advanced Security Monitoring & Management Platform**

NovaShield JARVIS Edition is a comprehensive security monitoring and management platform featuring real-time system monitoring, advanced file management, web terminal access, AI assistant capabilities, and complete administrative controls.

![NovaShield JARVIS Dashboard](https://github.com/user-attachments/assets/c95e81f2-ed8d-43a0-846a-f7c32862637c)

## Features

### 🔐 **Advanced Authentication & Security**
- **Enhanced Login System**: Modal login with proper error handling
- **2FA Support**: TOTP-based two-factor authentication with QR codes
- **CSRF Protection**: Cross-site request forgery protection
- **Rate Limiting**: Configurable request rate limiting per IP
- **Account Lockout**: Automatic lockout after failed login attempts
- **IP Access Control**: Allow/deny lists for network access
- **Session Management**: Secure session handling with idle timeouts
- **Audit Logging**: Comprehensive audit trail for all actions

### 📊 **Real-Time System Monitoring**
- **CPU Monitoring**: Load averages and utilization tracking
- **Memory Usage**: Real-time memory consumption with thresholds
- **Disk Space**: Storage usage monitoring with alerts
- **Network Status**: IP addresses, connectivity, and latency tracking
- **Process Monitoring**: System process oversight
- **Service Health**: Service status and availability checks
- **Integrity Monitoring**: File and system integrity verification
- **Alert System**: Real-time alerts and notifications

### 📁 **Enhanced File Manager**
- **File Operations**: Create, edit, delete, move, and rename files/folders
- **Directory Navigation**: Intuitive folder browsing with breadcrumbs
- **File Editor**: Built-in code editor with syntax highlighting
- **Permission Management**: File and folder permission controls
- **Backup & Restore**: File-level backup and restoration
- **Search Functionality**: Find files and content across the system
- **Bulk Operations**: Select and operate on multiple files

### 💻 **Web Terminal**
- **Full Shell Access**: Complete terminal emulation in the browser
- **Session Management**: Multiple concurrent terminal sessions
- **Idle Timeout**: Automatic session termination for security
- **Real-time I/O**: Bidirectional real-time terminal communication
- **Keyboard Support**: Full keyboard and control key support
- **Copy/Paste**: Clipboard integration for terminal operations

### 🤖 **Jarvis AI Assistant**
- **Natural Language Interface**: Chat with the system using natural language
- **System Status Queries**: Ask about system health and performance
- **Action Execution**: Trigger system actions through chat commands
- **Context Awareness**: AI understands system state and user context
- **Command Suggestions**: Helpful suggestions for common tasks

### 🌐 **Website Builder**
- **Page Creation**: Visual website and page builder
- **Content Management**: Rich text editing and content organization
- **Template System**: Pre-built templates for quick deployment
- **Page Management**: Edit, delete, and organize website pages
- **Publishing**: Instant website publishing and hosting

### ⚙️ **Configuration Editor**
- **YAML Editor**: Built-in YAML configuration editor
- **Syntax Validation**: Real-time YAML syntax checking
- **Live Reload**: Apply configuration changes without restart
- **Backup System**: Configuration versioning and rollback
- **Security Settings**: Comprehensive security configuration options

### 👥 **Admin Panel**
- **User Management**: Add, remove, and modify user accounts
- **Password Reset**: Administrative password reset capabilities
- **2FA Management**: Enable/disable 2FA for users
- **Role-Based Access**: User permissions and role management
- **System Actions**: Backup, restore, and maintenance operations
- **Notification Setup**: Configure email, Telegram, and Discord alerts

### 🔧 **System Integration**
- **Backup & Restore**: Complete system backup and restoration
- **Service Management**: Start, stop, and monitor system services
- **Log Management**: Centralized logging and log analysis
- **Performance Tuning**: System optimization and performance monitoring
- **Health Checks**: Automated system health verification

## Quick Start

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/MrNova420/NovaShield.git
   cd NovaShield
   ```

2. **Make Installer Executable**:
   ```bash
   chmod +x novashield.sh
   ```

3. **Install NovaShield**:
   ```bash
   ./novashield.sh --install
   ```

4. **Start the Platform**:
   ```bash
   ./novashield.sh --start
   ```

### Quick Development Setup

1. **Start the Web Server**:
   ```bash
   cd www
   python3 server.py
   ```

2. **Access the Dashboard**:
   - Open browser to: `http://127.0.0.1:8765`
   - Default login: `admin` / `admin123`

### Testing

Run the automated test suite:
```bash
python3 test_server.py
```

## Configuration

Edit `~/.novashield/config.yaml` to customize:

```yaml
# Security Configuration
security:
  auth_enabled: true
  csrf_required: true
  require_2fa: false
  auth_salt: changeme
  tls_enabled: false
  
# Network Configuration
host: 127.0.0.1
port: 8765
allow_lan: false

# Rate Limiting
rate_limit_per_min: 60
lockout_threshold: 10

# Access Control
ip_allowlist:
  - 127.0.0.1
  - 192.168.1.0/24

# Terminal Configuration
terminal:
  shell: /bin/bash
  idle_timeout_sec: 900
  allow_write: true
  cols: 120
  rows: 32
```

## API Endpoints

### Authentication
- `POST /api/login` - User authentication with 2FA support
- `POST /api/logout` - Session termination

### System Monitoring
- `GET /api/status` - Real-time system status
- `GET /api/logs` - System logs and events

### File Management
- `GET /api/fs` - Directory listing
- `GET /api/fs_read` - Read file contents
- `POST /api/fs_write` - Write file contents
- `POST /api/fs_mkdir` - Create directories
- `POST /api/fs_rm` - Delete files/folders
- `POST /api/fs_mv` - Move/rename files

### User Management
- `GET /api/admin/users` - List users
- `POST /api/admin/add_user` - Add new user
- `POST /api/admin/delete_user` - Remove user
- `POST /api/admin/reset_password` - Reset user password
- `POST /api/admin/toggle_2fa` - Enable/disable 2FA

### System Control
- `POST /api/control` - System actions (backup, restart, etc.)
- `POST /api/chat` - Jarvis AI assistant
- `GET /api/config` - Configuration management
- `POST /api/config_save` - Save configuration

### WebSocket Endpoints
- `WS /ws/term` - Web terminal connection

## Architecture

### Frontend
- **Pure JavaScript**: No external dependencies
- **Responsive Design**: Mobile-friendly interface
- **Real-time Updates**: WebSocket and AJAX communication
- **Progressive Enhancement**: Works without JavaScript for basic functions

### Backend
- **Python 3**: Pure Python implementation
- **HTTP Server**: Built-in HTTP server with WebSocket support
- **Security First**: Comprehensive security controls
- **Modular Design**: Extensible architecture

### Security Model
- **Authentication**: Username/password with optional 2FA
- **Authorization**: Role-based access control
- **Communication**: HTTPS/WSS encryption support
- **Input Validation**: Comprehensive input sanitization
- **Audit Trail**: Complete action logging

## Platform Compatibility

- **Linux**: Full support (Ubuntu, Debian, CentOS, etc.)
- **macOS**: Full support
- **Termux**: Android terminal support
- **Windows**: WSL/Cygwin support

## Development

### Project Structure
```
NovaShield/
├── www/                 # Web interface
│   ├── index.html      # JARVIS dashboard
│   ├── server.py       # Python web server
│   ├── app.js          # Frontend JavaScript
│   └── style.css       # JARVIS styling
├── novashield.sh       # Installation & management script
├── test_server.py      # Automated tests
└── README.md          # Documentation
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Security

NovaShield JARVIS Edition is designed with security as the primary focus:

- **Defense in Depth**: Multiple layers of security controls
- **Principle of Least Privilege**: Minimal required permissions
- **Secure by Default**: Security features enabled by default
- **Regular Updates**: Continuous security improvements
- **Audit Ready**: Comprehensive logging and monitoring

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: See the [Wiki](../../wiki) for detailed guides
- **Issues**: Report bugs via [GitHub Issues](../../issues)
- **Community**: Join discussions in [GitHub Discussions](../../discussions)

## Changelog

### v3.1.0 - JARVIS Edition
- Complete platform overhaul with JARVIS interface
- Enhanced authentication with 2FA and rate limiting
- Advanced file manager with full CRUD operations
- Integrated web terminal with WebSocket support
- AI assistant (Jarvis) for natural language system interaction
- Comprehensive admin panel for user and system management
- Real-time monitoring dashboard with status cards
- Website builder with page management
- Configuration editor with YAML validation
- Mobile-responsive design
- Complete API coverage with automated tests
- Enhanced security controls and audit logging

---

**NovaShield JARVIS Edition** - Advanced Security Monitoring & Management Platform  
Created by **niteas aka MrNova420**

I built you a single, self-contained script that sets up the entire NovaShield Terminal 2.0 project end-to-end (installer + runtime). It:

Detects Termux vs Linux, installs deps, creates the full directory tree.

Generates RSA + AES keys, encryption helpers (file/dir encrypt/decrypt).

Starts 5 background monitors (CPU, memory, disk, network, integrity).

Spins up a Python web dashboard (no external libs) with live status/alerts.

Adds backup + version snapshots, rotation, and manual overrides.

Supports Termux services or systemd-user (when available).

Provides a CLI + interactive menu.


I put the complete all-in-one script in the canvas (left panel) as “NovaShield Terminal 2.0 — All-in-One Installer & Runtime (novashield.sh)”. Save it as novashield.sh, make it executable, and run the steps below.

# 1) Save the script
nano novashield.sh   # paste the canvas contents
chmod +x novashield.sh

# 2) One-shot install (creates ~/.novashield and all subfiles)
./novashield.sh --install

# 3) Start everything (monitors + web dashboard)
./novashield.sh --start

# 4) (optional) Check status
./novashield.sh --status

Then open the local dashboard (by default):
http://127.0.0.1:8765

Useful commands

./novashield.sh --menu – interactive TUI for common actions

./novashield.sh --backup – encrypted snapshot with rotation

./novashield.sh --version-snapshot – copy of modules/projects/config/logs

./novashield.sh --encrypt <path> / --decrypt <file.enc> – AES-256 via OpenSSL

./novashield.sh --restart-monitors – bounce the background monitors

./novashield.sh --web-start / --web-stop – control the dashboard server

./novashield.sh --stop – stop everything


Notes & next steps

Termux services: If termux-services is installed, the script drops a service at ~/.termux/services/novashield. You can enable/disable with sv-enable novashield / sv-disable novashield.

systemd-user (Linux): Creates ~/.config/systemd/user/novashield.service. Enable with:

systemctl --user enable --now novashield

LAN access: To expose the dashboard on your LAN, set allow_lan: true in ~/.novashield/config.yaml and restart.

Security: Keys live in ~/.novashield/keys/ with 600 perms. Backups can be encrypted by default. Keep your AES key safe.

Extend: Drop your own scripts into ~/.novashield/modules/ and your work into ~/.novashield/projects/.


If you want me to also package this into a ready-to-push GitHub repo layout (README, LICENSE, .gitignore, screenshots), say the word and I’ll generate those files too.
