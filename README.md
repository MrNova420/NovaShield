# NovaShield — JARVIS Edition

**Advanced Security & Monitoring Platform with Comprehensive Web Dashboard**

NovaShield JARVIS Edition is a complete security and monitoring platform that provides real-time system monitoring, file management, web terminal access, AI assistance, and administrative tools through an advanced web interface.

## 🚀 Quick Start

### Installation & Startup

```bash
# 1) Save the installer script
wget https://raw.githubusercontent.com/MrNova420/NovaShield/main/novashield.sh
chmod +x novashield.sh

# 2) One-shot install (creates ~/.novashield and all components)
./novashield.sh --install

# 3) Start everything (monitors + web dashboard)
./novashield.sh --start

# 4) (optional) Check status
./novashield.sh --status
```

Then open the advanced dashboard:
**http://127.0.0.1:8765**

## ✨ Features

### 🎯 Advanced Dashboard
- **Multi-tab interface**: Status, Alerts, Files, Terminal, AI, Web Builder, Config, Admin
- **Real-time monitoring**: CPU, Memory, Disk, Network with color-coded status levels
- **Responsive design**: Mobile-friendly interface with dark theme
- **Modal login system**: Enhanced authentication with attempt tracking

### 🔐 Security & Authentication
- **Multi-factor authentication**: 2FA with TOTP support
- **Session management**: Secure token-based sessions with CSRF protection
- **Rate limiting**: Configurable request limits with automatic lockout
- **IP-based access control**: Allow/deny lists with temporary bans
- **Audit logging**: Comprehensive audit trail for all operations

### 📁 File Manager
- **Full CRUD operations**: Create, read, update, delete files and directories
- **Safe sandboxing**: All operations restricted to NovaShield home directory
- **Inline editing**: Edit files directly in the web interface
- **Directory navigation**: Browse the file system with parent directory navigation
- **File operations**: Move, rename, delete with confirmation dialogs

### 💻 Web Terminal
- **WebSocket-based**: Real-time terminal access through the browser
- **Session management**: Connect, disconnect, and clear terminal sessions
- **Keyboard support**: Full keyboard input including special keys and shortcuts
- **Auto-connect**: Automatically connects when accessing Terminal tab

### 🤖 AI Assistant (Jarvis)
- **Context-aware responses**: Understands system status, backup, and operational queries
- **Interactive chat**: Persistent chat log with conversation history
- **System integration**: Can provide information about system state and operations

### 🌐 Web Page Builder
- **Create web pages**: Build simple HTML pages with title and content
- **Page management**: Edit and delete existing pages
- **File-based storage**: Pages stored as HTML files in site directory

### ⚙️ Configuration Editor
- **YAML editing**: Edit NovaShield configuration through web interface
- **Syntax validation**: Real-time YAML validation with error reporting
- **Live reload**: Load current configuration and save changes

### 👑 Admin Panel
- **User management**: Add, delete, and manage user accounts
- **Password reset**: Reset user passwords through admin interface
- **2FA management**: Enable/disable 2FA for individual users
- **Backup & restore**: Create and restore system backups
- **Notification setup**: Configure email, Telegram, and Discord notifications

### 📊 System Monitoring
- **Real-time metrics**: CPU load, memory usage, disk space, network status
- **Alert system**: Live alerts feed with system events
- **Service monitoring**: Track running services and processes
- **Status levels**: Color-coded indicators (OK, WARN, CRIT)

### 🔧 Additional Features
- **Backup system**: Automated tar.gz backups with rotation
- **Version snapshots**: Quick system state snapshots
- **Monitor controls**: Start/stop individual monitoring components
- **Notification integration**: Email, Telegram, Discord alert support
- **Self-contained**: No external dependencies beyond Python standard library

## 🛠️ Usage Commands

### Interactive Menu
```bash
./novashield.sh --menu    # Interactive TUI for common actions
```

### Backup & Snapshots
```bash
./novashield.sh --backup                # Encrypted snapshot with rotation
./novashield.sh --version-snapshot      # Copy of modules/projects/config/logs
```

### Encryption
```bash
./novashield.sh --encrypt <path>         # AES-256 encrypt file/directory
./novashield.sh --decrypt <file.enc>     # Decrypt encrypted file
```

### Service Management
```bash
./novashield.sh --restart-monitors       # Restart background monitors
./novashield.sh --web-start              # Start web dashboard only
./novashield.sh --web-stop               # Stop web dashboard only
./novashield.sh --stop                   # Stop everything
```

### User Management
```bash
./novashield.sh --add-user               # Add new web user
./novashield.sh --enable-2fa             # Enable 2FA for user
```

## 🔧 Configuration

### Main Configuration (`~/.novashield/config.yaml`)

```yaml
security:
  auth_enabled: true          # Enable/disable authentication
  csrf_required: true         # Require CSRF tokens
  require_2fa: false          # Force 2FA for all users

web:
  bind_host: 127.0.0.1       # Web server bind address
  bind_port: 8765            # Web server port
  use_ssl: false             # Enable HTTPS (requires certs)
  allow_lan: false           # Allow LAN access

rate_limit_per_min: 60       # API requests per minute
lockout_threshold: 10        # Failed attempts before lockout

# IP Access Control
ip_allowlist:
  - 127.0.0.1
  - 192.168.1.0/24

ip_denylist:
  - 0.0.0.0/0                # Block all by default
```

### Service Integration

#### Termux (Android)
```bash
# Auto-installed if termux-services is available
sv-enable novashield         # Enable auto-start
sv-disable novashield        # Disable auto-start
```

#### systemd (Linux)
```bash
# Auto-installed for user systemd
systemctl --user enable --now novashield    # Enable and start
systemctl --user status novashield          # Check status
```

## 🏗️ Architecture

### Directory Structure
```
~/.novashield/
├── config.yaml              # Main configuration
├── keys/                     # Encryption keys & certs
│   ├── auth.salt            # Authentication salt
│   ├── aes.key              # AES encryption key
│   └── server.{crt,key}     # SSL certificates
├── www/                      # Web dashboard files
│   ├── index.html           # JARVIS dashboard
│   ├── style.css            # Advanced styling
│   ├── app.js               # Frontend application
│   └── server.py            # Backend API server
├── control/                  # Control & session files
│   ├── sessions.json        # User sessions & database
│   ├── ratelimit.json       # Rate limiting data
│   └── bans.json            # IP ban list
├── logs/                     # System logs
│   ├── audit.log            # Security audit log
│   ├── chat.log             # AI chat history
│   └── *.log                # Monitor logs
├── backups/                  # System backups
├── site/                     # Generated web pages
├── modules/                  # Custom modules
└── projects/                 # User projects
```

### Security Features

- **Authentication**: Salted SHA-256 password hashing
- **Session Management**: Secure token-based sessions with expiration
- **CSRF Protection**: Anti-CSRF tokens for all state-changing operations
- **Rate Limiting**: Per-IP request limiting with exponential backoff
- **File Sandboxing**: All file operations restricted to NovaShield directory
- **Input Validation**: Comprehensive input sanitization
- **Audit Logging**: All security-relevant operations logged
- **IP Access Control**: Configurable allow/deny lists

## 🧪 Testing

Run the automated test suite:

```bash
cd /path/to/NovaShield
python3 test_server.py
```

Tests cover:
- Authentication and session management
- File operations and security
- Rate limiting and lockout
- YAML configuration parsing
- System status generation
- AI response generation
- Backup functionality

## 🌟 Advanced Usage

### LAN Access
To expose the dashboard on your LAN:

1. Edit `~/.novashield/config.yaml`:
```yaml
web:
  bind_host: 0.0.0.0    # Listen on all interfaces
  allow_lan: true       # Enable LAN access
```

2. Configure firewall (if needed):
```bash
# UFW example
sudo ufw allow 8765/tcp
```

3. Restart NovaShield:
```bash
./novashield.sh --stop
./novashield.sh --start
```

### SSL/HTTPS Setup
1. Generate or obtain SSL certificates
2. Place in `~/.novashield/keys/server.{crt,key}`
3. Enable SSL in config:
```yaml
web:
  use_ssl: true
```

### Custom Notifications
Configure in the Admin panel or directly in `~/.novashield/control/notifications.json`:

```json
{
  "email": {
    "server": "smtp.gmail.com",
    "port": 587,
    "username": "your-email@gmail.com",
    "password": "app-password"
  },
  "telegram": {
    "token": "bot-token",
    "chat_id": "your-chat-id"
  },
  "discord": {
    "webhook_url": "discord-webhook-url"
  }
}
```

## 🤝 Contributing

NovaShield is open source and welcomes contributions! Areas for improvement:

- Additional monitoring modules
- Enhanced AI capabilities
- Mobile app development
- Plugin system
- Advanced analytics
- Integration with external tools

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**MrNova420** (niteas)
- GitHub: [@MrNova420](https://github.com/MrNova420)

---

*NovaShield JARVIS Edition - Advanced Security & Monitoring Platform*