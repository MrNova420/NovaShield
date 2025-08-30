# NovaShield — Advanced JARVIS Edition

**NovaShield** is a comprehensive, self-contained security monitoring and administration dashboard for Termux and Linux systems. This latest **JARVIS Edition** features an advanced web interface with enterprise-level security, monitoring capabilities, and administrative tools.

![NovaShield JARVIS Dashboard](https://github.com/user-attachments/assets/8b9ee72d-4708-497b-a052-8bc6fa9e57ee)

## 🚀 Features

### 🎛️ **Advanced JARVIS Dashboard**
- **Modern UI**: Sleek, responsive design with JARVIS-themed interface
- **Real-time Monitoring**: Live system status with CPU, memory, disk, and network metrics
- **Multi-tab Interface**: Organized tabs for different system functions
- **Mobile Responsive**: Works perfectly on desktop, tablet, and mobile devices

### 🔐 **Enterprise Security**
- **Multi-factor Authentication**: TOTP-based 2FA support
- **Rate Limiting**: Automatic IP-based rate limiting (100 requests/minute)
- **Account Lockout**: IP banning after 5 failed login attempts
- **CSRF Protection**: Token-based CSRF protection for all API endpoints
- **Secure Sessions**: HttpOnly, SameSite secure cookie management
- **Enhanced Headers**: Security headers (XSS protection, content type options, etc.)

### 👥 **User Management**
- **Admin Panel**: Complete user administration interface
- **User CRUD Operations**: Add, delete, and manage users
- **Password Management**: Secure password reset functionality
- **2FA Management**: Enable/disable 2FA per user
- **Session Management**: View and manage active sessions

### 📁 **File Manager**
- **Full File Operations**: Browse, create, edit, delete, move, and rename files
- **Security Boundaries**: Restricted to NovaShield directory for safety
- **Syntax Highlighting**: Built-in file viewer with editing capabilities
- **Directory Navigation**: Intuitive directory browsing
- **Bulk Operations**: Support for multiple file operations

### 💬 **Jarvis AI Assistant**
- **Intelligent Responses**: Context-aware AI assistant
- **System Integration**: Direct system status and control queries
- **Chat History**: Persistent conversation logging
- **Help System**: Built-in help and guidance

### 🖥️ **Web Terminal**
- **Full Terminal Access**: Complete shell access through web interface
- **WebSocket Connection**: Real-time terminal interaction
- **Secure Sessions**: Authenticated terminal access
- **Keyboard Support**: Full keyboard shortcut support

### 📊 **System Monitoring**
- **Real-time Metrics**: Live CPU, memory, disk, and network monitoring
- **Alert System**: Configurable system alerts and notifications
- **Historical Data**: System performance tracking
- **Service Monitoring**: Monitor critical system services

### 🔧 **Configuration Management**
- **Live Config Editor**: Real-time YAML configuration editing
- **Validation**: Built-in YAML syntax validation
- **Backup/Restore**: Automatic config backup and restore
- **Safe Editing**: Configuration backup before changes

### 📧 **Notification System**
- **Email Notifications**: SMTP-based email alerts
- **Telegram Integration**: Telegram bot messaging
- **Discord Webhooks**: Discord channel notifications
- **Test Functions**: Built-in notification testing

### 💾 **Backup & Restore**
- **Automated Backups**: Scheduled and manual backup creation
- **Full System Restore**: Complete system state restoration
- **Backup Management**: List, download, and manage backups
- **Encrypted Storage**: Secure backup storage

## 📦 Installation

### Quick Installation

```bash
# 1) Download and make executable
curl -O https://raw.githubusercontent.com/MrNova420/NovaShield/main/novashield.sh
chmod +x novashield.sh

# 2) One-shot install (creates ~/.novashield and all components)
./novashield.sh --install

# 3) Start all services (monitors + web dashboard)
./novashield.sh --start
```

### Manual Setup

```bash
# Clone the repository
git clone https://github.com/MrNova420/NovaShield.git
cd NovaShield

# Make the script executable
chmod +x novashield.sh

# Install dependencies and setup
./novashield.sh --install

# Start the system
./novashield.sh --start
```

## 🌐 Accessing the Dashboard

After installation and startup, access the dashboard at:
- **Local Access**: http://127.0.0.1:8765
- **LAN Access**: Set `allow_lan: true` in config.yaml, then http://YOUR_IP:8765

### Default Access
- If authentication is disabled: Direct access to dashboard
- If authentication is enabled: Login screen will appear
- First-time setup will prompt for initial user creation

## 🎮 Usage

### Command Line Interface

```bash
# Interactive menu
./novashield.sh --menu

# System control
./novashield.sh --start          # Start all services
./novashield.sh --stop           # Stop all services
./novashield.sh --restart        # Restart services
./novashield.sh --status         # Check status

# Backup operations
./novashield.sh --backup         # Create encrypted backup
./novashield.sh --restore        # Restore from backup

# File operations
./novashield.sh --encrypt <path> # Encrypt file/directory
./novashield.sh --decrypt <file> # Decrypt file

# Version management
./novashield.sh --version-snapshot  # Create version snapshot

# Service control
./novashield.sh --web-start      # Start web server only
./novashield.sh --web-stop       # Stop web server only
./novashield.sh --restart-monitors  # Restart monitors only
```

### Web Dashboard Features

#### 📊 **Status Tab**
- Real-time system metrics
- Monitor control buttons
- System health indicators
- Performance graphs

#### 🚨 **Alerts Tab**
- Recent system alerts
- Alert history
- Notification status
- Alert configuration

#### 📁 **Files Tab**
- File browser with full CRUD operations
- Built-in text editor
- File upload/download
- Directory management
- Security-restricted access

#### 🖥️ **Terminal Tab**
- Full web-based terminal
- Real-time command execution
- Secure authenticated access
- Keyboard shortcut support

#### 🤖 **Jarvis Tab**
- AI assistant chat interface
- System query capabilities
- Help and guidance
- Command suggestions

#### 👥 **Admin Tab** (Admin users only)
- **User Management**: Add, delete, reset passwords
- **2FA Configuration**: Enable/disable per user
- **Notification Setup**: Configure email, Telegram, Discord
- **Backup Management**: Create, restore, download backups

#### ⚙️ **Config Tab**
- Live YAML configuration editing
- Real-time syntax validation
- Automatic backup before changes
- Configuration history

## 🔧 Configuration

### Main Configuration (`~/.novashield/config.yaml`)

```yaml
# Server Configuration
host: "127.0.0.1"
port: 8765
allow_lan: false

# Security Settings
security:
  auth_enabled: true
  auth_salt: "your-secret-salt"
  session_timeout: 3600
  max_login_attempts: 5
  lockout_duration: 300

# Monitoring Settings
monitoring:
  cpu_warning: 80
  cpu_critical: 95
  memory_warning: 80
  memory_critical: 95
  disk_warning: 85
  disk_critical: 95

# Notification Settings
notifications:
  email_enabled: false
  telegram_enabled: false
  discord_enabled: false
  alert_levels: ["CRIT", "WARN", "ERROR"]

# Backup Settings
backup:
  auto_backup: true
  backup_interval: 86400  # 24 hours
  max_backups: 10
  encryption_enabled: true
```

## 🏗️ Architecture

### Components
- **novashield.sh**: Main installer and runtime script
- **Web Server**: Python-based HTTP server with API
- **Frontend**: Modern JavaScript SPA with JARVIS theme
- **Monitoring**: Background system monitors
- **Database**: JSON-based data storage
- **Security**: Multi-layer security implementation

### Directory Structure
```
~/.novashield/
├── www/                    # Web interface files
│   ├── index.html         # Main dashboard
│   ├── login.html         # Login page
│   ├── app.js             # Frontend application
│   ├── style.css          # JARVIS theme styles
│   └── server.py          # Backend server
├── logs/                   # System and audit logs
├── control/               # Session and control data
├── keys/                  # Encryption keys
├── backups/               # System backups
├── modules/               # Custom modules
├── projects/              # User projects
├── versions/              # Version snapshots
└── config.yaml           # Main configuration
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **niteas aka MrNova420** - Original creator and maintainer
- **Community Contributors** - Feature requests and testing
- **Open Source Libraries** - Various dependencies and inspirations

---

**NovaShield JARVIS Edition** - Your Advanced Security Companion 🛡️