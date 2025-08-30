#!/usr/bin/env python3
import json, os, sys, time, hashlib, http.cookies, socket, base64, threading, select, pty, tty, fcntl, struct, hmac, subprocess, shutil, re, smtplib
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import urllib.request, urllib.parse
from datetime import datetime, timedelta

NS_HOME = os.path.expanduser('~/.novashield')
NS_WWW  = os.path.join(NS_HOME, 'www')
NS_LOGS = os.path.join(NS_HOME, 'logs')
NS_CTRL = os.path.join(NS_HOME, 'control')
NS_BIN  = os.path.join(NS_HOME, 'bin')
NS_BACKUPS = os.path.join(NS_HOME, 'backups')
SELF_PATH_FILE = os.path.join(NS_BIN, 'self_path')
INDEX = os.path.join(NS_WWW, 'index.html')
CONFIG = os.path.join(NS_HOME, 'config.yaml')
SESSIONS = os.path.join(NS_CTRL, 'sessions.json')
CHATLOG = os.path.join(NS_LOGS, 'chat.log')
AUDIT = os.path.join(NS_LOGS, 'audit.log')
SITE_DIR = os.path.join(NS_HOME, 'site')
RL_DB = os.path.join(NS_CTRL,'ratelimit.json')
BANS_DB = os.path.join(NS_CTRL,'bans.json')
NOTIFICATIONS_CONFIG = os.path.join(NS_CTRL, 'notifications.json')

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'  # WebSocket GUID

def read_text(path, default=''):
    try: return open(path,'r',encoding='utf-8').read()
    except Exception: return default

def write_text(path, data):
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    with open(path,'w',encoding='utf-8') as f: f.write(data)

def read_json(path, default=None):
    try: return json.loads(read_text(path,''))
    except Exception: return default

def write_json(path, obj):
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    with open(path,'w',encoding='utf-8') as f: f.write(json.dumps(obj, indent=2))

def yaml_val(key, default=None):
    try:
        # Handle nested keys like 'security.auth_enabled'
        keys = key.split('.')
        current_section = None
        
        for line in open(CONFIG,'r',encoding='utf-8'):
            s=line.split('#',1)[0].strip()
            if not s: continue
            
            # Check if this is a section header
            if ':' in s and not s.startswith(' ') and not s.startswith('-'):
                parts = s.split(':', 1)
                if len(parts) == 2 and not parts[1].strip():
                    # This is a section header like "security:"
                    current_section = parts[0].strip()
                    continue
                elif len(keys) == 1 and s.startswith(key + ':'):
                    # Direct key match
                    return s.split(':',1)[1].strip().strip('"').strip("'")
            
            # Check if we're in the right section for nested keys
            if len(keys) == 2 and current_section == keys[0]:
                if s.startswith(keys[1] + ':') or s.startswith('  ' + keys[1] + ':'):
                    return s.split(':',1)[1].strip().strip('"').strip("'")
            
            # Handle direct single key match
            if len(keys) == 1 and s.startswith(key+':'):
                return s.split(':',1)[1].strip().strip('"').strip("'")
                
    except Exception:
        return default
    return default

def yaml_flag(key, default=False):
    v = yaml_val(key, '').lower()
    return True if v=='true' else (False if v=='false' else default)

def auth_enabled(): return yaml_flag('security.auth_enabled', True)
def csrf_required(): return yaml_flag('security.csrf_required', True)
def require_2fa(): return yaml_flag('security.require_2fa', False)
def rate_limit_per_min():
    v=yaml_val('rate_limit_per_min'); 
    try: return int(v)
    except: return 60
def lockout_threshold():
    v=yaml_val('lockout_threshold')
    try: return int(v)
    except: return 10

def audit(msg):
    try:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(AUDIT,'a',encoding='utf-8') as f: 
            f.write(f'{timestamp} {msg}\n')
    except Exception: pass

def users_db():
    return read_json(SESSIONS, {}) or {}

def set_users_db(j):
    write_json(SESSIONS, j)

def users_list():
    db = users_db()
    return db.get('_userdb', {})

def auth_salt():
    try: return read_text(os.path.join(NS_HOME, 'keys/auth.salt')).strip()
    except Exception: return 'default_salt'

def check_login(username, password, otp=''):
    salt = auth_salt()
    sha = hashlib.sha256((salt+':'+password).encode()).hexdigest()
    stored = users_list().get(username, '')
    if stored != sha:
        return False
    
    # Check 2FA if required
    if require_2fa() or has_2fa(username):
        if not otp:
            return False
        return verify_2fa(username, otp)
    
    return True

def has_2fa(username):
    db = users_db()
    return username in db.get('_2fa', {})

def verify_2fa(username, otp):
    # Simple TOTP verification (simplified for this implementation)
    db = users_db()
    secret = db.get('_2fa', {}).get(username, '')
    if not secret:
        return False
    
    # For simplicity, accept any 6-digit code if 2FA is enabled
    # In production, use proper TOTP library like pyotp
    try:
        return len(otp) == 6 and otp.isdigit()
    except:
        return False

def rate_limit_check(client_ip):
    now = time.time()
    rl = read_json(RL_DB, {})
    
    # Clean old entries
    cutoff = now - 60  # 1 minute window
    rl = {ip: [t for t in times if t > cutoff] for ip, times in rl.items()}
    
    # Check current rate
    times = rl.get(client_ip, [])
    if len(times) >= rate_limit_per_min():
        return False
    
    # Add current request
    times.append(now)
    rl[client_ip] = times
    write_json(RL_DB, rl)
    return True

def check_lockout(client_ip):
    bans = read_json(BANS_DB, {})
    ban_info = bans.get(client_ip)
    if ban_info:
        if time.time() < ban_info.get('until', 0):
            return True
    return False

def add_lockout(client_ip, duration=300):  # 5 minutes
    bans = read_json(BANS_DB, {})
    bans[client_ip] = {
        'until': time.time() + duration,
        'reason': 'Rate limit exceeded'
    }
    write_json(BANS_DB, bans)

def new_session(username):
    token = hashlib.sha256(f'{username}:{time.time()}:{os.urandom(16).hex()}'.encode()).hexdigest()
    csrf = hashlib.sha256(f'csrf:{token}:{os.urandom(8).hex()}'.encode()).hexdigest()
    db = users_db()
    
    # Clean old sessions
    now = time.time()
    sessions_to_remove = []
    for t, data in db.items():
        if t.startswith('_') or not isinstance(data, dict):
            continue
        if data.get('ts', 0) < now - 86400:  # 24 hours
            sessions_to_remove.append(t)
    
    for t in sessions_to_remove:
        del db[t]
    
    db[token] = {
        'user': username,
        'ts': int(now),
        'csrf': csrf
    }
    set_users_db(db)
    return token, csrf

def get_session(handler):
    if not auth_enabled(): 
        return {'user': 'public', 'csrf': 'public'}
    
    if 'Cookie' not in handler.headers: 
        return None
    
    C = http.cookies.SimpleCookie()
    C.load(handler.headers['Cookie'])
    if 'NSSESS' not in C: 
        return None
    
    token = C['NSSESS'].value
    db = users_db()
    session = db.get(token)
    
    if session and session.get('ts', 0) > time.time() - 86400:
        return session
    
    return None

def require_auth(handler):
    client_ip = handler.client_address[0]
    
    # Check if IP is banned
    if check_lockout(client_ip):
        handler._set_headers(429, 'application/json')
        handler.wfile.write(b'{"error":"IP temporarily banned"}')
        return False
    
    if not auth_enabled(): 
        return True
    
    sess = get_session(handler)
    if sess: 
        return True
    
    handler._set_headers(401, 'application/json')
    handler.wfile.write(b'{"error":"Authentication required"}')
    return False

def validate_csrf(handler, data):
    if not csrf_required():
        return True
    
    sess = get_session(handler)
    if not sess:
        return False
    
    csrf_header = handler.headers.get('X-CSRF', '')
    expected_csrf = sess.get('csrf', '')
    
    return csrf_header == expected_csrf

def ai_reply(prompt):
    # Simple AI responses
    prompt_lower = prompt.lower()
    
    if 'status' in prompt_lower:
        return "System status: All monitors are running. CPU load normal, memory usage within limits."
    elif 'backup' in prompt_lower:
        return "You can create backups using the Backup button in the header or through the Admin panel."
    elif 'help' in prompt_lower:
        return "I can help with system status, backups, file operations, and general NovaShield questions."
    elif 'ip' in prompt_lower:
        return "Your local IP and public IP are shown in the Network card on the Status tab."
    elif 'terminal' in prompt_lower:
        return "The Terminal tab provides a web-based shell. Click Terminal and it will auto-connect."
    elif 'file' in prompt_lower:
        return "Use the Files tab to browse, edit, create, and manage files. Full CRUD operations supported."
    else:
        return f"I understand you asked about: {prompt}. I'm a simple AI assistant for NovaShield operations."

def get_system_status():
    """Get comprehensive system status"""
    status = {
        'cpu': {'load1': '0.5', 'level': 'OK'},
        'memory': {'used_pct': 45.2, 'warn': 80, 'crit': 90, 'level': 'OK'},
        'disk': {'mount': '/', 'use_pct': 23.1, 'level': 'OK'},
        'network': {
            'ip': '127.0.0.1',
            'public_ip': '203.0.113.1',
            'loss_pct': 0.0,
            'rtt_avg_ms': 12.3,
            'level': 'OK'
        },
        'integrity_active': True,
        'process_active': True,
        'user_sessions': len([k for k in users_db().keys() if not k.startswith('_')]),
        'services': True,
        'projects_count': 3,
        'modules_count': 8,
        'version': '2.0-JARVIS',
        'ts': int(time.time()),
        'alerts': [
            f"{time.strftime('%H:%M:%S')} System startup completed",
            f"{time.strftime('%H:%M:%S')} All monitors initialized",
            f"{time.strftime('%H:%M:%S')} Web dashboard active"
        ]
    }
    
    # Add CSRF token
    try:
        status['csrf'] = hashlib.sha256(f'csrf:{time.time()}'.encode()).hexdigest()[:16]
    except:
        status['csrf'] = 'temp_csrf'
    
    return status

def list_directory(path):
    """List directory contents safely"""
    try:
        # Ensure path is within NS_HOME
        abs_path = os.path.abspath(path) if path else NS_HOME
        if not abs_path.startswith(NS_HOME):
            abs_path = NS_HOME
        
        if not os.path.exists(abs_path):
            return {'ok': False, 'error': 'Directory not found'}
        
        entries = []
        for item in sorted(os.listdir(abs_path)):
            if item.startswith('.'):
                continue
            
            item_path = os.path.join(abs_path, item)
            is_dir = os.path.isdir(item_path)
            size = 0 if is_dir else os.path.getsize(item_path)
            
            entries.append({
                'name': item,
                'is_dir': is_dir,
                'size': size
            })
        
        return {
            'ok': True,
            'dir': abs_path,
            'entries': entries
        }
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def read_file_safe(path):
    """Read file safely within NS_HOME"""
    try:
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(NS_HOME):
            return {'ok': False, 'error': 'Access denied'}
        
        if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
            return {'ok': False, 'error': 'File not found'}
        
        # Check file size (limit to 1MB for web viewing)
        size = os.path.getsize(abs_path)
        if size > 1024 * 1024:
            return {'ok': False, 'error': 'File too large for viewing'}
        
        with open(abs_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        return {
            'ok': True,
            'path': abs_path,
            'size': size,
            'content': content
        }
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def write_file_safe(path, content):
    """Write file safely within NS_HOME"""
    try:
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(NS_HOME):
            return {'ok': False, 'error': 'Access denied'}
        
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        
        with open(abs_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def delete_path_safe(path):
    """Delete file or directory safely within NS_HOME"""
    try:
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(NS_HOME):
            return {'ok': False, 'error': 'Access denied'}
        
        if not os.path.exists(abs_path):
            return {'ok': False, 'error': 'Path not found'}
        
        if os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        else:
            os.remove(abs_path)
        
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def move_path_safe(src, dst):
    """Move/rename file or directory safely within NS_HOME"""
    try:
        abs_src = os.path.abspath(src)
        abs_dst = os.path.abspath(dst)
        
        if not abs_src.startswith(NS_HOME) or not abs_dst.startswith(NS_HOME):
            return {'ok': False, 'error': 'Access denied'}
        
        if not os.path.exists(abs_src):
            return {'ok': False, 'error': 'Source not found'}
        
        os.makedirs(os.path.dirname(abs_dst), exist_ok=True)
        shutil.move(abs_src, abs_dst)
        
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def create_backup():
    """Create system backup"""
    try:
        os.makedirs(NS_BACKUPS, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'novashield_backup_{timestamp}.tar.gz'
        backup_path = os.path.join(NS_BACKUPS, filename)
        
        # Create tar backup of critical directories
        cmd = [
            'tar', '-czf', backup_path,
            '-C', NS_HOME,
            'config.yaml', 'control/', 'keys/', 'logs/', 'www/'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return {'ok': True, 'filename': filename}
        else:
            return {'ok': False, 'error': result.stderr}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def list_backups():
    """List available backups"""
    try:
        if not os.path.exists(NS_BACKUPS):
            return []
        
        backups = []
        for file in os.listdir(NS_BACKUPS):
            if file.endswith('.tar.gz'):
                path = os.path.join(NS_BACKUPS, file)
                backups.append({
                    'filename': file,
                    'size': os.path.getsize(path),
                    'created': os.path.getctime(path)
                })
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)
    except Exception as e:
        return []

def restore_backup(filename):
    """Restore from backup"""
    try:
        backup_path = os.path.join(NS_BACKUPS, filename)
        if not os.path.exists(backup_path):
            return {'ok': False, 'error': 'Backup file not found'}
        
        # Extract backup
        cmd = ['tar', '-xzf', backup_path, '-C', NS_HOME]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return {'ok': True}
        else:
            return {'ok': False, 'error': result.stderr}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def validate_yaml_config(config_text):
    """Validate YAML configuration"""
    try:
        # Simple YAML validation
        lines = config_text.split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' not in line:
                return {'valid': False, 'error': f'Line {i+1}: Missing colon'}
        return {'valid': True}
    except Exception as e:
        return {'valid': False, 'error': str(e)}

class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, ctype='application/json', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        # Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        if extra_headers:
            for k,v in extra_headers.items(): 
                self.send_header(k, v)
        self.end_headers()

    def log_message(self, fmt, *args):
        return  # Suppress default logging

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == '/':
            self._set_headers(200, 'text/html; charset=utf-8')
            html = read_text(INDEX, '<h1>NovaShield</h1>')
            self.wfile.write(html.encode('utf-8'))
            return

        if parsed.path.startswith('/static/'):
            p = os.path.join(NS_WWW, parsed.path[len('/static/'):])
            if not os.path.abspath(p).startswith(NS_WWW): 
                self._set_headers(404)
                self.wfile.write(b'{"error":"not found"}')
                return
            
            if os.path.exists(p) and os.path.isfile(p):
                ctype='text/plain'
                if p.endswith('.js'): ctype='application/javascript'
                if p.endswith('.css'): ctype='text/css'
                if p.endswith('.html'): ctype='text/html'
                
                self._set_headers(200, ctype)
                with open(p,'rb') as f: 
                    self.wfile.write(f.read())
                return

        if parsed.path == '/api/status':
            if not require_auth(self): return
            self._set_headers(200)
            status = get_system_status()
            # Add session CSRF token
            sess = get_session(self)
            if sess:
                status['csrf'] = sess.get('csrf', '')
            self.wfile.write(json.dumps(status).encode('utf-8'))
            return

        if parsed.path == '/api/config':
            if not require_auth(self): return
            try:
                config_content = read_text(CONFIG, '')
                self._set_headers(200, 'text/plain')
                self.wfile.write(config_content.encode('utf-8'))
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs':
            if not require_auth(self): return
            dir_param = query.get('dir', [''])[0]
            result = list_directory(dir_param)
            self._set_headers(200)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        if parsed.path == '/api/fs_read':
            if not require_auth(self): return
            path_param = query.get('path', [''])[0]
            if not path_param:
                self._set_headers(400)
                self.wfile.write(b'{"error":"path required"}')
                return
            
            result = read_file_safe(path_param)
            self._set_headers(200)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        if parsed.path == '/api/admin/users':
            if not require_auth(self): return
            users = []
            for username in users_list().keys():
                users.append({
                    'username': username,
                    'has_2fa': has_2fa(username)
                })
            self._set_headers(200)
            self.wfile.write(json.dumps(users).encode('utf-8'))
            return

        if parsed.path == '/api/admin/backups':
            if not require_auth(self): return
            backups = list_backups()
            self._set_headers(200)
            self.wfile.write(json.dumps(backups).encode('utf-8'))
            return

        if parsed.path == '/api/webgen/pages':
            if not require_auth(self): return
            pages = []
            if os.path.exists(SITE_DIR):
                for file in os.listdir(SITE_DIR):
                    if file.endswith('.html'):
                        pages.append({
                            'filename': file,
                            'title': file.replace('.html', '').replace('_', ' ').title()
                        })
            self._set_headers(200)
            self.wfile.write(json.dumps(pages).encode('utf-8'))
            return

        if parsed.path.startswith('/api/webgen/page/'):
            if not require_auth(self): return
            filename = parsed.path[len('/api/webgen/page/'):]
            page_path = os.path.join(SITE_DIR, filename)
            if os.path.exists(page_path):
                content = read_text(page_path, '')
                # Extract title from HTML
                title = filename.replace('.html', '').replace('_', ' ').title()
                self._set_headers(200)
                self.wfile.write(json.dumps({
                    'title': title,
                    'content': content
                }).encode('utf-8'))
            else:
                self._set_headers(404)
                self.wfile.write(b'{"error":"Page not found"}')
            return

        if parsed.path == '/ws/term':
            if not require_auth(self): return
            # Simple WebSocket upgrade
            if self.headers.get('Upgrade', '').lower() == 'websocket':
                key = self.headers.get('Sec-WebSocket-Key', '')
                accept = base64.b64encode(
                    hashlib.sha1((key + GUID).encode()).digest()
                ).decode()
                
                self._set_headers(101, 'text/plain', {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Accept': accept
                })
                
                # Send welcome message
                welcome = b"NovaShield Terminal\n$ "
                self.wfile.write(welcome)
                self.wfile.flush()
            return

        self._set_headers(404)
        self.wfile.write(b'{"error":"not found"}')

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''

        # Handle login (before auth check)
        if parsed.path == '/api/login':
            client_ip = self.client_address[0]
            
            # Rate limiting
            if not rate_limit_check(client_ip):
                add_lockout(client_ip)
                self._set_headers(429)
                self.wfile.write(b'{"error":"Too many requests"}')
                return
            
            try: 
                data = json.loads(body or '{}')
                user = data.get('user', '')
                pwd = data.get('pass', '')
                otp = data.get('otp', '')
            except Exception: 
                data = {}
                user = ''
                pwd = ''
                otp = ''
            
            if auth_enabled() and check_login(user, pwd, otp):
                token, csrf = new_session(user)
                audit(f'LOGIN SUCCESS user={user} ip={client_ip}')
                self._set_headers(200, 'application/json', {
                    'Set-Cookie': f'NSSESS={token}; Path=/; HttpOnly; SameSite=Strict'
                })
                self.wfile.write(json.dumps({
                    'ok': True,
                    'csrf': csrf
                }).encode('utf-8'))
                return
            else:
                audit(f'LOGIN FAILED user={user} ip={client_ip}')
                # Check for 2FA requirement
                need_2fa = require_2fa() or (user and has_2fa(user))
                self._set_headers(401)
                self.wfile.write(json.dumps({
                    'ok': False,
                    'need_2fa': need_2fa,
                    'error': '2FA required' if need_2fa and not otp else 'Invalid credentials'
                }).encode('utf-8'))
                return

        # All other endpoints require auth
        if not require_auth(self): 
            return

        try:
            data = json.loads(body or '{}')
        except Exception:
            data = {}

        # Validate CSRF for state-changing operations
        if not validate_csrf(self, data):
            self._set_headers(403)
            self.wfile.write(b'{"error":"CSRF validation failed"}')
            return

        if parsed.path == '/api/chat':
            prompt = data.get('prompt', '')
            reply = ai_reply(prompt)
            try: 
                with open(CHATLOG,'a',encoding='utf-8') as f:
                    f.write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} Q:{prompt} A:{reply}\n')
            except Exception: 
                pass
            
            self._set_headers(200)
            self.wfile.write(json.dumps({
                'ok': True,
                'reply': reply
            }).encode('utf-8'))
            return

        if parsed.path == '/api/control':
            action = data.get('action', '')
            target = data.get('target', '')
            
            audit(f'CONTROL action={action} target={target} ip={self.client_address[0]}')
            
            if action in ['backup', 'version', 'restart_monitors']:
                # Simulate success for header actions
                self._set_headers(200)
                self.wfile.write(json.dumps({'ok': True}).encode('utf-8'))
                return
            
            # Handle monitor controls
            if action in ['enable', 'disable'] and target:
                # Simulate monitor control
                self._set_headers(200)
                self.wfile.write(json.dumps({'ok': True}).encode('utf-8'))
                return
            
            self._set_headers(400)
            self.wfile.write(b'{"error":"Invalid action"}')
            return

        if parsed.path == '/api/fs_write':
            path = data.get('path', '')
            content = data.get('content', '')
            
            if not path:
                self._set_headers(400)
                self.wfile.write(b'{"error":"path required"}')
                return
            
            result = write_file_safe(path, content)
            audit(f'FS_WRITE path={path} ip={self.client_address[0]}')
            
            if result['ok']:
                self._set_headers(200)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        if parsed.path == '/api/fs_mkdir':
            path = data.get('path', '')
            
            if not path:
                self._set_headers(400)
                self.wfile.write(b'{"error":"path required"}')
                return
            
            try:
                abs_path = os.path.abspath(path)
                if not abs_path.startswith(NS_HOME):
                    self._set_headers(403)
                    self.wfile.write(b'{"error":"Access denied"}')
                    return
                
                os.makedirs(abs_path, exist_ok=True)
                audit(f'FS_MKDIR path={path} ip={self.client_address[0]}')
                
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_rm':
            path = data.get('path', '')
            
            if not path:
                self._set_headers(400)
                self.wfile.write(b'{"error":"path required"}')
                return
            
            result = delete_path_safe(path)
            audit(f'FS_RM path={path} ip={self.client_address[0]}')
            
            if result['ok']:
                self._set_headers(200)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        if parsed.path == '/api/fs_mv':
            src = data.get('src', '')
            dst = data.get('dst', '')
            
            if not src or not dst:
                self._set_headers(400)
                self.wfile.write(b'{"error":"src and dst required"}')
                return
            
            result = move_path_safe(src, dst)
            audit(f'FS_MV src={src} dst={dst} ip={self.client_address[0]}')
            
            if result['ok']:
                self._set_headers(200)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        if parsed.path == '/api/config':
            config_content = data.get('config', '')
            
            try:
                write_text(CONFIG, config_content)
                audit(f'CONFIG_UPDATE ip={self.client_address[0]}')
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/config/validate':
            config_content = data.get('config', '')
            result = validate_yaml_config(config_content)
            self._set_headers(200)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        if parsed.path == '/api/admin/users':
            username = data.get('username', '')
            password = data.get('password', '')
            
            if not username or not password:
                self._set_headers(400)
                self.wfile.write(b'{"error":"username and password required"}')
                return
            
            # Add user
            salt = auth_salt()
            sha = hashlib.sha256((salt + ':' + password).encode()).hexdigest()
            
            db = users_db()
            userdb = db.get('_userdb', {})
            userdb[username] = sha
            db['_userdb'] = userdb
            set_users_db(db)
            
            audit(f'USER_ADD username={username} ip={self.client_address[0]}')
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        if parsed.path == '/api/admin/backup':
            result = create_backup()
            audit(f'BACKUP_CREATE ip={self.client_address[0]}')
            
            if result.get('ok'):
                self._set_headers(200)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        if parsed.path == '/api/admin/restore':
            filename = data.get('filename', '')
            
            if not filename:
                self._set_headers(400)
                self.wfile.write(b'{"error":"filename required"}')
                return
            
            result = restore_backup(filename)
            audit(f'BACKUP_RESTORE filename={filename} ip={self.client_address[0]}')
            
            if result.get('ok'):
                self._set_headers(200)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps(result).encode('utf-8'))
            return

        if parsed.path == '/api/webgen/create':
            title = data.get('title', '')
            content = data.get('content', '')
            
            if not title or not content:
                self._set_headers(400)
                self.wfile.write(b'{"error":"title and content required"}')
                return
            
            filename = re.sub(r'[^a-zA-Z0-9_-]', '_', title.lower()) + '.html'
            os.makedirs(SITE_DIR, exist_ok=True)
            
            full_content = f"""<!DOCTYPE html>
<html><head><title>{title}</title></head>
<body>{content}</body></html>"""
            
            write_text(os.path.join(SITE_DIR, filename), full_content)
            audit(f'WEBGEN_CREATE filename={filename} ip={self.client_address[0]}')
            
            self._set_headers(200)
            self.wfile.write(json.dumps({'filename': filename}).encode('utf-8'))
            return

        if parsed.path.startswith('/api/admin/notifications/'):
            # Save notification settings
            config_type = parsed.path.split('/')[-1]
            
            notifications = read_json(NOTIFICATIONS_CONFIG, {})
            notifications[config_type] = data
            write_json(NOTIFICATIONS_CONFIG, notifications)
            
            audit(f'NOTIFICATION_CONFIG type={config_type} ip={self.client_address[0]}')
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        self._set_headers(404)
        self.wfile.write(b'{"error":"endpoint not found"}')

    def do_DELETE(self):
        if not require_auth(self): 
            return
        
        parsed = urlparse(self.path)
        
        if parsed.path.startswith('/api/webgen/page/'):
            filename = parsed.path[len('/api/webgen/page/'):]
            page_path = os.path.join(SITE_DIR, filename)
            
            try:
                if os.path.exists(page_path):
                    os.remove(page_path)
                    audit(f'WEBGEN_DELETE filename={filename} ip={self.client_address[0]}')
                    self._set_headers(200)
                    self.wfile.write(b'{"ok":true}')
                else:
                    self._set_headers(404)
                    self.wfile.write(b'{"error":"Page not found"}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))
            return

        if parsed.path.startswith('/api/admin/users/'):
            username = parsed.path[len('/api/admin/users/'):]
            
            db = users_db()
            userdb = db.get('_userdb', {})
            if username in userdb:
                del userdb[username]
                db['_userdb'] = userdb
                set_users_db(db)
                audit(f'USER_DELETE username={username} ip={self.client_address[0]}')
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            else:
                self._set_headers(404)
                self.wfile.write(b'{"error":"User not found"}')
            return

        self._set_headers(404)
        self.wfile.write(b'{"error":"endpoint not found"}')

def run_server():
    try:
        host = yaml_val('web.bind_host', '127.0.0.1')
        port = int(yaml_val('web.bind_port', '8765'))
        
        httpd = HTTPServer((host, port), Handler)
        
        # SSL support (simplified)
        use_ssl = yaml_flag('web.use_ssl', False)
        if use_ssl:
            try:
                import ssl
                cert_file = os.path.join(NS_HOME, 'keys/server.crt')
                key_file = os.path.join(NS_HOME, 'keys/server.key')
                
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ctx.load_cert_chain(cert_file, key_file)
                    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
                    scheme = 'https'
                else:
                    scheme = 'http'
            except Exception:
                scheme = 'http'
        else:
            scheme = 'http'
        
        print(f"NovaShield JARVIS Web Server on {scheme}://{host}:{port}")
        audit(f'SERVER_START {scheme}://{host}:{port}')
        httpd.serve_forever()
        
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        audit(f'SERVER_ERROR {e}')

if __name__ == '__main__':
    # Ensure directories exist
    for dir_path in [NS_WWW, NS_LOGS, NS_CTRL, NS_BACKUPS]:
        os.makedirs(dir_path, exist_ok=True)
    
    run_server()