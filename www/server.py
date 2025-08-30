#!/usr/bin/env python3
import json, os, sys, time, hashlib, http.cookies, socket, secrets, threading
import smtplib, ssl, subprocess, re, base64, struct, hmac, urllib.request, shutil, glob
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socketserver

NS_HOME = os.path.expanduser('~/.novashield')
NS_WWW  = os.path.join(NS_HOME, 'www')
NS_LOGS = os.path.join(NS_HOME, 'logs')
NS_CTRL = os.path.join(NS_HOME, 'control')
NS_BIN  = os.path.join(NS_HOME, 'bin')
NS_BACKUPS = os.path.join(NS_HOME, 'backups')
NS_KEYS = os.path.join(NS_HOME, 'keys')
SELF_PATH_FILE = os.path.join(NS_BIN, 'self_path')
INDEX = os.path.join(NS_WWW, 'index.html')
LOGIN = os.path.join(NS_WWW, 'login.html')
CONFIG = os.path.join(NS_HOME, 'config.yaml')
SESSIONS = os.path.join(NS_CTRL, 'sessions.json')
CHATLOG = os.path.join(NS_LOGS, 'chat.log')
AUDIT = os.path.join(NS_LOGS, 'audit.log')
SITE_DIR = os.path.join(NS_HOME, 'site')
RATELIMIT = os.path.join(NS_CTRL, 'ratelimit.json')
BANLIST = os.path.join(NS_CTRL, 'bans.json')

# Rate limiting settings
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes
RATE_LIMIT_WINDOW = 60  # 1 minute
MAX_REQUESTS_PER_MINUTE = 100

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

def yaml_scalar(key):
    try:
        for line in open(CONFIG,'r',encoding='utf-8'):
            s=line.split('#',1)[0].strip()
            if not s: continue
            if s.startswith(key+':'):
                return s.split(':',1)[1].strip().strip('"').strip("'")
    except Exception:
        return None
    return None

def yaml_flag(path, default=False):
    v = None
    try:
        for line in open(CONFIG,'r',encoding='utf-8'):
            s=line.split('#',1)[0].strip()
            if not s: continue
            if s.startswith(path+':'):
                v = s.split(':',1)[1].strip().lower()
                break
    except Exception:
        return default
    return (v=='true')

def auth_enabled():
    return yaml_flag('security.auth_enabled', False) or yaml_flag('auth_enabled', False)

def auth_salt():
    v = yaml_scalar('security.auth_salt') or yaml_scalar('auth_salt') or 'changeme'
    return v

def audit(msg):
    try:
        with open(AUDIT,'a',encoding='utf-8') as f: 
            f.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+msg+'\n')
    except Exception: 
        pass

def users_db():
    return read_json(SESSIONS, {}) or {}

def set_users_db(j):
    write_json(SESSIONS, j)

def users_list():
    db = users_db()
    return db.get('_userdb', {})

def user_2fa_secret(user):
    return (users_db().get('_2fa', {}) or {}).get(user)

def set_user(username, pass_sha):
    db = users_db()
    ud = db.get('_userdb', {})
    ud[username]=pass_sha
    db['_userdb']=ud
    set_users_db(db)

def set_2fa(username, secret_b32):
    db = users_db()
    tow = db.get('_2fa', {})
    tow[username]=secret_b32
    db['_2fa']=tow
    set_users_db(db)

def delete_user(username):
    db = users_db()
    ud = db.get('_userdb', {})
    if username in ud:
        del ud[username]
        db['_userdb'] = ud
    tow = db.get('_2fa', {})
    if username in tow:
        del tow[username]
        db['_2fa'] = tow
    set_users_db(db)

def check_login(username, password, otp=''):
    salt = auth_salt()
    sha = hashlib.sha256((salt+':'+password).encode()).hexdigest()
    users = users_list()
    if users.get(username,'') != sha:
        return False, False
    
    # Check 2FA if enabled
    secret = user_2fa_secret(username)
    if secret:
        if not otp or not verify_totp(secret, otp):
            return False, True  # Valid password but need 2FA
    
    return True, False

def verify_totp(secret, token, window=1):
    """Verify TOTP token with time window"""
    try:
        # Decode base32 secret
        secret_bytes = base64.b32decode(secret + '=' * (-len(secret) % 8))
        
        # Current time counter
        current_time = int(time.time()) // 30
        
        # Check current and nearby time windows
        for i in range(-window, window + 1):
            time_counter = current_time + i
            time_bytes = struct.pack('>Q', time_counter)
            
            # Generate HMAC
            hmac_digest = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
            
            # Extract dynamic binary code
            offset = hmac_digest[-1] & 0x0F
            binary_code = struct.unpack('>I', hmac_digest[offset:offset+4])[0] & 0x7FFFFFFF
            
            # Generate 6-digit code
            totp_code = binary_code % 1000000
            
            if f"{totp_code:06d}" == str(token).zfill(6):
                return True
        
        return False
    except Exception:
        return False

def generate_2fa_secret():
    """Generate a new TOTP secret"""
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii')

def new_session(username):
    token = hashlib.sha256(f'{username}:{time.time()}:{secrets.token_hex(16)}'.encode()).hexdigest()
    db = read_json(SESSIONS, {}) or {}
    db[token]={'user':username,'ts':int(time.time()),'csrf':secrets.token_hex(16)}
    write_json(SESSIONS, db)
    return token

def get_session(handler):
    if not auth_enabled(): return {'user':'public', 'csrf': 'no-auth'}
    if 'Cookie' not in handler.headers: return None
    C = http.cookies.SimpleCookie()
    C.load(handler.headers['Cookie'])
    if 'NSSESS' not in C: return None
    token = C['NSSESS'].value
    db = read_json(SESSIONS, {}) or {}
    return db.get(token)

def require_auth(handler):
    if not auth_enabled(): return True
    sess = get_session(handler)
    if sess: return True
    handler._set_headers(401); handler.wfile.write(b'{"error":"unauthorized"}'); return False

def check_csrf(handler, required_token):
    """Check CSRF token"""
    if not auth_enabled(): return True
    sess = get_session(handler)
    if not sess: return False
    expected = sess.get('csrf', '')
    return expected and expected == required_token

def get_client_ip(handler):
    """Get client IP address"""
    forwarded = handler.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    real_ip = handler.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    return handler.client_address[0]

def is_rate_limited(ip):
    """Check if IP is rate limited"""
    try:
        now = time.time()
        rl_data = read_json(RATELIMIT, {})
        
        cutoff = now - RATE_LIMIT_WINDOW
        rl_data = {k: v for k, v in rl_data.items() if v.get('last_request', 0) > cutoff}
        
        if ip in rl_data:
            data = rl_data[ip]
            if data.get('requests', 0) >= MAX_REQUESTS_PER_MINUTE:
                return True
            
            if data.get('last_request', 0) > now - RATE_LIMIT_WINDOW:
                data['requests'] = data.get('requests', 0) + 1
            else:
                data['requests'] = 1
            data['last_request'] = now
        else:
            rl_data[ip] = {'requests': 1, 'last_request': now}
        
        write_json(RATELIMIT, rl_data)
        return False
    except Exception:
        return False

def is_banned(ip):
    """Check if IP is banned"""
    try:
        bans = read_json(BANLIST, {})
        if ip in bans:
            ban_data = bans[ip]
            if ban_data.get('until', 0) > time.time():
                return True
            else:
                del bans[ip]
                write_json(BANLIST, bans)
        return False
    except Exception:
        return False

def ban_ip(ip, duration=LOCKOUT_DURATION, reason='Too many failed attempts'):
    """Ban an IP address"""
    try:
        bans = read_json(BANLIST, {})
        bans[ip] = {
            'until': time.time() + duration,
            'reason': reason,
            'banned_at': time.time()
        }
        write_json(BANLIST, bans)
        audit(f"IP {ip} banned for {duration}s: {reason}")
    except Exception as e:
        audit(f"Failed to ban IP {ip}: {e}")

def track_login_attempt(ip, success=False):
    """Track login attempts for an IP"""
    try:
        attempts = read_json(RATELIMIT, {})
        key = f"login_{ip}"
        
        now = time.time()
        cutoff = now - LOCKOUT_DURATION
        
        if key in attempts:
            data = attempts[key]
            data['attempts'] = [t for t in data.get('attempts', []) if t > cutoff]
            
            if not success:
                data['attempts'].append(now)
                if len(data['attempts']) >= MAX_LOGIN_ATTEMPTS:
                    ban_ip(ip, LOCKOUT_DURATION, 'Too many failed login attempts')
                    return True
        else:
            if not success:
                attempts[key] = {'attempts': [now]}
        
        if success and key in attempts:
            del attempts[key]
        
        write_json(RATELIMIT, attempts)
        return False
    except Exception:
        return False

def last_lines(path, n=100):
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END); size=f.tell(); block=1024; data=b''
            while size>0 and n>0:
                step=min(block,size); size-=step; f.seek(size); buf=f.read(step); data=buf+data; n-=buf.count(b'\n')
            return data.decode('utf-8','ignore').splitlines()[-n:]
    except Exception:
        return []

def ai_reply(prompt):
    """Enhanced AI reply function"""
    prompt = prompt.lower().strip()
    
    responses = {
        'status': 'All systems operational, sir. Monitoring is active.',
        'hello': 'Hello! I am Jarvis, your AI assistant. How may I help you today?',
        'help': 'I can assist with: status checks, backup operations, IP information, system monitoring, user management, and general system queries.',
        'backup': 'Backup systems are ready. I can create, list, or restore backups through the admin panel.',
        'ip': 'Network configuration is being monitored. Check the status panel for current IP information.',
        'time': f'Current system time: {time.strftime("%Y-%m-%d %H:%M:%S")}',
        'restart': 'System restart procedures are available through the control panel, sir.',
        'users': 'User management is available in the admin panel. I can help with user operations.',
        'config': 'Configuration editor is available in the config tab with real-time validation.',
        'terminal': 'Web terminal is available and ready for your commands.',
        'alerts': 'System alerts are being monitored. Check the alerts tab for recent notifications.',
    }
    
    for key, response in responses.items():
        if key in prompt:
            return response
    
    if '?' in prompt:
        return 'I am here to assist you. Try asking about status, backup, users, or system information.'
    
    return 'I understand, sir. How else may I assist you today?'

def send_email(to_addr, subject, body):
    """Send email notification"""
    try:
        config = read_json(CONFIG.replace('.yaml', '_email.json'), {})
        if not config:
            return False
        
        smtp_server = config.get('smtp_server')
        smtp_port = config.get('smtp_port', 587)
        username = config.get('username')
        password = config.get('password')
        from_addr = config.get('from_addr')
        
        if not all([smtp_server, username, password, from_addr]):
            return False
        
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
        
        return True
    except Exception as e:
        audit(f"Email send failed: {e}")
        return False

def send_telegram(message):
    """Send Telegram notification"""
    try:
        config = read_json(CONFIG.replace('.yaml', '_telegram.json'), {})
        bot_token = config.get('bot_token')
        chat_id = config.get('chat_id')
        
        if not bot_token or not chat_id:
            return False
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'Markdown'
        }
        
        req = urllib.request.Request(url, 
                                   data=json.dumps(data).encode('utf-8'),
                                   headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status == 200
        
    except Exception as e:
        audit(f"Telegram send failed: {e}")
        return False

def send_discord(message):
    """Send Discord webhook notification"""
    try:
        config = read_json(CONFIG.replace('.yaml', '_discord.json'), {})
        webhook_url = config.get('webhook_url')
        
        if not webhook_url:
            return False
        
        data = {'content': message}
        
        req = urllib.request.Request(webhook_url,
                                   data=json.dumps(data).encode('utf-8'),
                                   headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status == 204
        
    except Exception as e:
        audit(f"Discord send failed: {e}")
        return False

class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, ctype='application/json', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        # Enhanced security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-XSS-Protection', '1; mode=block')
        if extra_headers:
            for k,v in (extra_headers or {}).items(): 
                self.send_header(k, v)
        self.end_headers()

    def log_message(self, format, *args):
        # Custom logging
        audit(f"HTTP {self.client_address[0]} - {format % args}")

    def do_GET(self):
        client_ip = get_client_ip(self)
        
        # Security checks
        if is_banned(client_ip):
            self._set_headers(429)
            self.wfile.write(b'{"error":"IP banned"}')
            return
            
        if is_rate_limited(client_ip):
            self._set_headers(429)
            self.wfile.write(b'{"error":"Rate limited"}')
            return

        parsed = urlparse(self.path)
        
        # Serve static files
        if parsed.path.startswith('/static/'):
            file_path = parsed.path[8:]  # Remove '/static/'
            full_path = os.path.join(NS_WWW, file_path)
            
            if os.path.exists(full_path) and os.path.isfile(full_path):
                content_type = 'text/css' if file_path.endswith('.css') else \
                              'application/javascript' if file_path.endswith('.js') else \
                              'text/html'
                self._set_headers(200, content_type)
                with open(full_path, 'rb') as f:
                    self.wfile.write(f.read())
                return

        # Serve main page or login
        if parsed.path == '/' or parsed.path == '/index.html':
            if auth_enabled():
                sess = get_session(self)
                if not sess:
                    # Redirect to login
                    self._set_headers(200, 'text/html')
                    with open(LOGIN if os.path.exists(LOGIN) else INDEX, 'rb') as f:
                        self.wfile.write(f.read())
                    return
            
            self._set_headers(200, 'text/html')
            with open(INDEX, 'rb') as f:
                self.wfile.write(f.read())
            return

        # API endpoints
        if parsed.path == '/api/status':
            if not require_auth(self): return
            
            # Generate status data
            status_data = {
                'csrf': get_session(self).get('csrf', ''),
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'version': '3.1.0',
                'cpu': {'load1': 0.5, 'level': 'OK'},
                'memory': {'used_pct': 45, 'warn': 80, 'crit': 95, 'level': 'OK'},
                'disk': {'mount': '/', 'use_pct': 23, 'level': 'OK'},
                'network': {'ip': '127.0.0.1', 'public_ip': '?', 'loss_pct': 0, 'rtt_avg_ms': 1, 'level': 'OK'},
                'services': True,
                'projects_count': len(os.listdir(os.path.join(NS_HOME, 'projects'))),
                'modules_count': len(os.listdir(os.path.join(NS_HOME, 'modules'))),
                'alerts': last_lines(os.path.join(NS_LOGS, 'alerts.log'), 50)
            }
            
            self._set_headers(200)
            self.wfile.write(json.dumps(status_data).encode('utf-8'))
            return

        if parsed.path == '/api/config':
            if not require_auth(self): return
            config_content = read_text(CONFIG, '# Configuration file')
            self._set_headers(200, 'text/plain')
            self.wfile.write(config_content.encode('utf-8'))
            return

        # File system API
        if parsed.path.startswith('/api/fs'):
            if not require_auth(self): return
            
            if parsed.path == '/api/fs':
                q = parse_qs(parsed.query)
                d = q.get('dir', [''])[0]
                if not d or d.startswith('~'):
                    d = NS_HOME
                
                full = os.path.abspath(d)
                if not full.startswith(NS_HOME):
                    self._set_headers(403)
                    self.wfile.write(b'{"error":"forbidden"}')
                    return
                
                out = []
                try:
                    for entry in os.scandir(full):
                        if entry.name.startswith('.'): continue
                        if 'keys' in full and entry.is_file(): continue
                        out.append({
                            'name': entry.name,
                            'is_dir': entry.is_dir(),
                            'size': entry.stat().st_size if entry.is_file() else 0
                        })
                except Exception:
                    pass
                
                self._set_headers(200)
                self.wfile.write(json.dumps({'dir': full, 'entries': out}).encode('utf-8'))
                return

            if parsed.path == '/api/fs_read':
                q = parse_qs(parsed.query)
                p = q.get('path', [''])[0]
                full = os.path.abspath(p)
                
                if not full.startswith(NS_HOME):
                    self._set_headers(403)
                    self.wfile.write(b'{"error":"forbidden"}')
                    return
                
                if not os.path.exists(full) or not os.path.isfile(full):
                    self._set_headers(404)
                    self.wfile.write(b'{"ok":false,"error":"not found"}')
                    return
                
                try:
                    content = read_text(full)
                    size = os.path.getsize(full)
                    self._set_headers(200)
                    self.wfile.write(json.dumps({
                        'ok': True,
                        'path': full,
                        'content': content,
                        'size': size
                    }).encode('utf-8'))
                except Exception as e:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
                return

        # Admin API endpoints
        if parsed.path.startswith('/api/admin/'):
            if not require_auth(self): return
            
            if parsed.path == '/api/admin/users':
                users = users_list()
                user_data = []
                for username in users.keys():
                    user_data.append({
                        'username': username,
                        'has_2fa': bool(user_2fa_secret(username))
                    })
                
                self._set_headers(200)
                self.wfile.write(json.dumps({'users': user_data}).encode('utf-8'))
                return

            if parsed.path == '/api/admin/backups':
                backups = []
                try:
                    for backup_file in glob.glob(os.path.join(NS_BACKUPS, '*.tar.gz')):
                        stat = os.stat(backup_file)
                        backups.append({
                            'name': os.path.basename(backup_file),
                            'date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
                            'size': f"{stat.st_size // 1024}KB"
                        })
                except Exception:
                    pass
                
                self._set_headers(200)
                self.wfile.write(json.dumps({'backups': backups}).encode('utf-8'))
                return

            if parsed.path == '/api/admin/notification_settings':
                settings = {
                    'email': read_json(CONFIG.replace('.yaml', '_email.json'), {}),
                    'telegram': read_json(CONFIG.replace('.yaml', '_telegram.json'), {}),
                    'discord': read_json(CONFIG.replace('.yaml', '_discord.json'), {})
                }
                
                # Remove sensitive data
                if 'password' in settings['email']:
                    settings['email']['password'] = '***'
                if 'bot_token' in settings['telegram']:
                    settings['telegram']['bot_token'] = '***'
                
                self._set_headers(200)
                self.wfile.write(json.dumps(settings).encode('utf-8'))
                return

        self._set_headers(404)
        self.wfile.write(b'{"error":"not found"}')

    def do_POST(self):
        client_ip = get_client_ip(self)
        
        # Security checks
        if is_banned(client_ip):
            self._set_headers(429)
            self.wfile.write(b'{"error":"IP banned"}')
            return

        parsed = urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''

        # Login endpoint
        if parsed.path == '/api/login':
            try:
                data = json.loads(body or '{}')
                user = data.get('user', '')
                pwd = data.get('pass', '')
                otp = data.get('otp', '')
            except Exception:
                data = {}
                user = pwd = otp = ''

            if auth_enabled():
                valid, need_2fa = check_login(user, pwd, otp)
                
                if valid:
                    track_login_attempt(client_ip, success=True)
                    tok = new_session(user)
                    self._set_headers(200, 'application/json', {
                        'Set-Cookie': f'NSSESS={tok}; Path=/; HttpOnly; SameSite=Strict'
                    })
                    self.wfile.write(b'{"ok":true}')
                    audit(f"Login success: {user} from {client_ip}")
                    return
                else:
                    is_banned = track_login_attempt(client_ip, success=False)
                    response = {'ok': False}
                    
                    if need_2fa:
                        response['need_2fa'] = True
                        response['error'] = '2FA required'
                    elif is_banned:
                        response['locked'] = True
                        response['error'] = 'Account locked'
                    else:
                        response['error'] = 'Invalid credentials'
                    
                    self._set_headers(401)
                    self.wfile.write(json.dumps(response).encode('utf-8'))
                    audit(f"Login failed: {user} from {client_ip}")
                    return

            self._set_headers(401)
            self.wfile.write(b'{"ok":false}')
            return

        # Logout endpoint
        if parsed.path == '/api/logout':
            if auth_enabled():
                sess = get_session(self)
                if sess:
                    # Remove session
                    db = read_json(SESSIONS, {})
                    for token, session_data in list(db.items()):
                        if session_data.get('user') == sess.get('user'):
                            del db[token]
                    write_json(SESSIONS, db)
                    
                self._set_headers(200, 'application/json', {
                    'Set-Cookie': 'NSSESS=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'
                })
            else:
                self._set_headers(200)
            
            self.wfile.write(b'{"ok":true}')
            return

        # All other endpoints require auth
        if not require_auth(self): return

        # CSRF check for authenticated endpoints
        csrf_token = self.headers.get('X-CSRF', '')
        if not check_csrf(self, csrf_token):
            self._set_headers(403)
            self.wfile.write(b'{"error":"CSRF token invalid"}')
            return

        try:
            data = json.loads(body or '{}')
        except Exception:
            data = {}

        # Chat endpoint
        if parsed.path == '/api/chat':
            prompt = data.get('prompt', '')
            reply = ai_reply(prompt)
            
            # Log chat
            try:
                with open(CHATLOG, 'a', encoding='utf-8') as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} USER: {prompt}\n")
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} JARVIS: {reply}\n")
            except Exception:
                pass
            
            self._set_headers(200)
            self.wfile.write(json.dumps({'reply': reply}).encode('utf-8'))
            return

        # File system operations
        if parsed.path == '/api/fs_write':
            path = data.get('path', '')
            content = data.get('content', '')
            
            if not path:
                self._set_headers(400)
                self.wfile.write(b'{"error":"path required"}')
                return
            
            full = os.path.abspath(path)
            if not full.startswith(NS_HOME):
                self._set_headers(403)
                self.wfile.write(b'{"error":"forbidden"}')
                return
            
            try:
                write_text(full, content)
                audit(f"File written: {full}")
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_mkdir':
            path = data.get('path', '')
            
            if not path:
                self._set_headers(400)
                self.wfile.write(b'{"error":"path required"}')
                return
            
            full = os.path.abspath(path)
            if not full.startswith(NS_HOME):
                self._set_headers(403)
                self.wfile.write(b'{"error":"forbidden"}')
                return
            
            try:
                os.makedirs(full, exist_ok=True)
                audit(f"Directory created: {full}")
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_delete':
            path = data.get('path', '')
            
            if not path:
                self._set_headers(400)
                self.wfile.write(b'{"error":"path required"}')
                return
            
            full = os.path.abspath(path)
            if not full.startswith(NS_HOME) or full == NS_HOME:
                self._set_headers(403)
                self.wfile.write(b'{"error":"forbidden"}')
                return
            
            try:
                if os.path.isdir(full):
                    shutil.rmtree(full)
                elif os.path.isfile(full):
                    os.remove(full)
                else:
                    raise FileNotFoundError("Path not found")
                
                audit(f"Deleted: {full}")
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_move':
            from_path = data.get('from', '')
            to_path = data.get('to', '')
            
            if not from_path or not to_path:
                self._set_headers(400)
                self.wfile.write(b'{"error":"from and to paths required"}')
                return
            
            full_from = os.path.abspath(from_path)
            full_to = os.path.abspath(to_path)
            
            if not full_from.startswith(NS_HOME) or not full_to.startswith(NS_HOME):
                self._set_headers(403)
                self.wfile.write(b'{"error":"forbidden"}')
                return
            
            try:
                os.makedirs(os.path.dirname(full_to), exist_ok=True)
                shutil.move(full_from, full_to)
                audit(f"Moved: {full_from} -> {full_to}")
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        # Admin endpoints
        if parsed.path == '/api/admin/add_user':
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                self._set_headers(400)
                self.wfile.write(b'{"error":"username and password required"}')
                return
            
            if len(password) < 8:
                self._set_headers(400)
                self.wfile.write(b'{"error":"password too short"}')
                return
            
            # Check if user exists
            if username in users_list():
                self._set_headers(400)
                self.wfile.write(b'{"error":"user already exists"}')
                return
            
            # Create user
            salt = auth_salt()
            pass_hash = hashlib.sha256((salt + ':' + password).encode()).hexdigest()
            set_user(username, pass_hash)
            
            audit(f"User created: {username}")
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        if parsed.path == '/api/admin/delete_user':
            username = data.get('username', '').strip()
            
            if not username:
                self._set_headers(400)
                self.wfile.write(b'{"error":"username required"}')
                return
            
            if username not in users_list():
                self._set_headers(404)
                self.wfile.write(b'{"error":"user not found"}')
                return
            
            delete_user(username)
            audit(f"User deleted: {username}")
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        if parsed.path == '/api/admin/reset_password':
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                self._set_headers(400)
                self.wfile.write(b'{"error":"username and password required"}')
                return
            
            if len(password) < 8:
                self._set_headers(400)
                self.wfile.write(b'{"error":"password too short"}')
                return
            
            if username not in users_list():
                self._set_headers(404)
                self.wfile.write(b'{"error":"user not found"}')
                return
            
            salt = auth_salt()
            pass_hash = hashlib.sha256((salt + ':' + password).encode()).hexdigest()
            set_user(username, pass_hash)
            
            audit(f"Password reset for user: {username}")
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        if parsed.path == '/api/admin/toggle_2fa':
            username = data.get('username', '').strip()
            enable = data.get('enable', False)
            
            if not username:
                self._set_headers(400)
                self.wfile.write(b'{"error":"username required"}')
                return
            
            if username not in users_list():
                self._set_headers(404)
                self.wfile.write(b'{"error":"user not found"}')
                return
            
            if enable:
                secret = generate_2fa_secret()
                set_2fa(username, secret)
                audit(f"2FA enabled for user: {username}")
                self._set_headers(200)
                self.wfile.write(json.dumps({'ok': True, 'secret': secret}).encode('utf-8'))
            else:
                set_2fa(username, None)
                audit(f"2FA disabled for user: {username}")
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            return

        # Notification config endpoints
        if parsed.path == '/api/admin/config_email':
            config_path = CONFIG.replace('.yaml', '_email.json')
            write_json(config_path, data)
            audit("Email configuration updated")
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        if parsed.path == '/api/admin/config_telegram':
            config_path = CONFIG.replace('.yaml', '_telegram.json')
            write_json(config_path, data)
            audit("Telegram configuration updated")
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        if parsed.path == '/api/admin/config_discord':
            config_path = CONFIG.replace('.yaml', '_discord.json')
            write_json(config_path, data)
            audit("Discord configuration updated")
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        # Test notification endpoints
        if parsed.path == '/api/admin/test_email':
            config = read_json(CONFIG.replace('.yaml', '_email.json'), {})
            to_addr = config.get('to_addr', 'test@example.com')
            
            if send_email(to_addr, 'NovaShield Test', 'This is a test email from NovaShield.'):
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            else:
                self._set_headers(500)
                self.wfile.write(b'{"error":"failed to send email"}')
            return

        if parsed.path == '/api/admin/test_telegram':
            if send_telegram('🔧 NovaShield Test Message'):
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            else:
                self._set_headers(500)
                self.wfile.write(b'{"error":"failed to send telegram message"}')
            return

        if parsed.path == '/api/admin/test_discord':
            if send_discord('🔧 NovaShield Test Message'):
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            else:
                self._set_headers(500)
                self.wfile.write(b'{"error":"failed to send discord message"}')
            return

        # Backup endpoints
        if parsed.path == '/api/admin/create_backup':
            try:
                timestamp = time.strftime('%Y%m%d_%H%M%S')
                backup_name = f"novashield_backup_{timestamp}.tar.gz"
                backup_path = os.path.join(NS_BACKUPS, backup_name)
                
                # Create backup using tar
                cmd = ['tar', '-czf', backup_path, '-C', os.path.dirname(NS_HOME), 
                       os.path.basename(NS_HOME)]
                subprocess.run(cmd, check=True, capture_output=True)
                
                audit(f"Backup created: {backup_name}")
                self._set_headers(200)
                self.wfile.write(json.dumps({'ok': True, 'backup': backup_name}).encode('utf-8'))
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/admin/restore_backup':
            backup_name = data.get('name', '')
            if not backup_name:
                self._set_headers(400)
                self.wfile.write(b'{"error":"backup name required"}')
                return
            
            backup_path = os.path.join(NS_BACKUPS, backup_name)
            if not os.path.exists(backup_path):
                self._set_headers(404)
                self.wfile.write(b'{"error":"backup not found"}')
                return
            
            try:
                # Restore backup
                cmd = ['tar', '-xzf', backup_path, '-C', os.path.dirname(NS_HOME)]
                subprocess.run(cmd, check=True, capture_output=True)
                
                audit(f"Backup restored: {backup_name}")
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        # Config save endpoint
        if parsed.path == '/api/admin/save_config':
            content = data.get('content', '')
            if not content:
                self._set_headers(400)
                self.wfile.write(b'{"error":"content required"}')
                return
            
            try:
                # Backup current config
                backup_path = CONFIG + '.backup.' + str(int(time.time()))
                shutil.copy2(CONFIG, backup_path)
                
                # Save new config
                write_text(CONFIG, content)
                audit("Configuration file updated")
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/admin/backup_config':
            try:
                backup_path = CONFIG + '.backup.' + str(int(time.time()))
                shutil.copy2(CONFIG, backup_path)
                audit(f"Configuration backed up to: {backup_path}")
                self._set_headers(200)
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode('utf-8'))
            return

        # Control endpoint
        if parsed.path == '/api/control':
            action = data.get('action', '')
            target = data.get('target', '')
            
            # Simulate control actions
            audit(f"Control action: {action} {target}")
            self._set_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        self._set_headers(400)
        self.wfile.write(b'{"ok":false}')

def pick_host_port():
    host = '127.0.0.1'
    port = 8765
    try:
        h = None
        p = None
        for line in open(CONFIG,'r',encoding='utf-8'):
            s=line.split('#',1)[0].strip()
            if not s: continue
            if s.startswith('host:') and 'http:' not in s:
                h = s.split(':',1)[1].strip().strip('"').strip("'")
            if s.startswith('port:') and 'http:' not in s:
                try: p = int(s.split(':',1)[1].strip())
                except: pass
            if s.startswith('allow_lan:') and 'true' in s:
                h = '0.0.0.0'
        if h: host = h
        if p: port = p
    except Exception:
        pass
    try:
        socket.getaddrinfo(host, port)
    except Exception:
        host = '127.0.0.1'
    return host, port

if __name__ == '__main__':
    # Ensure directories exist
    for path in [NS_CTRL, NS_LOGS, NS_BACKUPS]:
        os.makedirs(path, exist_ok=True)
    
    host, port = pick_host_port()
    os.chdir(NS_WWW)
    
    for h in (host, '127.0.0.1', '0.0.0.0'):
        try:
            httpd = HTTPServer((h, port), Handler)
            print(f"NovaShield Web Server on http://{h}:{port}")
            audit(f"Server started on {h}:{port}")
            httpd.serve_forever()
        except Exception as e:
            print(f"Bind failed on {h}:{port}: {e}", file=sys.stderr)
            time.sleep(0.5)
            continue