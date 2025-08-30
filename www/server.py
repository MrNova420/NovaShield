#!/usr/bin/env python3
import json, os, sys, time, hashlib, http.cookies, socket, base64, threading, select, pty, tty, fcntl, struct, hmac
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

NS_HOME = os.path.expanduser('~/.novashield')
NS_WWW  = os.path.join(NS_HOME, 'www')
NS_LOGS = os.path.join(NS_HOME, 'logs')
NS_CTRL = os.path.join(NS_HOME, 'control')
NS_BIN  = os.path.join(NS_HOME, 'bin')
SELF_PATH_FILE = os.path.join(NS_BIN, 'self_path')
INDEX = os.path.join(NS_WWW, 'index.html')
CONFIG = os.path.join(NS_HOME, 'config.yaml')
SESSIONS = os.path.join(NS_CTRL, 'sessions.json')
CHATLOG = os.path.join(NS_LOGS, 'chat.log')
AUDIT = os.path.join(NS_LOGS, 'audit.log')
SITE_DIR = os.path.join(NS_HOME, 'site')
RL_DB = os.path.join(NS_CTRL,'ratelimit.json')
BANS_DB = os.path.join(NS_CTRL,'bans.json')

# Use current www directory for running from repo
CURRENT_WWW = os.path.dirname(os.path.abspath(__file__))

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'  # WebSocket

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
    with open(path,'w',encoding='utf-8') as f: f.write(json.dumps(obj))

def yaml_val(key, default=None):
    try:
        for line in open(CONFIG,'r',encoding='utf-8'):
            s=line.split('#',1)[0].strip()
            if not s: continue
            if s.startswith(key+':'):
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

def ip_lists():
    allow = []
    deny = []
    try:
        allow_block=False; deny_block=False
        for line in open(CONFIG,'r',encoding='utf-8'):
            s=line.split('#',1)[0].strip()
            if s.startswith('ip_allowlist:'): allow_block=True; deny_block=False; continue
            if s.startswith('ip_denylist:'): deny_block=True; allow_block=False; continue
            if allow_block:
                if s.startswith('- '): allow.append(s[2:].strip().strip('"'))
                elif s and not s.startswith('- '): allow_block=False
            if deny_block:
                if s.startswith('- '): deny.append(s[2:].strip().strip('"'))
                elif s and not s.startswith('- '): deny_block=False
    except Exception: pass
    return allow, deny

def audit(msg):
    try:
        Path(os.path.dirname(AUDIT)).mkdir(parents=True, exist_ok=True)
        with open(AUDIT,'a',encoding='utf-8') as f: f.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+msg+'\n')
    except Exception: pass

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

def check_login(username, password):
    salt = yaml_val('auth_salt','changeme')
    sha = hashlib.sha256((salt+':'+password).encode()).hexdigest()
    return users_list().get(username,'')==sha

def totp_now(secret_b32, t=None):
    if not secret_b32: return None
    try:
        key = base64.b32decode(secret_b32.upper())
    except Exception:
        return None
    if t is None: t = int(time.time())
    steps = int(t/30)
    msg = steps.to_bytes(8,'big')
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 0x0f
    code = (int.from_bytes(h[o:o+4],'big') & 0x7fffffff) % 1000000
    return f'{code:06d}'

def new_session(username):
    token = hashlib.sha256(f'{username}:{time.time()}:{os.urandom(8)}'.encode()).hexdigest()
    csrf  = hashlib.sha256(f'csrf:{token}:{os.urandom(8)}'.encode()).hexdigest()
    db = users_db()
    db[token]={'user':username,'ts':int(time.time()),'csrf':csrf}
    set_users_db(db)
    return token, csrf

def get_session(handler):
    if not auth_enabled(): return {'user':'public','csrf':'public'}
    if 'Cookie' not in handler.headers: return None
    C = http.cookies.SimpleCookie()
    C.load(handler.headers['Cookie'])
    if 'NSSESS' not in C: return None
    token = C['NSSESS'].value
    db = users_db()
    return db.get(token)

def require_auth(handler):
    client_ip = handler.client_address[0]
    allow, deny = ip_lists()
    if deny and (client_ip in deny or ('0.0.0.0/0' in deny)):
        handler._set_headers(403); handler.wfile.write(b'{"error":"forbidden"}'); return False
    if allow and client_ip not in allow:
        handler._set_headers(403); handler.wfile.write(b'{"error":"forbidden"}'); return False
    if not auth_enabled(): return True
    sess = get_session(handler)
    if not sess:
        handler._set_headers(401); handler.wfile.write(b'{"error":"unauthorized"}'); return False
    if csrf_required() and handler.command=='POST':
        client_csrf = handler.headers.get('X-CSRF','')
        if client_csrf != sess.get('csrf',''):
            handler._set_headers(403); handler.wfile.write(b'{"error":"csrf"}'); return False
    return True

def rate_limit_ok(handler, key='default'):
    ip = handler.client_address[0]
    now = int(time.time())
    rl = read_json(RL_DB,{}) or {}
    per = rate_limit_per_min()
    win = now // 60
    ent = rl.get(ip, {'win':win,'cnt':0,'lock':0})
    if ent.get('lock',0) and ent['lock']>now:
        return False
    if ent.get('win')!=win:
        ent={'win':win,'cnt':0,'lock':0}
    ent['cnt']=ent.get('cnt',0)+1
    if ent['cnt']>per:
        ent['lock']=now+min(900, int((ent['cnt']-per)*2))
    rl[ip]=ent
    write_json(RL_DB, rl)
    return ent['cnt']<=per

def login_fail(handler):
    ip=handler.client_address[0]
    rl = read_json(BANS_DB,{}) or {}
    now=int(time.time())
    ent = rl.get(ip, {'fails':0,'lock':0})
    ent['fails']=ent.get('fails',0)+1
    if ent['fails']>=lockout_threshold():
        ent['lock']=now+900
    rl[ip]=ent
    write_json(BANS_DB, rl)

def login_ok(handler):
    ip=handler.client_address[0]
    rl = read_json(BANS_DB,{}) or {}
    if ip in rl: rl.pop(ip,None); write_json(BANS_DB, rl)

def banned(handler):
    ip=handler.client_address[0]
    rl = read_json(BANS_DB,{}) or {}
    now=int(time.time())
    ent=rl.get(ip)
    return bool(ent and ent.get('lock',0)>now)

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
    prompt_low = (prompt or '').lower()
    now=time.strftime('%Y-%m-%d %H:%M:%S')
    status = {
        'cpu': read_json(os.path.join(NS_LOGS,'cpu.json'),{}),
        'mem': read_json(os.path.join(NS_LOGS,'memory.json'),{}),
        'disk': read_json(os.path.join(NS_LOGS,'disk.json'),{}),
        'net': read_json(os.path.join(NS_LOGS,'network.json'),{}),
    }
    if 'status' in prompt_low or 'health' in prompt_low:
        return f"[{now}] CPU {status['cpu'].get('load1','?')} | Mem {status['mem'].get('used_pct','?')}% | Disk {status['disk'].get('use_pct','?')}% | Loss {status['net'].get('loss_pct','?')}%."
    if 'backup' in prompt_low:
        return "Acknowledged. Use the backup controls in the admin panel."
    if 'version' in prompt_low or 'snapshot' in prompt_low:
        return "Version snapshot can be triggered from dashboard controls."
    if 'restart monitor' in prompt_low:
        return "Use the monitor toggle controls to restart monitors."
    if 'ip' in prompt_low:
        return f"Internal IP {status['net'].get('ip','?')} | Public {status['net'].get('public_ip','?')}."
    return f"I can help with status, backup, version snapshot, and restart monitors. You said: {prompt}"

# WebSocket support
def ws_key_response(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()

def ws_handshake(handler):
    if handler.headers.get('Upgrade','').lower() != 'websocket':
        return False
    key = handler.headers.get('Sec-WebSocket-Key')
    if not key: return False
    accept = ws_key_response(key)
    handler.send_response(101)
    handler.send_header('Upgrade', 'websocket')
    handler.send_header('Connection', 'Upgrade')
    handler.send_header('Sec-WebSocket-Accept', accept)
    handler.end_headers()
    return True

def ws_recv(sock):
    try:
        data = sock.recv(2)
        if len(data) < 2: return None, None
        fin = data[0] & 0x80
        opcode = data[0] & 0x0f
        masked = data[1] & 0x80
        length = data[1] & 0x7f
        
        if length == 126:
            length = struct.unpack('>H', sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack('>Q', sock.recv(8))[0]
        
        if masked:
            mask = sock.recv(4)
            payload = bytearray(sock.recv(length))
            for i in range(length):
                payload[i] ^= mask[i % 4]
        else:
            payload = sock.recv(length)
        
        return opcode, payload
    except Exception:
        return None, None

def ws_send(sock, data, opcode=2):
    if isinstance(data, str): data = data.encode()
    length = len(data)
    hdr = [0x80 | opcode]
    if length < 126:
        hdr.append(length)
    elif length < 65536:
        hdr.append(126); hdr += length.to_bytes(2,'big')
    else:
        hdr.append(127); hdr += length.to_bytes(8,'big')
    sock.send(bytes(hdr)+data)

def spawn_pty(shell=None, cols=120, rows=32):
    try:
        pid, fd = pty.fork()
        if pid==0:
            try:
                if shell is None or not shell:
                    shell = os.environ.get('SHELL','')
                if not shell:
                    for cand in ('/bin/bash','/bin/sh'):
                        if os.path.exists(cand): shell=cand; break
                if shell:
                    os.execv(shell, [shell, '-l'])
                else:
                    os._exit(1)
            except Exception as e:
                os.write(1, f'Failed to start shell: {e}\n'.encode())
                os._exit(1)
        winsz = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, tty.TIOCSWINSZ, winsz)
        return pid, fd
    except Exception:
        return None, None

def mirror_terminal(handler):
    if not require_auth(handler): return
    if not ws_handshake(handler): return
    sess = get_session(handler)
    user = sess.get('user','?') if sess else '?'
    client = handler.connection
    
    # Spawn shell
    shell_info = spawn_pty()
    if not shell_info[0]:
        ws_send(client, 'Failed to start terminal\r\n'); return
    
    pid, fd = shell_info
    audit(f'TERM START user={user} pid={pid} ip={handler.client_address[0]}')
    last_activity = time.time()

    def reader():
        try:
            while True:
                r,_,_ = select.select([fd],[],[], 1.0)
                if fd in r:
                    try:
                        data = os.read(fd, 4096)
                    except OSError:
                        break
                    if not data: break
                    try:
                        ws_send(client, data, opcode=2)
                    except Exception:
                        break
        finally:
            try: os.close(fd)
            except: pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    try:
        while True:
            if time.time()-last_activity>900:  # 15 min timeout
                ws_send(client, '\r\n[Session idle timeout]\r\n'); break
            opcode, data = ws_recv(client)
            if opcode is None: break
            last_activity = time.time()
            if opcode==8: break  # Close frame
            if opcode in (1,2):  # Text or binary
                try:
                    os.write(fd, data)
                except Exception:
                    break
    except Exception:
        pass
    finally:
        try:
            ws_send(client, '\r\n[Session ended]\r\n')
        except Exception: pass
        try: os.kill(pid, 15)
        except Exception: pass
        audit(f'TERM END user={user} pid={pid} ip={handler.client_address[0]}')

class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, ctype='application/json', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'geolocation=(), microphone=()')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self';")
        if extra_headers:
            for k,v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()

    def log_message(self, fmt, *args):
        return  # Suppress default logging

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == '/ws/term':
            if not require_auth(self): return
            mirror_terminal(self); return

        if parsed.path == '/':
            self._set_headers(200, 'text/html; charset=utf-8')
            html = read_text(os.path.join(CURRENT_WWW, 'index.html'), '<h1>NovaShield JARVIS</h1>')
            self.wfile.write(html.encode('utf-8')); return

        if parsed.path.startswith('/static/'):
            p = os.path.join(CURRENT_WWW, parsed.path[len('/static/'):])
            if not os.path.abspath(p).startswith(CURRENT_WWW): self._set_headers(404); self.wfile.write(b'{}'); return
            if os.path.exists(p) and os.path.isfile(p):
                ctype='text/plain'
                if p.endswith('.js'): ctype='application/javascript'
                if p.endswith('.css'): ctype='text/css'
                if p.endswith('.html'): ctype='text/html; charset=utf-8'
                self._set_headers(200, ctype); self.wfile.write(read_text(p).encode('utf-8')); return
            self._set_headers(404); self.wfile.write(b'{}'); return

        if parsed.path == '/api/status':
            if not require_auth(self): return
            sess = get_session(self) or {}
            
            # Create mock data for development
            data = {
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'cpu': {'load1': '0.5', 'level': 'OK'},
                'memory': {'used_pct': '45', 'warn': '80', 'crit': '90', 'level': 'OK'},
                'disk': {'mount': '/', 'use_pct': '30', 'level': 'OK'},
                'network': {'ip': '127.0.0.1', 'public_ip': 'N/A', 'loss_pct': '0', 'rtt_avg_ms': '1', 'level': 'OK'},
                'integrity': {'level': 'OK'},
                'process': {'level': 'OK'},
                'user': {'level': 'OK'},
                'services': {'level': 'OK'},
                'logwatch': {'level': 'OK'},
                'alerts': ['System started', 'All monitors active'],
                'projects_count': 0,
                'modules_count': 0,
                'version': 'JARVIS-3.1.0',
                'csrf': sess.get('csrf','') if auth_enabled() else 'public'
            }
            self._set_headers(200); self.wfile.write(json.dumps(data).encode('utf-8')); return

        if parsed.path == '/api/config':
            if not require_auth(self): return
            config_content = read_text(CONFIG, '''# NovaShield Configuration
security:
  auth_enabled: true
  csrf_required: true
  require_2fa: false
  auth_salt: changeme
host: 127.0.0.1
port: 8765
''')
            self._set_headers(200, 'text/plain; charset=utf-8'); self.wfile.write(config_content.encode('utf-8')); return

        if parsed.path == '/api/fs':
            if not require_auth(self): return
            q = parse_qs(parsed.query); d = q.get('dir',[''])[0]
            if not d: d = CURRENT_WWW
            try:
                d = os.path.abspath(d)
                out=[]
                if os.path.exists(d) and os.path.isdir(d):
                    for entry in os.scandir(d):
                        if entry.name.startswith('.'): continue
                        out.append({'name':entry.name,'is_dir':entry.is_dir(),'size':(entry.stat().st_size if entry.is_file() else 0)})
                self._set_headers(200); self.wfile.write(json.dumps({'dir':d,'entries':out}).encode('utf-8')); return
            except Exception as e:
                self._set_headers(500); self.wfile.write(json.dumps({'error':str(e)}).encode('utf-8')); return

        if parsed.path == '/api/fs_read':
            if not require_auth(self): return
            q = parse_qs(parsed.query); p = (q.get('path',[''])[0])
            try:
                full = os.path.abspath(p)
                if not os.path.exists(full) or not os.path.isfile(full):
                    self._set_headers(404); self.wfile.write(b'{"error":"not found"}'); return
                size = os.path.getsize(full)
                content = open(full,'rb').read(500_000).decode('utf-8','ignore')
                self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'path':full,'size':size,'content':content}).encode('utf-8')); return
            except Exception as e:
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8')); return

        if parsed.path == '/api/site_pages':
            if not require_auth(self): return
            try:
                pages = []
                if os.path.exists(SITE_DIR):
                    pages = [f for f in os.listdir(SITE_DIR) if f.endswith('.html')]
                self._set_headers(200); self.wfile.write(json.dumps(pages).encode('utf-8')); return
            except Exception:
                self._set_headers(200); self.wfile.write(b'[]'); return

        if parsed.path == '/api/admin/users':
            if not require_auth(self): return
            users = []
            for username in users_list().keys():
                users.append({
                    'username': username,
                    'has_2fa': bool(user_2fa_secret(username))
                })
            self._set_headers(200); self.wfile.write(json.dumps(users).encode('utf-8')); return

        self._set_headers(404); self.wfile.write(b'{"error":"not found"}')

    def do_POST(self):
        parsed = urlparse(self.path)
        if not rate_limit_ok(self, parsed.path):
            self._set_headers(429); self.wfile.write(b'{"error":"rate"}'); return
        if banned(self):
            self._set_headers(429); self.wfile.write(b'{"error":"locked"}'); return
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''

        if parsed.path == '/api/login':
            try: data = json.loads(body or '{}'); user=data.get('user',''); pwd=data.get('pass',''); otp=data.get('otp','')
            except Exception: data={}; user=''; pwd=''; otp=''
            if not user or not pwd:
                self._set_headers(400); self.wfile.write(b'{"ok":false}'); return
            if check_login(user, pwd):
                sec = user_2fa_secret(user)
                if require_2fa() or sec:
                    now = totp_now(sec)
                    if not otp or otp != now:
                        login_fail(self)
                        self._set_headers(401); self.wfile.write(b'{"ok":false,"need_2fa":true}'); return
                token, csrf = new_session(user)
                login_ok(self)
                audit(f'LOGIN OK user={user} ip={self.client_address[0]}')
                self._set_headers(200, 'application/json', {'Set-Cookie': f'NSSESS={token}; Path=/; HttpOnly; SameSite=Strict'})
                self.wfile.write(json.dumps({'ok':True,'csrf':csrf}).encode('utf-8')); return
            login_fail(self); audit(f'LOGIN FAIL user={user} ip={self.client_address[0]}')
            self._set_headers(401); self.wfile.write(b'{"ok":false}'); return

        if not require_auth(self): return

        if parsed.path == '/api/chat':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            prompt = data.get('prompt','')
            reply = ai_reply(prompt)
            try: 
                Path(os.path.dirname(CHATLOG)).mkdir(parents=True, exist_ok=True)
                open(CHATLOG,'a',encoding='utf-8').write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} Q:{prompt} A:{reply}\n')
            except Exception: pass
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'reply':reply}).encode('utf-8')); return

        if parsed.path == '/api/control':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            action = data.get('action','')
            audit(f'CONTROL {action} ip={self.client_address[0]}')
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return

        if parsed.path == '/api/fs_write':
            if not require_auth(self): return
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path',''); content=data.get('content','')
            full=os.path.abspath(path)
            try: 
                Path(os.path.dirname(full)).mkdir(parents=True, exist_ok=True)
                open(full,'w',encoding='utf-8').write(content); 
                audit(f'FS WRITE {full} ip={self.client_address[0]}'); 
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e: 
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_mkdir':
            if not require_auth(self): return
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path','')
            full=os.path.abspath(path)
            try: 
                Path(full).mkdir(parents=True, exist_ok=True); 
                audit(f'FS MKDIR {full} ip={self.client_address[0]}'); 
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e: 
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_rm':
            if not require_auth(self): return
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path',''); full=os.path.abspath(path)
            try:
                if os.path.isdir(full): os.rmdir(full)
                elif os.path.isfile(full): os.remove(full)
                audit(f'FS RM {full} ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/webgen':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            title = data.get('title','Untitled'); content = data.get('content','')
            slug = ''.join([c.lower() if c.isalnum() else '-' for c in title]).strip('-') or f'page-{int(time.time())}'
            Path(SITE_DIR).mkdir(parents=True, exist_ok=True)
            page_path = os.path.join(SITE_DIR, f'{slug}.html')
            write_text(page_path, f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title></head><body><h1>{title}</h1><div>{content}</div></body></html>')
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'page':f'/site/{slug}.html'}).encode('utf-8')); return

        if parsed.path == '/api/config_save':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            content = data.get('content','')
            try:
                Path(os.path.dirname(CONFIG)).mkdir(parents=True, exist_ok=True)
                write_text(CONFIG, content)
                audit(f'CONFIG SAVE ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        # Admin endpoints
        if parsed.path == '/api/admin/add_user':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            username = data.get('username',''); password = data.get('password','')
            if username and password:
                salt = yaml_val('auth_salt','changeme')
                sha = hashlib.sha256((salt+':'+password).encode()).hexdigest()
                set_user(username, sha)
                audit(f'USER ADD {username} ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            else:
                self._set_headers(400); self.wfile.write(b'{"error":"username and password required"}')
            return

        if parsed.path == '/api/admin/delete_user':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            username = data.get('username','')
            if username:
                db = users_db()
                ud = db.get('_userdb', {})
                if username in ud:
                    del ud[username]
                    db['_userdb'] = ud
                    set_users_db(db)
                    audit(f'USER DELETE {username} ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            else:
                self._set_headers(400); self.wfile.write(b'{"error":"username required"}')
            return

        if parsed.path == '/api/admin/reset_password':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            username = data.get('username',''); password = data.get('password','')
            if username and password:
                salt = yaml_val('auth_salt','changeme')
                sha = hashlib.sha256((salt+':'+password).encode()).hexdigest()
                set_user(username, sha)
                audit(f'PASSWD RESET {username} ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            else:
                self._set_headers(400); self.wfile.write(b'{"error":"username and password required"}')
            return

        if parsed.path == '/api/admin/toggle_2fa':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            username = data.get('username',''); action = data.get('action','')
            if action == 'enable':
                secret = base64.b32encode(os.urandom(10)).decode().strip('=')
                set_2fa(username, secret)
                audit(f'2FA ENABLE {username} ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'secret':secret}).encode('utf-8'))
            elif action == 'disable':
                db = users_db()
                tfa = db.get('_2fa', {})
                if username in tfa:
                    del tfa[username]
                    db['_2fa'] = tfa
                    set_users_db(db)
                audit(f'2FA DISABLE {username} ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            else:
                self._set_headers(400); self.wfile.write(b'{"error":"invalid action"}')
            return

        if parsed.path == '/api/admin/backup_restore':
            self._set_headers(200); self.wfile.write(json.dumps({'backup_status':'Available via novashield.sh --backup'}).encode('utf-8')); return

        if parsed.path == '/api/admin/notifications':
            self._set_headers(200); self.wfile.write(json.dumps({'notification_setup':'Configure via config.yaml'}).encode('utf-8')); return

        self._set_headers(400); self.wfile.write(b'{"ok":false}')

def pick_host_port():
    host = '127.0.0.1'; port = 8765
    return host, port

if __name__ == '__main__':
    # Create minimal required directories and files for demo
    os.makedirs(NS_HOME, exist_ok=True)
    os.makedirs(NS_CTRL, exist_ok=True)
    os.makedirs(NS_LOGS, exist_ok=True)
    os.makedirs(SITE_DIR, exist_ok=True)
    
    # Create a default user if none exists
    if not os.path.exists(SESSIONS):
        print("Creating default admin user (admin/admin123)")
        salt = 'changeme'
        sha = hashlib.sha256((salt+':admin123').encode()).hexdigest()
        write_json(SESSIONS, {'_userdb': {'admin': sha}})
    
    host, port = pick_host_port()
    os.chdir(CURRENT_WWW)
    
    try:
        httpd = HTTPServer((host, port), Handler)
        print(f"NovaShield JARVIS Edition on http://{host}:{port}")
        print("Default login: admin / admin123")
        httpd.serve_forever()
    except Exception as e:
        print(f"Bind failed on {host}:{port}: {e}", file=sys.stderr)
        sys.exit(1)
