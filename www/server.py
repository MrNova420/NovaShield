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
    v=yaml_val('security.rate_limit_per_min'); 
    try: return int(v)
    except: return 60
def lockout_threshold():
    v=yaml_val('security.lockout_threshold')
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
    # RFC 6238 TOTP 30s window, 6 digits, SHA1
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
    # IP allow/deny
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
        ent['lock']=now+min(900, int((ent['cnt']-per)*2))  # exponential-ish backoff
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
        os.system(f'\"{read_text(SELF_PATH_FILE).strip()}\" --backup >/dev/null 2>&1 &')
        return "Acknowledged. Snapshot backup started."
    if 'version' in prompt_low or 'snapshot' in prompt_low:
        os.system(f'\"{read_text(SELF_PATH_FILE).strip()}\" --version-snapshot >/dev/null 2>&1 &')
        return "Version snapshot underway."
    if 'restart monitor' in prompt_low:
        os.system(f'\"{read_text(SELF_PATH_FILE).strip()}\" --restart-monitors >/dev/null 2>&1 &')
        return "Restarting monitors."
    if 'ip' in prompt_low:
        return f"Internal IP {status['net'].get('ip','?')} | Public {status['net'].get('public_ip','?')}."
    return f"I can do status, backup, version snapshot, and restart monitors. You said: {prompt}"

# ------------------------------- WebSocket PTY -------------------------------
def ws_handshake(handler):
    key = handler.headers.get('Sec-WebSocket-Key')
    if not key: return False
    accept = base64.b64encode(hashlib.sha1((key+GUID).encode()).digest()).decode()
    headers = {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Accept': accept,
        'Sec-WebSocket-Protocol': 'chat'
    }
    handler._set_headers(101, 'application/octet-stream', headers)
    return True

def ws_recv(sock):
    # minimal WS frame parser (text/binary)
    hdr = sock.recv(2)
    if not hdr: return None, None
    fin = hdr[0] & 0x80
    opcode = hdr[0] & 0x0f
    masked = hdr[1] & 0x80
    length = hdr[1] & 0x7f
    if length==126:
        ext = sock.recv(2); length = int.from_bytes(ext,'big')
    elif length==127:
        ext = sock.recv(8); length = int.from_bytes(ext,'big')
    mask = sock.recv(4) if masked else b'\x00\x00\x00\x00'
    data = b''
    while len(data)<length:
        chunk = sock.recv(length-len(data))
        if not chunk: break
        data += chunk
    if masked:
        data = bytes(b ^ mask[i%4] for i,b in enumerate(data))
    return opcode, data

def ws_send(sock, data, opcode=1):
    # opcode 1=text, 2=binary
    if isinstance(data,str): data = data.encode()
    length = len(data)
    hdr = bytearray()
    hdr.append(0x80 | (opcode & 0x0f))
    if length<126:
        hdr.append(length)
    elif length<65536:
        hdr.append(126); hdr += length.to_bytes(2,'big')
    else:
        hdr.append(127); hdr += length.to_bytes(8,'big')
    sock.send(bytes(hdr)+data)

def spawn_pty(shell=None, cols=120, rows=32):
    pid, fd = pty.fork()
    if pid==0:
        # child
        try:
            if shell is None or not shell:
                shell = os.environ.get('SHELL','')
            if not shell:
                # Termux default; fallback to sh
                for cand in ('/data/data/com.termux/files/usr/bin/bash','/bin/bash','/system/bin/sh','/bin/sh'):
                    if os.path.exists(cand): shell=cand; break
            os.execv(shell, [shell, '-l'])
        except Exception as e:
            os.write(1, f'Failed to start shell: {e}\n'.encode())
            os._exit(1)
    # set window size
    winsz = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, tty.TIOCSWINSZ, winsz)
    return pid, fd

def mirror_terminal(handler):
    if not require_auth(handler): return
    if not ws_handshake(handler): return
    sess = get_session(handler)
    user = sess.get('user','?') if sess else '?'
    client = handler.connection
    # terminal options
    cols = int(yaml_val('cols') or yaml_val('terminal.cols') or 120)
    rows = int(yaml_val('rows') or yaml_val('terminal.rows') or 32)
    shell = yaml_val('terminal.shell','') or None
    idle_timeout = int(yaml_val('terminal.idle_timeout_sec') or 900)
    allow_write = (yaml_val('terminal.allow_write','true')=='true')
    pid, fd = spawn_pty(shell, cols, rows)
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
            if time.time()-last_activity>idle_timeout:
                ws_send(client, '\r\n[Session idle timeout]\r\n'); break
            opcode, data = ws_recv(client)
            if opcode is None: break
            last_activity = time.time()
            if opcode==8: break  # close
            if opcode in (1,2):
                if not allow_write:
                    continue
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

# ------------------------------- HTTP Handler -------------------------------
class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, ctype='application/json', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        # Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'geolocation=(), microphone=()')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self';")
        if extra_headers:
            for k,v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()

    def log_message(self, fmt, *args):
        # quiet default noisy logs; audits handled separately
        return

    def do_GET(self):
        parsed = urlparse(self.path)

        # WebSocket terminal
        if parsed.path == '/ws/term':
            if not require_auth(self): return
            mirror_terminal(self)
            return

        if parsed.path == '/':
            self._set_headers(200, 'text/html; charset=utf-8')
            html = read_text(INDEX, '<h1>NovaShield</h1>')
            self.wfile.write(html.encode('utf-8')); return

        if parsed.path.startswith('/static/'):
            p = os.path.join(NS_WWW, parsed.path[len('/static/'):])
            if not os.path.abspath(p).startswith(NS_WWW): self._set_headers(404); self.wfile.write(b'{}'); return
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
            data = {
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'cpu':   read_json(os.path.join(NS_LOGS, 'cpu.json'), {}),
                'memory':read_json(os.path.join(NS_LOGS, 'memory.json'), {}),
                'disk':  read_json(os.path.join(NS_LOGS, 'disk.json'), {}),
                'network':read_json(os.path.join(NS_LOGS, 'network.json'), {}),
                'integrity':read_json(os.path.join(NS_LOGS, 'integrity.json'), {}),
                'process': read_json(os.path.join(NS_LOGS,'process.json'),{}),
                'user': read_json(os.path.join(NS_LOGS,'user.json'),{}),
                'services': read_json(os.path.join(NS_LOGS,'service.json'),{}),
                'logwatch': read_json(os.path.join(NS_LOGS,'logwatch.json'),{}),
                'alerts': last_lines(os.path.join(NS_LOGS,'alerts.log'), 200),
                'projects_count': len([x for x in os.listdir(os.path.join(NS_HOME,'projects')) if not x.startswith('.')]) if os.path.exists(os.path.join(NS_HOME,'projects')) else 0,
                'modules_count': len([x for x in os.listdir(os.path.join(NS_HOME,'modules')) if not x.startswith('.')]) if os.path.exists(os.path.join(NS_HOME,'modules')) else 0,
                'version': read_text(os.path.join(NS_HOME,'version.txt'),'unknown'),
                'csrf': sess.get('csrf','') if auth_enabled() else 'public'
            }
            self._set_headers(200); self.wfile.write(json.dumps(data).encode('utf-8')); return

        if parsed.path == '/api/config':
            if not require_auth(self): return
            self._set_headers(200, 'text/plain; charset=utf-8'); self.wfile.write(read_text(CONFIG, '').encode('utf-8')); return

        if parsed.path == '/api/logs':
            if not require_auth(self): return
            q = parse_qs(parsed.query); name = (q.get('name', ['launcher.log'])[0]).replace('..','')
            p = os.path.join(NS_HOME, name); 
            if not os.path.exists(p): p = os.path.join(NS_LOGS, name)
            lines = []
            try:
                with open(p,'r',encoding='utf-8') as f: lines=f.read().splitlines()[-200:]
            except Exception: pass
            self._set_headers(200); self.wfile.write(json.dumps({'name': name, 'lines': lines}).encode('utf-8')); return

        if parsed.path == '/api/fs':
            if not require_auth(self): return
            q = parse_qs(parsed.query); d = q.get('dir',[''])[0]
            if not d: d = NS_HOME
            d = os.path.abspath(d)
            if not d.startswith(NS_HOME): self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            out=[]
            try:
                for entry in os.scandir(d):
                    if entry.name.startswith('.'): continue
                    if 'keys' in d and entry.is_file(): continue
                    out.append({'name':entry.name,'is_dir':entry.is_dir(),'size':(entry.stat().st_size if entry.is_file() else 0)})
            except Exception: pass
            self._set_headers(200); self.wfile.write(json.dumps({'dir':d,'entries':out}).encode('utf-8')); return

        if parsed.path == '/api/fs_read':
            if not require_auth(self): return
            q = parse_qs(parsed.query); p = (q.get('path',[''])[0])
            full = os.path.abspath(p)
            if not full.startswith(NS_HOME): self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            if not os.path.exists(full) or not os.path.isfile(full):
                self._set_headers(404); self.wfile.write(b'{"error":"not found"}'); return
            try:
                size = os.path.getsize(full)
                content = open(full,'rb').read(500_000).decode('utf-8','ignore')
                self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'path':full,'size':size,'content':content}).encode('utf-8')); return
            except Exception as e:
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8')); return

        if parsed.path == '/site':
            index = os.path.join(SITE_DIR,'index.html')
            self._set_headers(200,'text/html; charset=utf-8'); self.wfile.write(read_text(index,'<h1>No site yet</h1>').encode('utf-8')); return

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

        if parsed.path == '/api/control':
            if not require_auth(self): return
            try: data = json.loads(body or '{}')
            except Exception: data={}
            action = data.get('action',''); target = data.get('target','')
            flag = os.path.join(NS_CTRL, f'{target}.disabled')
            if action == 'enable' and target:
                try: 
                    if os.path.exists(flag): os.remove(flag)
                    audit(f'MONITOR ENABLE {target} ip={self.client_address[0]}')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception: pass
            if action == 'disable' and target:
                try:
                    open(flag,'w').close()
                    audit(f'MONITOR DISABLE {target} ip={self.client_address[0]}')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception:
                    pass
            self_path = read_text(SELF_PATH_FILE).strip() or os.path.join(NS_HOME, 'bin', 'novashield.sh')
            if action in ('backup','version','restart_monitors'):
                try:
                    if action=='backup': os.system(f'\"{self_path}\" --backup >/dev/null 2>&1 &')
                    if action=='version': os.system(f'\"{self_path}\" --version-snapshot >/dev/null 2>&1 &')
                    if action=='restart_monitors': os.system(f'\"{self_path}\" --restart-monitors >/dev/null 2>&1 &')
                    audit(f'CONTROL {action} ip={self.client_address[0]}')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception: pass
            self._set_headers(400); self.wfile.write(b'{"ok":false}'); return

        if parsed.path == '/api/chat':
            if not require_auth(self): return
            try: data = json.loads(body or '{}')
            except Exception: data={}
            prompt = data.get('prompt','')
            reply = ai_reply(prompt)
            try: open(CHATLOG,'a',encoding='utf-8').write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} Q:{prompt} A:{reply}\n')
            except Exception: pass
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'reply':reply}).encode('utf-8')); return

        if parsed.path == '/api/webgen':
            if not require_auth(self): return
            try: data = json.loads(body or '{}')
            except Exception: data={}
            title = data.get('title','Untitled'); content = data.get('content','')
            slug = ''.join([c.lower() if c.isalnum() else '-' for c in title]).strip('-') or f'page-{int(time.time())}'
            Path(SITE_DIR).mkdir(parents=True, exist_ok=True)
            page_path = os.path.join(SITE_DIR, f'{slug}.html')
            write_text(page_path, f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title></head><body><h1>{title}</h1><div>{content}</div></body></html>')
            pages = [p for p in os.listdir(SITE_DIR) if p.endswith('.html')]
            links = '\n'.join([f'<li><a href="/site/{p}">{p}</a></li>' for p in pages if p!='index.html'])
            write_text(os.path.join(SITE_DIR,'index.html'), f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>Site</title></head><body><h1>Site</h1><ul>{links}</ul></body></html>')
            audit(f'WEBGEN page={slug}.html ip={self.client_address[0]}')
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'page':f'/site/{slug}.html'}).encode('utf-8')); return

        # File manager actions
        if parsed.path == '/api/fs_write':
            if not require_auth(self): return
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path',''); content=data.get('content','')
            full=os.path.abspath(path)
            if not full.startswith(NS_HOME): self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            try: write_text(full, content); audit(f'FS WRITE {full} ip={self.client_address[0]}'); self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e: self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_mkdir':
            if not require_auth(self): return
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path','')
            full=os.path.abspath(path)
            if not full.startswith(NS_HOME): self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            try: Path(full).mkdir(parents=True, exist_ok=True); audit(f'FS MKDIR {full} ip={self.client_address[0]}'); self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e: self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_mv':
            if not require_auth(self): return
            try: data=json.loads(body or '{}')
            except Exception: data={}
            src=data.get('src',''); dst=data.get('dst','')
            srcf=os.path.abspath(src); dstf=os.path.abspath(dst)
            if not srcf.startswith(NS_HOME) or not dstf.startswith(NS_HOME): self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            try: os.rename(srcf,dstf); audit(f'FS MV {srcf} -> {dstf} ip={self.client_address[0]}'); self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e: self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        if parsed.path == '/api/fs_rm':
            if not require_auth(self): return
            try: data=json.loads(body or '{}')
            except Exception: data={}
            path=data.get('path',''); full=os.path.abspath(path)
            if not full.startswith(NS_HOME): self._set_headers(403); self.wfile.write(b'{"error":"forbidden"}'); return
            try:
                if os.path.isdir(full): os.rmdir(full)
                elif os.path.isfile(full): os.remove(full)
                audit(f'FS RM {full} ip={self.client_address[0]}')
                self._set_headers(200); self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self._set_headers(500); self.wfile.write(json.dumps({'ok':False,'error':str(e)}).encode('utf-8'))
            return

        self._set_headers(400); self.wfile.write(b'{"ok":false}')

def pick_host_port():
    host = '127.0.0.1'; port = 8765
    try:
        h = None; p = None
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

def tls_params():
    if not yaml_flag('security.tls_enabled', False):
        return None
    crt = yaml_val('security.tls_cert','keys/tls.crt')
    key = yaml_val('security.tls_key','keys/tls.key')
    return os.path.join(NS_HOME,crt), os.path.join(NS_HOME,key)

if __name__ == '__main__':
    host, port = pick_host_port()
    os.chdir(NS_WWW)
    crt_key = tls_params()
    import ssl
    for h in (host, '127.0.0.1', '0.0.0.0'):
        try:
            httpd = HTTPServer((h, port), Handler)
            if crt_key:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(crt_key[0], crt_key[1])
                httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
                scheme='https'
            else:
                scheme='http'
            print(f"NovaShield Web Server on {scheme}://{h}:{port}")
            httpd.serve_forever()
        except Exception as e:
            print(f"Bind failed on {h}:{port}: {e}", file=sys.stderr)
            time.sleep(0.5)
            continue
