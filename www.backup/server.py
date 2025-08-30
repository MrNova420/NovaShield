#!/usr/bin/env python3
import json, os, sys, time, hashlib, http.cookies, socket
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
LOGIN = os.path.join(NS_WWW, 'login.html')
CONFIG = os.path.join(NS_HOME, 'config.yaml')
SESSIONS = os.path.join(NS_CTRL, 'sessions.json')
CHATLOG = os.path.join(NS_LOGS, 'chat.log')
SITE_DIR = os.path.join(NS_HOME, 'site')

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

def users_list():
    db = read_json(SESSIONS, {}) or {}
    return db.get('_userdb', {})

def set_user(username, pass_sha):
    db = read_json(SESSIONS, {}) or {}
    ud = db.get('_userdb', {})
    ud[username]=pass_sha
    db['_userdb']=ud
    write_json(SESSIONS, db)

def check_login(username, password):
    salt = auth_salt()
    sha = hashlib.sha256((salt+':'+password).encode()).hexdigest()
    return users_list().get(username,'')==sha

def new_session(username):
    token = hashlib.sha256(f'{username}:{time.time()}'.encode()).hexdigest()
    db = read_json(SESSIONS, {}) or {}
    db[token]={'user':username,'ts':int(time.time())}
    write_json(SESSIONS, db)
    return token

def get_session(handler):
    if not auth_enabled(): return {'user':'public'}
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

def last_lines(path, n=100):
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END); size=f.tell(); block=1024; data=b''
            while size>0 and n>0:
                step=min(block,size); size-=step; f.seek(size); buf=f.read(step); data=buf+data; n-=buf.count(b'\n')
            return data.decode('utf-8','ignore').splitlines()[-100:]
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
            for k,v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/':
            if auth_enabled() and not get_session(self):
                self._set_headers(200, 'text/html; charset=utf-8')
                html = read_text(LOGIN, '<h1>Login required</h1>')
                self.wfile.write(html.encode('utf-8')); return
            self._set_headers(200, 'text/html; charset=utf-8')
            html = read_text(INDEX, '<h1>NovaShield</h1>')
            self.wfile.write(html.encode('utf-8')); return

        if parsed.path == '/logout':
            self._set_headers(302, 'text/plain', {'Set-Cookie': 'NSSESS=deleted; Path=/; HttpOnly; Max-Age=0', 'Location':'/'})
            self.wfile.write(b'bye'); return

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
                'alerts': (lambda p: (open(p,'r',encoding='utf-8').read().splitlines()[-100:]) if os.path.exists(p) else [])(os.path.join(NS_LOGS,'alerts.log')),
                'projects_count': len([x for x in os.listdir(os.path.join(NS_HOME, 'projects')) if not x.startswith('.')]) if os.path.exists(os.path.join(NS_HOME, 'projects')) else 0,
                'modules_count': len([x for x in os.listdir(os.path.join(NS_HOME, 'modules')) if not x.startswith('.')]) if os.path.exists(os.path.join(NS_HOME, 'modules')) else 0,
                'version': read_text(os.path.join(NS_HOME, 'version.txt'), 'unknown'),
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
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''

        if parsed.path == '/api/login':
            try: data = json.loads(body or '{}'); user=data.get('user'); pwd=data.get('pass')
            except Exception: data={}; user=''; pwd=''
            if auth_enabled() and check_login(user, pwd):
                tok = new_session(user)
                self._set_headers(200, 'application/json', {'Set-Cookie': f'NSSESS={tok}; Path=/; HttpOnly; SameSite=Strict'})
                self.wfile.write(b'{"ok":true}'); return
            self._set_headers(401); self.wfile.write(b'{"ok":false}'); return

        if not require_auth(self): return

        if parsed.path == '/api/chat':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            prompt = data.get('prompt','')
            reply = ai_reply(prompt)
            try: open(CHATLOG,'a',encoding='utf-8').write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} Q:{prompt} A:{reply}\n')
            except Exception: pass
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'reply':reply}).encode('utf-8')); return

        if parsed.path == '/api/control':
            try: data = json.loads(body or '{}')
            except Exception: data={}
            action = data.get('action',''); target = data.get('target','')
            flag = os.path.join(NS_CTRL, f'{target}.disabled')
            if action == 'enable' and target:
                try:
                    if os.path.exists(flag): os.remove(flag)
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception:
                    pass
            if action == 'disable' and target:
                try:
                    open(flag,'w').close()
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception:
                    pass
            self_path = read_text(SELF_PATH_FILE).strip() or os.path.join(NS_HOME, 'bin', 'novashield.sh')
            if action in ('backup','version','restart_monitors'):
                try:
                    if action=='backup': os.system(f'\"{self_path}\" --backup >/dev/null 2>&1 &')
                    if action=='version': os.system(f'\"{self_path}\" --version-snapshot >/dev/null 2>&1 &')
                    if action=='restart_monitors': os.system(f'\"{self_path}\" --restart-monitors >/dev/null 2>&1 &')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception:
                    pass
            self._set_headers(400); self.wfile.write(b'{"ok":false}'); return

        if parsed.path == '/api/webgen':
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
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'page':f'/site/{slug}.html'}).encode('utf-8')); return

        if parsed.path.startswith('/site/'):
            p = parsed.path[len('/site/'):]
            full = os.path.join(SITE_DIR, p)
            if not os.path.abspath(full).startswith(SITE_DIR): self._set_headers(403); self.wfile.write(b'{}'); return
            if os.path.exists(full):
                self._set_headers(200, 'text/html; charset=utf-8'); self.wfile.write(read_text(full).encode('utf-8')); return
            self._set_headers(404); self.wfile.write(b'{}'); return

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

if __name__ == '__main__':
    host, port = pick_host_port()
    os.chdir(NS_WWW)
    for h in (host, '127.0.0.1', '0.0.0.0'):
        try:
            httpd = HTTPServer((h, port), Handler)
            print(f"NovaShield Web Server on http://{h}:{port}")
            httpd.serve_forever()
        except Exception as e:
            print(f"Bind failed on {h}:{port}: {e}", file=sys.stderr)
            time.sleep(0.5)
            continue
