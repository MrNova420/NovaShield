#!/usr/bin/env bash
# ==============================================================================
# NovaShield Terminal 3.1.0 — JARVIS Edition — All‑in‑One Installer & Runtime
# ==============================================================================
# Author  : niteas aka MrNova420
# Project : NovaShield (a.k.a. Nova)
# License : MIT
# Platform: Termux (Android) + Linux (Debian/Ubuntu/Arch/Fedora) auto-detect
# Features: Web Terminal (PTY), 2FA/TOTP, TLS, File Manager, Enhanced Security
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

NS_VERSION="3.1.0"

NS_HOME="${HOME}/.novashield"
NS_BIN="${NS_HOME}/bin"
NS_LOGS="${NS_HOME}/logs"
NS_WWW="${NS_HOME}/www"
NS_MODULES="${NS_HOME}/modules"
NS_PROJECTS="${NS_HOME}/projects"
NS_VERSIONS="${NS_HOME}/versions"
NS_KEYS="${NS_HOME}/keys"
NS_CTRL="${NS_HOME}/control"
NS_TMP="${NS_HOME}/.tmp"
NS_PID="${NS_HOME}/.pids"
NS_CONF="${NS_HOME}/config.yaml"
NS_SESSION="${NS_HOME}/session.log"
NS_VERSION_FILE="${NS_HOME}/version.txt"
NS_SELF_PATH_FILE="${NS_BIN}/self_path"
NS_LAUNCHER_BACKUPS="${NS_BIN}/backups"
NS_ALERTS="${NS_LOGS}/alerts.log"
NS_CHATLOG="${NS_LOGS}/chat.log"
NS_SCHED_STATE="${NS_CTRL}/scheduler.state"
NS_SESS_DB="${NS_CTRL}/sessions.json"
NS_AUDIT_LOG="${NS_LOGS}/audit.log"
NS_CERT_DIR="${NS_KEYS}/certs"
NS_RATE_LIMIT_DB="${NS_CTRL}/rate_limits.json"
NS_IP_ALLOWLIST="${NS_CTRL}/ip_allow.txt"
NS_IP_DENYLIST="${NS_CTRL}/ip_deny.txt"

NS_AUDIT_LOG="${NS_LOGS}/audit.log"
NS_CERT_DIR="${NS_KEYS}/certs"
NS_RATE_LIMIT_DB="${NS_CTRL}/rate_limits.json"
NS_IP_ALLOWLIST="${NS_CTRL}/ip_allow.txt"
NS_IP_DENYLIST="${NS_CTRL}/ip_deny.txt"

NS_DEFAULT_PORT=8765
NS_DEFAULT_HOST="127.0.0.1"

NS_SELF="${BASH_SOURCE[0]}"
if command -v realpath >/dev/null 2>&1; then
  NS_SELF="$(realpath "${NS_SELF}")" || true
elif command -v readlink >/dev/null 2>&1; then
  NS_SELF="$(readlink -f "${NS_SELF}" 2>/dev/null || echo "${NS_SELF}")"
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

ns_now() { date '+%Y-%m-%d %H:%M:%S'; }
ns_log() { echo -e "$(ns_now) [INFO ] $*" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_warn(){ echo -e "${YELLOW}$(ns_now) [WARN ] $*${NC}" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_err() { echo -e "${RED}$(ns_now) [ERROR] $*${NC}" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_ok()  { echo -e "${GREEN}✔ $*${NC}"; }

alert(){
  local level="$1"; shift
  local msg="$*"
  local line="$(ns_now) [$level] $msg"
  echo "$line" | tee -a "$NS_ALERTS" >&2
  notify_dispatch "$level" "$msg" || true
}

trap 'ns_err "Unexpected error at line $LINENO"; alert "ERROR" "Trap error at $LINENO"' ERR

die(){ ns_err "$*"; alert "CRIT" "$*"; exit 1; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }
write_file(){ local path="$1"; local mode="$2"; shift 2; install -m "$mode" /dev/null "$path" 2>/dev/null || true; cat >"$path"; }
append_file(){ local path="$1"; shift; cat >>"$path"; }
slurp(){ [ -f "$1" ] && cat "$1" || true; }
is_int(){ [[ "$1" =~ ^[0-9]+$ ]]; }
ensure_int(){ local v="$1" d="$2"; is_int "$v" && echo "$v" || echo "$d"; }

IS_TERMUX=0
if uname -a | grep -iq termux || { [ -n "${PREFIX:-}" ] && echo "$PREFIX" | grep -q "/com.termux/"; }; then
  IS_TERMUX=1
fi

audit_log() {
  local action="$1" user="${2:-system}" details="${3:-}"
  echo "$(ns_now) $user $action $details" >> "$NS_AUDIT_LOG"
}

PKG_INSTALL(){
  if [ "$IS_TERMUX" -eq 1 ]; then
    pkg install -y "$@"
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y && sudo apt-get install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y "$@"
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm "$@"
  else
    ns_warn "Unknown package manager. Install dependencies manually: $*"
  fi
}

ensure_dirs(){
  mkdir -p "$NS_BIN" "$NS_LOGS" "$NS_WWW" "$NS_MODULES" "$NS_PROJECTS" \
           "$NS_VERSIONS" "$NS_KEYS" "$NS_CTRL" "$NS_TMP" "$NS_PID" \
           "$NS_LAUNCHER_BACKUPS" "${NS_HOME}/backups" "${NS_HOME}/site" \
           "$NS_CERT_DIR"
  : >"$NS_ALERTS" || true
  : >"$NS_CHATLOG" || true
  : >"$NS_AUDIT_LOG" || true
  [ -f "$NS_SESS_DB" ] || echo '{}' >"$NS_SESS_DB"
  echo "$NS_VERSION" >"$NS_VERSION_FILE"
  echo "$NS_SELF" >"$NS_SELF_PATH_FILE"
  audit_log "ensure_dirs" "system" "directories created"
}

write_default_config(){
  if [ -f "$NS_CONF" ]; then return 0; fi
  ns_log "Writing default config to $NS_CONF"
  write_file "$NS_CONF" 600 <<'YAML'
# NovaShield 3.1.0 Configuration
version: "3.1.0"

# Web server settings
web:
  host: "127.0.0.1"
  port: 8765
  allow_lan: false

# Enhanced Security Settings
security:
  auth_enabled: false
  auth_salt: "change-this-salt-in-production"
  session_timeout: 3600
  
  # Two-Factor Authentication (TOTP)
  totp_enabled: false
  totp_issuer: "NovaShield"
  
  # TLS/SSL Support
  tls_enabled: false
  cert_file: "keys/certs/server.crt"
  key_file: "keys/certs/server.key"
  
  # CSRF Protection
  csrf_enabled: true
  
  # Rate Limiting
  rate_limit_enabled: true
  rate_limit_requests: 30
  rate_limit_window: 60
  rate_limit_lockout: 300
  
  # IP Filtering
  ip_filtering_enabled: false
  ip_allowlist_file: "control/ip_allow.txt"
  ip_denylist_file: "control/ip_deny.txt"

# File Manager Settings
file_manager:
  enabled: true
  sandbox_root: ".novashield"
  max_file_size: 10485760  # 10MB
  allowed_extensions: [".txt", ".md", ".py", ".sh", ".yaml", ".yml", ".json", ".log"]

# Terminal Settings
terminal:
  enabled: true
  idle_timeout: 1800  # 30 minutes
  max_connections: 3
  shell: "/bin/bash"
  working_directory: "projects"

# Monitoring configuration
monitors:
  cpu:         { enabled: true,  interval_sec: 5,  warn_pct: 80, crit_pct: 95 }
  memory:      { enabled: true,  interval_sec: 5,  warn_pct: 80, crit_pct: 95 }
  disk:        { enabled: true,  interval_sec: 10, warn_pct: 85, crit_pct: 95, mount: "/" }
  network:     { enabled: true,  interval_sec: 5,  iface: "", ping_host: "1.1.1.1", loss_warn: 20 }
  integrity:   { enabled: true,  interval_sec: 60, watch_paths: ["/system/bin","/system/xbin","/usr/bin"] }
  process:     { enabled: true,  interval_sec: 10, suspicious: ["nc","nmap","hydra","netcat","telnet"] }
  userlogins:  { enabled: true,  interval_sec: 30 }
  services:    { enabled: false, interval_sec: 20, targets: ["cron","ssh","sshd"] }
  logs:        { enabled: true,  interval_sec: 15, files: ["/var/log/auth.log","/var/log/syslog"], patterns:["error","failed","denied","segfault"] }
  scheduler:   { enabled: true,  interval_sec: 30 }

# Logging and alerting
logging:
  keep_days: 14
  alerts_enabled: true
  alert_sink: ["terminal", "web", "notify"]
  notify_levels: ["CRIT","WARN","ERROR"]
  audit_enabled: true

# Backup settings
backup:
  enabled: true
  max_keep: 10
  encrypt: true
  paths: ["projects", "modules", "config.yaml"]

# Encryption keys
keys:
  rsa_bits: 4096
  aes_key_file: "keys/aes.key"

# Notification settings
notifications:
  email:
    enabled: false
    smtp_host: "smtp.example.com"
    smtp_port: 587
    username: "user@example.com"
    password: "change-me"
    to: ["you@example.com"]
    use_tls: true
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
  discord:
    enabled: false
    webhook_url: ""

scheduler:
  tasks:
    - name: "daily-backup"
      action: "backup"
      time: "02:30"
    - name: "version-snapshot-weekly"
      action: "version"
      time: "03:00"

webgen:
  enabled: true
  site_name: "NovaShield Site"
  theme: "jarvis-dark"
YAML
  audit_log "write_config" "system" "v3.1.0 configuration written"
}

install_dependencies(){
  ns_log "Checking dependencies..."
  local need=(python3 awk sed grep tar gzip df du ps top uname head tail cut tr sha256sum curl ping find xargs)
  for c in "${need[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      ns_warn "$c missing; attempting install"
      PKG_INSTALL "$c" || true
    fi
  done
  # OpenSSL binary name on Termux is openssl-tool
  if ! command -v openssl >/dev/null 2>&1; then
    if [ "$IS_TERMUX" -eq 1 ]; then
      ns_warn "Installing openssl-tool (Termux)"
      PKG_INSTALL openssl-tool || true
    else
      PKG_INSTALL openssl || true
    fi
  fi
  if [ "$IS_TERMUX" -eq 1 ]; then
    if ! command -v sv-enable >/dev/null 2>&1; then
      ns_warn "Installing termux-services (optional)"
      PKG_INSTALL termux-services || true
    fi
  fi
}

generate_keys(){
  if [ ! -f "${NS_KEYS}/private.pem" ] || [ ! -f "${NS_KEYS}/public.pem" ]; then
    ns_log "Generating RSA keypair"
    local bits; bits=$(awk -F': ' '/rsa_bits:/ {print $2}' "$NS_CONF" 2>/dev/null || echo 4096)
    (cd "$NS_KEYS" && openssl genrsa -out private.pem "${bits}" && openssl rsa -in private.pem -pubout -out public.pem)
    chmod 600 "${NS_KEYS}/private.pem"
  fi
  local aesf
  aesf=$(awk -F': ' '/aes_key_file:/ {print $2}' "$NS_CONF" | tr -d '"' | tr -d ' ' || true)
  [ -z "$aesf" ] && aesf="keys/aes.key"
  if [ ! -f "${NS_HOME}/${aesf}" ]; then
    ns_log "Generating AES key file: ${aesf}"
    head -c 64 /dev/urandom >"${NS_HOME}/${aesf}"
    chmod 600 "${NS_HOME}/${aesf}"
  fi
  audit_log "generate_keys" "system" "encryption keys generated"
}

generate_self_signed_cert(){
  local cert_file="$NS_CERT_DIR/server.crt"
  local key_file="$NS_CERT_DIR/server.key"
  
  if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
    return 0
  fi
  
  ns_log "Generating self-signed certificate..."
  
  local openssl_cmd="openssl"
  if [ "$IS_TERMUX" -eq 1 ] && command -v openssl-tool >/dev/null 2>&1; then
    openssl_cmd="openssl-tool"
  fi
  
  "$openssl_cmd" req -x509 -newkey rsa:2048 -keyout "$key_file" -out "$cert_file" \
    -days 365 -nodes -subj "/C=US/ST=State/L=City/O=NovaShield/CN=localhost" 2>/dev/null
  
  chmod 600 "$key_file" "$cert_file"
  audit_log "generate_cert" "system" "self-signed certificate generated"
  ns_ok "Self-signed certificate generated"
}

# TOTP Support Functions
generate_totp_secret(){
  local user="$1"
  local secret_file="${NS_KEYS}/totp_${user}.secret"
  if [ -f "$secret_file" ]; then
    return 0
  fi
  
  # Generate base32 secret (16 chars = 80 bits)
  local secret
  secret=$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16)
  echo "$secret" > "$secret_file"
  chmod 600 "$secret_file"
  audit_log "generate_totp_secret" "$user" "TOTP secret generated"
}

get_totp_secret(){
  local user="$1"
  local secret_file="${NS_KEYS}/totp_${user}.secret"
  if [ -f "$secret_file" ]; then
    cat "$secret_file"
  fi
}

verify_totp(){
  local user="$1" code="$2"
  local secret; secret=$(get_totp_secret "$user")
  if [ -z "$secret" ]; then
    return 1
  fi
  
  # Simple TOTP verification using Python
  python3 << EOF
import hmac, hashlib, struct, time, base64

def totp(secret, time_step=30, digits=6):
    # Convert base32 secret to bytes
    try:
        key = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))
    except:
        exit(1)
    
    # Get current time window
    counter = int(time.time() // time_step)
    
    # Generate TOTP for current and previous window (allow 30s drift)
    for window in [counter, counter - 1]:
        counter_bytes = struct.pack('>Q', window)
        hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = hmac_digest[-1] & 0x0f
        code = struct.unpack('>I', hmac_digest[offset:offset+4])[0] & 0x7fffffff
        code = str(code % (10 ** digits)).zfill(digits)
        if code == "$code":
            exit(0)
    exit(1)

totp("$secret")
EOF
}

aes_key_path(){ awk -F': ' '/aes_key_file:/ {print $2}' "$NS_CONF" | tr -d '"' | tr -d ' ' ; }
enc_file(){ local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"; openssl enc -aes-256-cbc -salt -pbkdf2 -in "$in" -out "$out" -pass file:"$key"; }
dec_file(){ local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"; openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$out" -pass file:"$key"; }
enc_dir(){ local dir="$1"; local out="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"; tar -C "$dir" -czf "$tmp" . || tar -czf "$tmp" "$dir"; enc_file "$tmp" "$out"; rm -f "$tmp"; }
dec_dir(){ local in="$1"; local outdir="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"; dec_file "$in" "$tmp"; mkdir -p "$outdir"; tar -C "$outdir" -xzf "$tmp"; rm -f "$tmp"; }

write_notify_py(){
  write_file "${NS_BIN}/notify.py" 700 <<'PY'
#!/usr/bin/env python3
import os, sys, json, smtplib, ssl, urllib.request, urllib.parse
from email.mime_text import MIMEText as _MT
try:
  from email.mime.text import MIMEText
except Exception:
  MIMEText = _MT

NS_HOME = os.path.expanduser('~/.novashield')
CONF = os.path.join(NS_HOME, 'config.yaml')

def yaml_get(path, default=None):
  try:
    with open(CONF,'r',encoding='utf-8') as f:
      tree = {}
      stack = [(-1, tree)]
      for line in f:
        if not line.strip() or line.strip().startswith('#'): continue
        indent = len(line)-len(line.lstrip())
        while stack and indent <= stack[-1][0]: stack.pop()
        parent = stack[-1][1] if stack else tree
        s=line.strip()
        if ':' in s:
          k,v = s.split(':',1)
          k=k.strip(); v=v.strip()
          if v=='':
            parent[k]={}
            stack.append((indent,parent[k]))
          else:
            parent[k]=v.strip().strip('"')
        elif s.startswith('- '):
          k=s[2:].strip().strip('"')
          parent.setdefault('_list',[]).append(k)
    cur=tree
    for p in path.split('.'):
      if isinstance(cur,dict) and p in cur: cur=cur[p]
      else: return default
    return cur
  except Exception:
    return default

def send_email(subject, body):
  if not yaml_get('notifications.email.enabled') == 'true': return
  host = yaml_get('notifications.email.smtp_host','')
  port = int(yaml_get('notifications.email.smtp_port','587'))
  user = yaml_get('notifications.email.username','')
  pwd  = yaml_get('notifications.email.password','')
  to   = yaml_get('notifications.email.to','').strip('[]').replace('"','').split(',')
  use_tls = yaml_get('notifications.email.use_tls','true')=='true'
  tos = [t.strip() for t in to if t.strip()]
  if not (host and user and pwd and tos): return
  msg = MIMEText(body, 'plain', 'utf-8')
  msg['Subject'] = subject
  msg['From'] = user
  msg['To'] = ','.join(tos)
  try:
    if use_tls:
      context = ssl.create_default_context()
      with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls(context=context)
        server.login(user, pwd)
        server.sendmail(user, tos, msg.as_string())
    else:
      with smtplib.SMTP(host, port, timeout=10) as server:
        server.login(user, pwd)
        server.sendmail(user, tos, msg.as_string())
  except Exception:
    pass

def send_telegram(body):
  if not yaml_get('notifications.telegram.enabled') == 'true': return
  token = yaml_get('notifications.telegram.bot_token','')
  chat  = yaml_get('notifications.telegram.chat_id','')
  if not (token and chat): return
  data = urllib.parse.urlencode({'chat_id':chat,'text':body}).encode('utf-8')
  try: urllib.request.urlopen(urllib.request.Request(f'https://api.telegram.org/bot{token}/sendMessage', data=data), timeout=5)
  except Exception: pass

def send_discord(body):
  if not yaml_get('notifications.discord.enabled') == 'true': return
  hook = yaml_get('notifications.discord.webhook_url','')
  if not hook: return
  payload = json.dumps({'content': body}).encode('utf-8')
  req = urllib.request.Request(hook, data=payload, headers={'Content-Type':'application/json'})
  try: urllib.request.urlopen(req, timeout=5)
  except Exception: pass

if __name__ == '__main__':
  level = sys.argv[1] if len(sys.argv)>1 else 'INFO'
  subject = sys.argv[2] if len(sys.argv)>2 else 'NovaShield Notification'
  body = sys.argv[3] if len(sys.argv)>3 else ''
  allow = (yaml_get('logging.notify_levels','["CRIT","WARN","ERROR"]') or '').upper()
  if (level or '').upper() in allow:
    send_email(subject, body)
    send_telegram(f'{subject}\n{body}')
    send_discord(f'{subject}\n{body}')
PY
}

notify_dispatch(){
  local enabled; enabled=$(awk -F': ' '/alerts_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ')
  local sinks; sinks=$(awk -F'[][]' '/alert_sink:/ {print $2}' "$NS_CONF" | tr -d ' "' | tr ',' ' ')
  [ "$enabled" = "true" ] || return 0
  for s in $sinks; do
    case "$s" in
      notify) python3 "${NS_BIN}/notify.py" "$1" "NovaShield [$1]" "$2" >/dev/null 2>&1 || true ;;
      *) : ;;
    esac
  done
}

backup_snapshot(){
  local stamp; stamp=$(date '+%Y%m%d-%H%M%S')
  local tmp_tar="${NS_TMP}/backup-${stamp}.tar.gz"
  local dest_dir="${NS_HOME}/backups"; mkdir -p "$dest_dir"
  ns_log "Creating backup snapshot: $stamp"

  local incl=( )
  while IFS= read -r line; do
    case "$line" in
      *projects*) incl+=("$NS_PROJECTS") ;;
      *modules*)  incl+=("$NS_MODULES") ;;
      *config.yaml*) incl+=("$NS_CONF") ;;
    esac
  done < <(awk '/backup:/,0' "$NS_CONF" 2>/dev/null || true)
  [ ${#incl[@]} -eq 0 ] && incl=("$NS_PROJECTS" "$NS_MODULES" "$NS_CONF")

  tar -czf "$tmp_tar" "${incl[@]}" 2>/dev/null || tar -C "$NS_HOME" -czf "$tmp_tar" projects modules config.yaml || true

  local enc_enabled; enc_enabled=$(awk -F': ' '/encrypt:/ {print $2}' "$NS_CONF" | head -n1 | tr -d ' ')
  local final
  if [ "$enc_enabled" = "true" ]; then
    final="${dest_dir}/backup-${stamp}.tar.gz.enc"
    enc_file "$tmp_tar" "$final"
    rm -f "$tmp_tar"
  else
    final="${dest_dir}/backup-${stamp}.tar.gz"
    mv "$tmp_tar" "$final"
  fi

  ns_ok "Backup created: $final"
  rotate_backups
}


rotate_backups(){
  local max_keep; max_keep=$(awk -F': ' '/max_keep:/ {print $2}' "$NS_CONF" | tr -d ' ' || echo 10)
  ls -1t "$NS_HOME/backups" 2>/dev/null | tail -n +$((max_keep+1)) | while read -r f; do
    ns_warn "Removing old backup: $f"; rm -f "$NS_HOME/backups/$f" || true
  done
}

version_snapshot(){
  local stamp="$(date '+%Y%m%d-%H%M%S')"
  local vdir="${NS_VERSIONS}/${stamp}"; mkdir -p "$vdir"
  ns_log "Creating version snapshot: $vdir"
  cp -a "$NS_MODULES" "$vdir/modules" 2>/dev/null || true
  cp -a "$NS_PROJECTS" "$vdir/projects" 2>/dev/null || true
  cp -a "$NS_CONF" "$vdir/config.yaml" 2>/dev/null || true
  cp -a "$NS_HOME/launcher.log" "$vdir/launcher.log" 2>/dev/null || true
  cp -a "$NS_ALERTS" "$vdir/alerts.log" 2>/dev/null || true
}

monitor_enabled(){ local name="$1"; [ -f "${NS_CTRL}/${name}.disabled" ] && return 1 || return 0; }
write_json(){ local path="$1"; shift; printf '%s' "$*" >"$path"; }

# Helper: get internal IP on Termux without netlink; fallback to ifconfig/ip.
ns_internal_ip(){
  local iface="$1" ip=""
  if [ "$IS_TERMUX" -eq 1 ] && command -v getprop >/dev/null 2>&1; then
    ip=$(getprop dhcp.wlan0.ipaddress 2>/dev/null || true)
    [ -z "$ip" ] && ip=$(getprop dhcp.eth0.ipaddress 2>/dev/null || true)
    if [ -z "$ip" ]; then
      ip=$(getprop 2>/dev/null | awk -F'[][]' '/dhcp\..*\.ipaddress]/{print $3}' | head -n1)
    fi
  fi
  if [ -z "$ip" ] && command -v ifconfig >/dev/null 2>&1; then
    ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1)
    [ -z "$ip" ] && ip=$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | head -n1)
  fi
  if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
    ip=$(ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
    [ -z "$ip" ] && ip=$(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.' | head -n1)
  fi
  echo "$ip"
}

_monitor_cpu(){
  set +e; set +o pipefail
  local interval warn crit
  interval=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 3)
  warn=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /warn_load/) print $2 }' "$NS_CONF" | tr -d ' ')
  crit=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /crit_load/) print $2 }' "$NS_CONF" | tr -d ' ')
  [ -z "$warn" ] && warn=2.00; [ -z "$crit" ] && crit=4.00
  while true; do
    monitor_enabled cpu || { sleep "$interval"; continue; }
    local load1; load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
    local lvl
    lvl=$(awk -v l="$load1" -v w="$warn" -v c="$crit" 'BEGIN{ if(l>=c){print "CRIT"} else if(l>=w){print "WARN"} else {print "OK"} }')
    write_json "${NS_LOGS}/cpu.json" "{\"ts\":\"$(ns_now)\",\"load1\":$load1,\"warn\":$warn,\"crit\":$crit,\"level\":\"$lvl\"}"
    [ "$lvl" = "CRIT" ] && alert CRIT "CPU load high: $load1" || { [ "$lvl" = "WARN" ] && alert WARN "CPU load elevated: $load1"; }
    sleep "$interval"
  done
}

_monitor_mem(){
  set +e; set +o pipefail
  local interval warn crit
  interval=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 3)
  warn=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /warn_pct/) print $2 }' "$NS_CONF" | tr -d ' '); warn=$(ensure_int "${warn:-}" 80)
  crit=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /crit_pct/) print $2 }' "$NS_CONF" | tr -d ' '); crit=$(ensure_int "${crit:-}" 92)
  while true; do
    monitor_enabled memory || { sleep "$interval"; continue; }
    local mem_total mem_avail mem_used pct
    if grep -q MemAvailable /proc/meminfo 2>/dev/null; then
      mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
      mem_avail=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
      mem_used=$((mem_total-mem_avail)); pct=$((mem_used*100/mem_total))
    else
      read -r _ mem_total _ < <(free -k | awk '/Mem:/ {print $2, $3, $4}')
      mem_used=$(free -k | awk '/Mem:/ {print $3}'); pct=$((mem_used*100/mem_total))
    fi
    local lvl="OK"; [ "$pct" -ge "$crit" ] && lvl="CRIT" || { [ "$pct" -ge "$warn" ] && lvl="WARN"; }
    write_json "${NS_LOGS}/memory.json" "{\"ts\":\"$(ns_now)\",\"used_pct\":$pct,\"warn\":$warn,\"crit\":$crit,\"level\":\"$lvl\"}"
    [ "$lvl" = "CRIT" ] && alert CRIT "Memory high: ${pct}%" || { [ "$lvl" = "WARN" ] && alert WARN "Memory elevated: ${pct}%"; }
    sleep "$interval"
  done
}

_monitor_disk(){
  set +e; set +o pipefail
  local interval warn crit mount
  interval=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 10)
  warn=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /warn_pct/) print $2 }' "$NS_CONF" | tr -d ' '); warn=$(ensure_int "${warn:-}" 85)
  crit=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /crit_pct/) print $2 }' "$NS_CONF" | tr -d ' '); crit=$(ensure_int "${crit:-}" 95)
  mount=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /mount:/) print $2 }' "$NS_CONF" | tr -d '" ')
  [ -z "$mount" ] && mount="/"
  if [ "$IS_TERMUX" -eq 1 ] && [ "$mount" = "/" ]; then
    mount="$NS_HOME"
  fi
  while true; do
    monitor_enabled disk || { sleep "$interval"; continue; }
    local use; use=$(df -P "$mount" | awk 'END {gsub("%","",$5); print $5+0}')
    local lvl="OK"; [ "$use" -ge "$crit" ] && lvl="CRIT" || { [ "$use" -ge "$warn" ] && lvl="WARN"; }
    write_json "${NS_LOGS}/disk.json" "{\"ts\":\"$(ns_now)\",\"use_pct\":$use,\"warn\":$warn,\"crit\":$crit,\"mount\":\"$mount\",\"level\":\"$lvl\"}"
    [ "$lvl" = "CRIT" ] && alert CRIT "Disk $mount high: ${use}%" || { [ "$lvl" = "WARN" ] && alert WARN "Disk $mount elevated: ${use}%"; }
    sleep "$interval"
  done
}

_monitor_net(){
  set +e; set +o pipefail
  local interval iface pingh warnloss
  interval=$(awk -F': ' '/network:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 5)
  iface=$(awk -F': ' '/network:/,/}/ { if($1 ~ /iface:/) print $2 }' "$NS_CONF" | tr -d '" ')
  pingh=$(awk -F': ' '/network:/,/}/ { if($1 ~ /ping_host/) print $2 }' "$NS_CONF" | tr -d '" '); [ -z "$pingh" ] && pingh="1.1.1.1"
  warnloss=$(awk -F': ' '/network:/,/}/ { if($1 ~ /loss_warn/) print $2 }' "$NS_CONF" | tr -d ' '); warnloss=$(ensure_int "${warnloss:-}" 20)
  while true; do
    monitor_enabled network || { sleep "$interval"; continue; }
    local ip pubip loss=0 avg=0
    ip="$(ns_internal_ip "$iface")"
    if command -v ping >/dev/null 2>&1; then
      local out; out=$(ping -c 3 -w 3 "$pingh" 2>/dev/null || true)
      loss=$(echo "$out" | awk -F',' '/packet loss/ {gsub("%","",$3); gsub(" ","",$3); print $3+0}' 2>/dev/null || echo 0)
      avg=$(echo "$out" | awk -F'/' '/rtt/ {print $5}' 2>/dev/null || echo 0)
    fi
    pubip=""
    for e in icanhazip.com ifconfig.me api.ipify.org; do
      if command -v curl >/dev/null 2>&1; then pubip=$(curl -s --max-time 2 "$e" || true); fi
      [ -n "$pubip" ] && break
    done
    local lvl="OK"; [ "${loss:-0}" -ge "${warnloss:-999}" ] && lvl="WARN"
    write_json "${NS_LOGS}/network.json" "{\"ts\":\"$(ns_now)\",\"ip\":\"${ip:-}\",\"public_ip\":\"${pubip:-}\",\"loss_pct\":${loss:-0},\"rtt_avg_ms\":${avg:-0},\"level\":\"$lvl\"}"
    [ "$lvl" = "WARN" ] && alert WARN "Network loss ${loss}% to ${pingh}"
    sleep "$interval"
  done
}

_monitor_integrity(){
  set +e; set +o pipefail
  local interval; interval=$(awk -F': ' '/integrity:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 60)
  local list; list=$(awk -F'- ' '/watch_paths:/{flag=1;next}/]/{flag=0}flag{print $2}' "$NS_CONF" 2>/dev/null || true)
  while true; do
    monitor_enabled integrity || { sleep "$interval"; continue; }
    for p in $list; do
      p=$(echo "$p" | tr -d '"' | tr -d ' ')
      [ -d "$p" ] || continue
      local sumfile="${NS_LOGS}/integrity.$(echo "$p" | tr '/' '_').sha"
      if [ -f "$sumfile" ]; then
        local changes=0
        while IFS= read -r line; do
          local have file; have=$(echo "$line" | awk '{print $1}'); file=$(echo "$line" | awk '{print $2}')
          if [ -f "$file" ]; then
            local now; now=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            [ "$now" != "$have" ] && changes=$((changes+1))
          fi
        done <"$sumfile"
        [ "$changes" -gt 0 ] && alert WARN "Integrity changes in $p: $changes files"
      fi
      find "$p" -maxdepth 1 -type f -printf '%p\n' 2>/dev/null | head -n 200 | xargs -r sha256sum >"$sumfile" 2>/dev/null || true
    done
    write_json "${NS_LOGS}/integrity.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

_monitor_process(){
  set +e; set +o pipefail
  local interval suspicious; interval=$(awk -F': ' '/process:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 10)
  suspicious=$(awk -F'[][]' '/process:/,/\}/ { if($0 ~ /suspicious:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' '\n')
  while true; do
    monitor_enabled process || { sleep "$interval"; continue; }
    local procs; procs=$(ps aux 2>/dev/null || ps -ef 2>/dev/null || true)
    for s in $suspicious; do
      [ -z "$s" ] && continue
      if echo "$procs" | grep -Eiq "[[:space:]]$s[[:space:]]|$s$|/$s"; then
        alert WARN "Suspicious process detected: $s"
      fi
    done
    write_json "${NS_LOGS}/process.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

_monitor_userlogins(){
  set +e; set +o pipefail
  local interval; interval=$(awk -F': ' '/userlogins:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 30)
  local prev_hash=""
  while true; do
    monitor_enabled userlogins || { sleep "$interval"; continue; }
    local users; users=$(who 2>/dev/null || true)
    local cur_hash; cur_hash=$(printf '%s' "$users" | sha256sum | awk '{print $1}')
    if [ -n "$prev_hash" ] && [ "$cur_hash" != "$prev_hash" ]; then
      alert INFO "User sessions changed: $(echo "$users" | tr '\n' '; ')"
    fi
    prev_hash="$cur_hash"
    local users_json; users_json=$(printf '%s' "$users" | python3 - <<'PY'
import sys, json
print(json.dumps(sys.stdin.read()))
PY
)
    write_json "${NS_LOGS}/user.json" "{\"ts\":\"$(ns_now)\",\"who\":${users_json:-\"\"}}"
    sleep "$interval"
  done
}

_monitor_services(){
  set +e; set +o pipefail
  local interval targets; interval=$(awk -F': ' '/services:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 20)
  targets=$(awk -F'[][]' '/services:/,/\}/ { if($0 ~ /targets:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' '\n')
  while true; do
    monitor_enabled services || { sleep "$interval"; continue; }
    for svc in $targets; do
      [ -z "$svc" ] && continue
      if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$svc" 2>/dev/null || alert CRIT "Service $svc is not active!"
      else
        pgrep -f "$svc" >/dev/null 2>&1 || alert WARN "Service process not found: $svc"
      fi
    done
    write_json "${NS_LOGS}/service.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

_monitor_logs(){
  set +e; set +o pipefail
  local interval; interval=$(awk -F': ' '/logs:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 15)
  local files patterns; files=$(awk -F'[][]' '/logs:/,/\}/ { if($0 ~ /files:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' ' ')
  patterns=$(awk -F'[][]' '/logs:/,/\}/ { if($0 ~ /patterns:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' '|')
  [ -z "$patterns" ] && patterns="error|failed|denied|segfault"
  local state="${NS_CTRL}/logwatch.state"; touch "$state" || true
  while true; do
    monitor_enabled logs || { sleep "$interval"; continue; }
    for f in $files; do
      [ -f "$f" ] || continue
      local size from
      size=$(stat -c%s "$f" 2>/dev/null || wc -c <"$f" 2>/dev/null || echo 0)
      from=$(awk -v F="$f" '$1==F{print $2}' "$state" 2>/dev/null | tail -n1)
      [ -z "$from" ] && from=0
      if [ "$size" -gt "$from" ]; then
        tail -c +"$((from+1))" "$f" 2>/dev/null | grep -Eai "$patterns" | while IFS= read -r line; do
          alert WARN "Log anomaly in $(basename "$f"): $line"
        done
      fi
      if grep -q "^$f " "$state" 2>/dev/null; then
        sed -i "s|^$f .*|$f $size|" "$state" 2>/dev/null || true
      else
        echo "$f $size" >>"$state"
      fi
    done
    write_json "${NS_LOGS}/logwatch.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

_supervisor(){
  set +e; set +o pipefail
  local interval=10
  while true; do
    for p in cpu memory disk network integrity process userlogins services logs; do
      if [ -f "${NS_PID}/${p}.pid" ]; then
        local pid; pid=$(cat "${NS_PID}/${p}.pid" 2>/dev/null || echo 0)
        kill -0 "$pid" 2>/dev/null || {
          alert ERROR "Monitor $p crashed. Restarting."
          case "$p" in
            cpu) _monitor_cpu & echo $! >"${NS_PID}/${p}.pid" ;;
            memory) _monitor_mem & echo $! >"${NS_PID}/${p}.pid" ;;
            disk) _monitor_disk & echo $! >"${NS_PID}/${p}.pid" ;;
            network) _monitor_net & echo $! >"${NS_PID}/${p}.pid" ;;
            integrity) _monitor_integrity & echo $! >"${NS_PID}/${p}.pid" ;;
            process) _monitor_process & echo $! >"${NS_PID}/${p}.pid" ;;
            userlogins) _monitor_userlogins & echo $! >"${NS_PID}/${p}.pid" ;;
            services) _monitor_services & echo $! >"${NS_PID}/${p}.pid" ;;
            logs) _monitor_logs & echo $! >"${NS_PID}/${p}.pid" ;;
          esac
        }
      fi
    done
    if [ -f "${NS_PID}/web.pid" ]; then
      local wpid; wpid=$(cat "${NS_PID}/web.pid" 2>/dev/null || echo 0)
      kill -0 "$wpid" 2>/dev/null || { alert ERROR "Web server crashed. Restarting."; start_web || true; }
    fi
    sleep "$interval"
  done
}

_monitor_scheduler(){
  set +e; set +o pipefail
  local interval; interval=$(awk -F': ' '/scheduler:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 30)
  : >"$NS_SCHED_STATE" || true
  while true; do
    monitor_enabled scheduler || { sleep "$interval"; continue; }
    local now_hm; now_hm=$(date +%H:%M)
    local ran_today_key="$(date +%Y-%m-%d)"
    awk '/scheduler:/,/tasks:/{print}' "$NS_CONF" >/dev/null 2>&1 || { sleep "$interval"; continue; }
    local names; names=$(awk '/tasks:/,0{if($1=="-"){print $0}}' "$NS_CONF" 2>/dev/null || true)
    local IFS=$'\n'
    for line in $names; do
      local name action time every
      name=$(echo "$line" | awk -F'name:' '{print $2}' | awk -F'action:' '{print $1}' | tr -d '"' | tr -d ' ' || true)
      action=$(echo "$line" | awk -F'action:' '{print $2}' | awk -F'time:' '{print $1}' | awk -F'every_n_min:' '{print $1}' | tr -d '"' | tr -d ' ' || true)
      time=$(echo "$line" | awk -F'time:' '{print $2}' | awk -F',' '{print $1}' | tr -d '"' | tr -d ' ' || true)
      every=$(echo "$line" | awk -F'every_n_min:' '{print $2}' | awk -F',' '{print $1}' | tr -d '"' | tr -d ' ' || true)
      [ -z "$name" ] && continue
      if [ -n "$time" ] && [ "$time" = "$now_hm" ]; then
        if ! grep -q "^$ran_today_key $name$" "$NS_SCHED_STATE" 2>/dev/null; then
          ns_log "Scheduler running '$name' ($action at $time)"; scheduler_run_action "$action"
          echo "$ran_today_key $name" >>"$NS_SCHED_STATE"
        fi
      fi
      if [ -n "$every" ]; then
        local mod=$(( $(date +%s) / 60 % every ))
        if [ "$mod" -eq 0 ]; then
          ns_log "Scheduler running '$name' (every ${every}m: $action)"; scheduler_run_action "$action"
        fi
      fi
    done
    sleep "$interval"
  done
}

scheduler_run_action(){
  local act="$1"
  case "$act" in
    backup) backup_snapshot;;
    version) version_snapshot;;
    restart_monitors) restart_monitors;;
    *) if [ -x "${NS_MODULES}/${act}.sh" ]; then "${NS_MODULES}/${act}.sh" || alert ERROR "Module ${act} failed"; else ns_warn "Unknown scheduler action: $act"; fi ;;
  esac
}

_spawn_monitor(){ local name="$1"; shift; "$@" & echo $! > "${NS_PID}/${name}.pid"; }

start_monitors(){
  ns_log "Starting monitors..."
  stop_monitors || true
  _spawn_monitor cpu _monitor_cpu
  _spawn_monitor memory _monitor_mem
  _spawn_monitor disk _monitor_disk
  _spawn_monitor network _monitor_net
  _spawn_monitor integrity _monitor_integrity
  _spawn_monitor process _monitor_process
  _spawn_monitor userlogins _monitor_userlogins
  _spawn_monitor services _monitor_services
  _spawn_monitor logs _monitor_logs
  _spawn_monitor scheduler _monitor_scheduler
  _spawn_monitor supervisor _supervisor
  ns_ok "Monitors started"
}

stop_monitors(){
  local any=0
  for p in cpu memory disk network integrity process userlogins services logs scheduler supervisor; do
    if [ -f "${NS_PID}/${p}.pid" ]; then
      kill "$(cat "${NS_PID}/${p}.pid")" 2>/dev/null || true
      rm -f "${NS_PID}/${p}.pid"
      any=1
    fi
  done
  [ "$any" -eq 1 ] && ns_ok "Monitors stopped" || true
}

write_server_py(){
  write_file "${NS_WWW}/server.py" 700 <<'PY'
#!/usr/bin/env python3
import json, os, sys, time, hashlib, http.cookies, socket, ssl, threading, subprocess, select, struct, base64, hmac, secrets
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import socketserver

NS_HOME = os.path.expanduser('~/.novashield')
NS_WWW  = os.path.join(NS_HOME, 'www')
NS_LOGS = os.path.join(NS_HOME, 'logs')
NS_CTRL = os.path.join(NS_HOME, 'control')
NS_BIN  = os.path.join(NS_HOME, 'bin')
NS_KEYS = os.path.join(NS_HOME, 'keys')
SELF_PATH_FILE = os.path.join(NS_BIN, 'self_path')
INDEX = os.path.join(NS_WWW, 'index.html')
CONFIG = os.path.join(NS_HOME, 'config.yaml')
SESSIONS = os.path.join(NS_CTRL, 'sessions.json')
CHATLOG = os.path.join(NS_LOGS, 'chat.log')
AUDIT_LOG = os.path.join(NS_LOGS, 'audit.log')
SITE_DIR = os.path.join(NS_HOME, 'site')
RATE_LIMIT_DB = os.path.join(NS_CTRL, 'rate_limits.json')

# Global WebSocket connections tracking
terminal_connections = {}

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

def audit_log(action, user='system', details=''):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write(f"{timestamp} {user} {action} {details}\\n")
    except:
        pass

def yaml_scalar(key, default=''):
    try:
        for line in open(CONFIG,'r',encoding='utf-8'):
            s = line.split('#',1)[0].strip()
            if not s: continue
            if s.startswith(key+':'):
                return s.split(':',1)[1].strip().strip('"').strip("'")
    except Exception: pass
    return default

def yaml_flag(key, default=False):
    v = yaml_scalar(key, str(default)).lower()
    return v == 'true'

def auth_enabled():
    return yaml_flag('security.auth_enabled', False)

def totp_enabled():
    return yaml_flag('security.totp_enabled', False)

def csrf_enabled():
    return yaml_flag('security.csrf_enabled', True)

def tls_enabled():
    return yaml_flag('security.tls_enabled', False)

def rate_limit_enabled():
    return yaml_flag('security.rate_limit_enabled', True)

def auth_salt():
    return yaml_scalar('security.auth_salt', 'changeme')

def users_list():
    db = read_json(SESSIONS, {}) or {}
    return db.get('_userdb', {})

def check_login(username, password):
    salt = auth_salt()
    sha = hashlib.sha256((salt+':'+password).encode()).hexdigest()
    return users_list().get(username,'') == sha

def get_totp_secret(username):
    secret_file = os.path.join(NS_KEYS, f'totp_{username}.secret')
    try:
        with open(secret_file, 'r') as f:
            return f.read().strip()
    except:
        return None

def verify_totp(username, code):
    secret = get_totp_secret(username)
    if not secret:
        return False
    
    try:
        key = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))
        counter = int(time.time() // 30)
        
        for window in [counter, counter - 1]:
            counter_bytes = struct.pack('>Q', window)
            hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
            offset = hmac_digest[-1] & 0x0f
            totp_code = struct.unpack('>I', hmac_digest[offset:offset+4])[0] & 0x7fffffff
            totp_code = str(totp_code % 1000000).zfill(6)
            if totp_code == code:
                return True
        return False
    except:
        return False

def new_session(username):
    token = hashlib.sha256(f'{username}:{time.time()}'.encode()).hexdigest()
    db = read_json(SESSIONS, {}) or {}
    csrf_token = secrets.token_urlsafe(32) if csrf_enabled() else ''
    db[token] = {'user': username, 'ts': int(time.time()), 'csrf_token': csrf_token}
    write_json(SESSIONS, db)
    return token

def get_session(handler):
    if not auth_enabled(): 
        return {'user': 'public', 'csrf_token': ''}
    if 'Cookie' not in handler.headers: 
        return None
    C = http.cookies.SimpleCookie()
    C.load(handler.headers['Cookie'])
    if 'NSSESS' not in C: 
        return None
    token = C['NSSESS'].value
    db = read_json(SESSIONS, {}) or {}
    session = db.get(token)
    if session:
        timeout = int(yaml_scalar('security.session_timeout', '3600'))
        if int(time.time()) - session.get('ts', 0) > timeout:
            del db[token]
            write_json(SESSIONS, db)
            return None
    return session

def check_rate_limit(client_ip):
    if not rate_limit_enabled():
        return True
    
    db = read_json(RATE_LIMIT_DB, {}) or {}
    now = int(time.time())
    window = int(yaml_scalar('security.rate_limit_window', '60'))
    max_requests = int(yaml_scalar('security.rate_limit_requests', '30'))
    lockout_time = int(yaml_scalar('security.rate_limit_lockout', '300'))
    
    if client_ip not in db:
        db[client_ip] = {'requests': [], 'locked_until': 0}
    
    client_data = db[client_ip]
    
    if client_data['locked_until'] > now:
        return False
    
    client_data['requests'] = [req for req in client_data['requests'] if req > now - window]
    
    if len(client_data['requests']) >= max_requests:
        client_data['locked_until'] = now + lockout_time
        write_json(RATE_LIMIT_DB, db)
        audit_log('rate_limit_exceeded', 'system', f'IP: {client_ip}')
        return False
    
    client_data['requests'].append(now)
    write_json(RATE_LIMIT_DB, db)
    return True

def require_auth(handler):
    if not auth_enabled(): 
        return True
    sess = get_session(handler)
    if sess: 
        return True
    handler._set_headers(401)
    handler.wfile.write(b'{"error":"unauthorized"}')
    return False

def require_csrf(handler, data):
    if not csrf_enabled():
        return True
    if not auth_enabled():
        return True
    
    sess = get_session(handler)
    if not sess:
        return False
        
    csrf_token = data.get('csrf_token', '')
    if sess.get('csrf_token') != csrf_token:
        handler._set_headers(403)
        handler.wfile.write(b'{"error":"csrf_token_invalid"}')
        return False
    return True

# WebSocket handshake implementation
def websocket_handshake(handler):
    key = handler.headers.get('Sec-WebSocket-Key')
    if not key:
        return False
    
    magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()
    
    handler.send_response(101)
    handler.send_header('Upgrade', 'websocket')
    handler.send_header('Connection', 'Upgrade')
    handler.send_header('Sec-WebSocket-Accept', accept)
    handler.end_headers()
    return True

# Simple WebSocket frame handling
def send_websocket_frame(socket, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    length = len(data)
    if length < 126:
        frame = struct.pack('!BB', 0x81, length) + data
    elif length < 65536:
        frame = struct.pack('!BBH', 0x81, 126, length) + data
    else:
        frame = struct.pack('!BBQ', 0x81, 127, length) + data
    
    try:
        socket.sendall(frame)
    except:
        pass

def read_websocket_frame(socket):
    try:
        header = socket.recv(2)
        if len(header) != 2:
            return None
        
        fin = header[0] & 0x80
        opcode = header[0] & 0x0f
        masked = header[1] & 0x80
        length = header[1] & 0x7f
        
        if length == 126:
            length = struct.unpack('!H', socket.recv(2))[0]
        elif length == 127:
            length = struct.unpack('!Q', socket.recv(8))[0]
        
        if masked:
            mask = socket.recv(4)
            data = socket.recv(length)
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        else:
            data = socket.recv(length)
        
        return data.decode('utf-8') if opcode == 1 else data
    except:
        return None

def handle_terminal_websocket(handler):
    if not yaml_flag('terminal.enabled', True):
        handler._set_headers(403)
        handler.wfile.write(b'{"error":"terminal_disabled"}')
        return
    
    # Check authentication
    if not require_auth(handler):
        return
    
    # Perform WebSocket handshake
    if not websocket_handshake(handler):
        return
    
    # Get session info
    session = get_session(handler)
    user = session.get('user', 'anonymous') if session else 'anonymous'
    
    # Start PTY
    shell = yaml_scalar('terminal.shell', '/bin/bash')
    work_dir = os.path.join(NS_HOME, yaml_scalar('terminal.working_directory', 'projects'))
    
    try:
        os.makedirs(work_dir, exist_ok=True)
        import pty
        master, slave = pty.openpty()
        
        proc = subprocess.Popen([shell], 
                              stdin=slave, 
                              stdout=slave, 
                              stderr=slave,
                              cwd=work_dir,
                              preexec_fn=os.setsid)
        
        os.close(slave)
        
        # Track connection
        conn_id = len(terminal_connections)
        terminal_connections[conn_id] = {
            'master': master,
            'proc': proc,
            'user': user,
            'start_time': time.time()
        }
        
        audit_log('terminal_connect', user, f'connection_id: {conn_id}')
        
        # Handle WebSocket communication
        socket_fd = handler.connection.fileno()
        
        while True:
            ready, _, _ = select.select([master, socket_fd], [], [], 1.0)
            
            if master in ready:
                try:
                    data = os.read(master, 1024)
                    if data:
                        send_websocket_frame(handler.connection, data.decode('utf-8', errors='replace'))
                except:
                    break
            
            if socket_fd in ready:
                frame_data = read_websocket_frame(handler.connection)
                if frame_data is None:
                    break
                
                if frame_data:
                    try:
                        os.write(master, frame_data.encode('utf-8'))
                    except:
                        break
            
            # Check if process is still alive
            if proc.poll() is not None:
                break
        
        # Cleanup
        try:
            proc.terminate()
            os.close(master)
        except:
            pass
        
        if conn_id in terminal_connections:
            del terminal_connections[conn_id]
        
        audit_log('terminal_disconnect', user, f'connection_id: {conn_id}')
        
    except Exception as e:
        audit_log('terminal_error', user, str(e))

# File Manager API
def handle_file_api(handler, parsed, body):
    if not yaml_flag('file_manager.enabled', True):
        handler._set_headers(403)
        handler.wfile.write(b'{"error":"file_manager_disabled"}')
        return
    
    if not require_auth(handler):
        return
    
    try:
        data = json.loads(body or '{}')
    except:
        data = {}
    
    if not require_csrf(handler, data):
        return
    
    session = get_session(handler)
    user = session.get('user', 'anonymous') if session else 'anonymous'
    
    # Sandbox to .novashield directory
    sandbox_root = os.path.join(NS_HOME, yaml_scalar('file_manager.sandbox_root', '.'))
    
    action = parsed.path.split('/')[-1]  # /api/file/list -> list
    
    if action == 'list':
        path = data.get('path', '')
        full_path = os.path.abspath(os.path.join(sandbox_root, path.lstrip('/')))
        
        # Security check - ensure within sandbox
        if not full_path.startswith(sandbox_root):
            handler._set_headers(403)
            handler.wfile.write(b'{"error":"access_denied"}')
            return
        
        try:
            if os.path.isdir(full_path):
                entries = []
                for entry in os.listdir(full_path):
                    entry_path = os.path.join(full_path, entry)
                    stat = os.stat(entry_path)
                    entries.append({
                        'name': entry,
                        'is_dir': os.path.isdir(entry_path),
                        'size': stat.st_size,
                        'modified': stat.st_mtime
                    })
                handler._set_headers(200)
                handler.wfile.write(json.dumps({'ok': True, 'entries': entries}).encode())
                audit_log('file_list', user, f'path: {path}')
            else:
                handler._set_headers(404)
                handler.wfile.write(b'{"error":"directory_not_found"}')
        except Exception as e:
            handler._set_headers(500)
            handler.wfile.write(json.dumps({'error': str(e)}).encode())
    
    elif action == 'read':
        path = data.get('path', '')
        full_path = os.path.abspath(os.path.join(sandbox_root, path.lstrip('/')))
        
        if not full_path.startswith(sandbox_root):
            handler._set_headers(403)
            handler.wfile.write(b'{"error":"access_denied"}')
            return
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            handler._set_headers(200)
            handler.wfile.write(json.dumps({'ok': True, 'content': content}).encode())
            audit_log('file_read', user, f'path: {path}')
        except Exception as e:
            handler._set_headers(500)
            handler.wfile.write(json.dumps({'error': str(e)}).encode())
    
    elif action == 'write':
        path = data.get('path', '')
        content = data.get('content', '')
        full_path = os.path.abspath(os.path.join(sandbox_root, path.lstrip('/')))
        
        if not full_path.startswith(sandbox_root):
            handler._set_headers(403)
            handler.wfile.write(b'{"error":"access_denied"}')
            return
        
        # Check file size limit
        max_size = int(yaml_scalar('file_manager.max_file_size', '10485760'))
        if len(content.encode('utf-8')) > max_size:
            handler._set_headers(413)
            handler.wfile.write(b'{"error":"file_too_large"}')
            return
        
        try:
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            handler._set_headers(200)
            handler.wfile.write(b'{"ok":true}')
            audit_log('file_write', user, f'path: {path}')
        except Exception as e:
            handler._set_headers(500)
            handler.wfile.write(json.dumps({'error': str(e)}).encode())
    
    elif action == 'mkdir':
        path = data.get('path', '')
        full_path = os.path.abspath(os.path.join(sandbox_root, path.lstrip('/')))
        
        if not full_path.startswith(sandbox_root):
            handler._set_headers(403)
            handler.wfile.write(b'{"error":"access_denied"}')
            return
        
        try:
            os.makedirs(full_path, exist_ok=True)
            handler._set_headers(200)
            handler.wfile.write(b'{"ok":true}')
            audit_log('file_mkdir', user, f'path: {path}')
        except Exception as e:
            handler._set_headers(500)
            handler.wfile.write(json.dumps({'error': str(e)}).encode())
    
    elif action == 'delete':
        path = data.get('path', '')
        full_path = os.path.abspath(os.path.join(sandbox_root, path.lstrip('/')))
        
        if not full_path.startswith(sandbox_root):
            handler._set_headers(403)
            handler.wfile.write(b'{"error":"access_denied"}')
            return
        
        try:
            if os.path.isdir(full_path):
                os.rmdir(full_path)
            else:
                os.remove(full_path)
            handler._set_headers(200)
            handler.wfile.write(b'{"ok":true}')
            audit_log('file_delete', user, f'path: {path}')
        except Exception as e:
            handler._set_headers(500)
            handler.wfile.write(json.dumps({'error': str(e)}).encode())
    
    else:
        handler._set_headers(404)
        handler.wfile.write(b'{"error":"unknown_action"}')

def last_lines(path, n=100):
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END); size=f.tell(); block=1024; data=b''
            while size>0 and n>0:
                step=min(block,size); size-=step; f.seek(size); buf=f.read(step); data=buf+data; n-=buf.count(b'\\n')
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
        os.system(f'\\"{read_text(SELF_PATH_FILE).strip()}\\" --backup >/dev/null 2>&1 &')
        return "Acknowledged. Snapshot backup started."
    if 'version' in prompt_low or 'snapshot' in prompt_low:
        os.system(f'\\"{read_text(SELF_PATH_FILE).strip()}\\" --version-snapshot >/dev/null 2>&1 &')
        return "Version snapshot underway."
    if 'restart monitor' in prompt_low:
        os.system(f'\\"{read_text(SELF_PATH_FILE).strip()}\\" --restart-monitors >/dev/null 2>&1 &')
        return "Restarting monitors."
    if 'ip' in prompt_low:
        return f"Internal IP {status['net'].get('ip','?')} | Public {status['net'].get('public_ip','?')}."
    return f"I can do status, backup, version snapshot, and restart monitors. You said: {prompt}"

class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, ctype='application/json', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        
        # Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        
        if csrf_enabled():
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
        
        if extra_headers:
            for k,v in (extra_headers or {}).items(): 
                self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        # Rate limiting and IP filtering
        client_ip = self.client_address[0]
        if not check_rate_limit(client_ip):
            self._set_headers(429)
            self.wfile.write(b'{"error":"rate_limit_exceeded"}')
            return
        
        parsed = urlparse(self.path)
        
        # WebSocket upgrade for terminal
        if parsed.path == '/ws/term':
            handle_terminal_websocket(self)
            return
        
        if parsed.path == '/':
            self._set_headers(200, 'text/html; charset=utf-8')
            html = read_text(INDEX, '<h1>NovaShield</h1>')
            self.wfile.write(html.encode('utf-8')); return
        
        if parsed.path.startswith('/static/'):
            p = os.path.join(NS_WWW, parsed.path[len('/static/'):])
            if not os.path.abspath(p).startswith(NS_WWW): 
                self._set_headers(404); self.wfile.write(b'{}'); return
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
                'cpu': read_json(os.path.join(NS_LOGS,'cpu.json'),{}),
                'memory': read_json(os.path.join(NS_LOGS,'memory.json'),{}),
                'disk': read_json(os.path.join(NS_LOGS,'disk.json'),{}),
                'network': read_json(os.path.join(NS_LOGS,'network.json'),{}),
                'alerts': last_lines(os.path.join(NS_LOGS,'alerts.log'), 50),
                'version': '3.1.0'
            }
            self._set_headers(200); self.wfile.write(json.dumps(data).encode('utf-8')); return
        
        if parsed.path == '/api/config':
            if not require_auth(self): return
            conf = read_text(CONFIG, 'version: "3.1.0"')
            self._set_headers(200, 'text/plain'); self.wfile.write(conf.encode('utf-8')); return
        
        if parsed.path.startswith('/api/file/'):
            handle_file_api(self, parsed, '')
            return
        
        if parsed.path.startswith('/site/'):
            p = parsed.path[len('/site/'):]
            full = os.path.join(SITE_DIR, p)
            if not os.path.abspath(full).startswith(SITE_DIR): 
                self._set_headers(403); self.wfile.write(b'{}'); return
            if os.path.exists(full):
                self._set_headers(200, 'text/html; charset=utf-8'); self.wfile.write(read_text(full).encode('utf-8')); return
            self._set_headers(404); self.wfile.write(b'{}'); return
        
        self._set_headers(404); self.wfile.write(b'{"error":"not found"}')

    def do_POST(self):
        # Rate limiting
        client_ip = self.client_address[0]
        if not check_rate_limit(client_ip):
            self._set_headers(429)
            self.wfile.write(b'{"error":"rate_limit_exceeded"}')
            return
        
        parsed = urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''
        
        if parsed.path == '/api/login':
            try: 
                data = json.loads(body or '{}')
                user = data.get('user')
                pwd = data.get('pass')
                totp_code = data.get('totp', '')
            except Exception: 
                data = {}
                user = ''
                pwd = ''
                totp_code = ''
            
            if auth_enabled() and check_login(user, pwd):
                # Check TOTP if enabled
                if totp_enabled() and get_totp_secret(user):
                    if not totp_code or not verify_totp(user, totp_code):
                        self._set_headers(401)
                        self.wfile.write(b'{"ok":false,"totp_required":true}')
                        audit_log('login_failed_totp', user, 'TOTP verification failed')
                        return
                
                tok = new_session(user)
                self._set_headers(200, 'application/json', {'Set-Cookie': f'NSSESS={tok}; Path=/; HttpOnly'})
                self.wfile.write(b'{"ok":true}')
                audit_log('login_success', user, 'successful authentication')
                return
            
            self._set_headers(401)
            self.wfile.write(b'{"ok":false}')
            audit_log('login_failed', user or 'unknown', 'invalid credentials')
            return
        
        if parsed.path == '/api/control':
            if not require_auth(self): return
            try: data = json.loads(body or '{}')
            except Exception: data={}
            
            if not require_csrf(self, data): return
            
            session = get_session(self)
            user = session.get('user', 'anonymous') if session else 'anonymous'
            
            action = data.get('action','')
            target = data.get('target','')
            flag = os.path.join(NS_CTRL, f'{target}.disabled')
            
            if action == 'enable' and target:
                try: 
                    if os.path.exists(flag): os.remove(flag)
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8'))
                    audit_log('control_enable', user, f'target: {target}')
                    return
                except Exception: pass
            
            if action == 'disable' and target:
                try: 
                    Path(flag).touch()
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8'))
                    audit_log('control_disable', user, f'target: {target}')
                    return
                except Exception: pass
            
            self._set_headers(400); self.wfile.write(b'{"ok":false}'); return
        
        if parsed.path.startswith('/api/file/'):
            handle_file_api(self, parsed, body)
            return
        
        if parsed.path == '/api/ai':
            if not require_auth(self): return
            try: data = json.loads(body or '{}')
            except Exception: data={}
            
            if not require_csrf(self, data): return
            
            session = get_session(self)
            user = session.get('user', 'anonymous') if session else 'anonymous'
            
            prompt = data.get('prompt','')
            reply = ai_reply(prompt)
            try: 
                open(CHATLOG,'a',encoding='utf-8').write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} Q:{prompt} A:{reply}\\n')
            except Exception: pass
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'reply':reply}).encode('utf-8'))
            audit_log('ai_query', user, f'prompt: {prompt[:50]}...')
            return
        
        if parsed.path == '/api/webgen':
            if not require_auth(self): return
            try: data = json.loads(body or '{}')
            except Exception: data={}
            
            if not require_csrf(self, data): return
            
            session = get_session(self)
            user = session.get('user', 'anonymous') if session else 'anonymous'
            
            title = data.get('title','Untitled')
            content = data.get('content','')
            slug = ''.join([c.lower() if c.isalnum() else '-' for c in title]).strip('-') or f'page-{int(time.time())}'
            Path(SITE_DIR).mkdir(parents=True, exist_ok=True)
            
            html = f'''<!DOCTYPE html>
<html><head><title>{title}</title><style>body{{font-family:Arial,sans-serif;margin:40px;}}</style></head>
<body><h1>{title}</h1><div>{content}</div></body></html>'''
            
            write_text(os.path.join(SITE_DIR, f'{slug}.html'), html)
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'url':f'/site/{slug}.html'}).encode('utf-8'))
            audit_log('webgen_create', user, f'title: {title}')
            return
        
        self._set_headers(400); self.wfile.write(b'{"ok":false}')

def pick_host_port():
    host = '127.0.0.1'; port = 8765
    try:
        h = None; p = None
        for line in open(CONFIG,'r',encoding='utf-8'):
            s=line.split('#',1)[0].strip()
            if not s: continue
            if s.startswith('web.host:') or (s.startswith('host:') and 'http:' not in s):
                h = s.split(':',1)[1].strip().strip('"').strip("'")
            if s.startswith('web.port:') or (s.startswith('port:') and 'http:' not in s):
                try: p = int(s.split(':',1)[1].strip())
                except: pass
            if s.startswith('web.allow_lan:') or (s.startswith('allow_lan:') and 'true' in s):
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

def create_ssl_context():
    if not tls_enabled():
        return None
    
    cert_file = os.path.join(NS_HOME, yaml_scalar('security.cert_file', 'keys/certs/server.crt'))
    key_file = os.path.join(NS_HOME, yaml_scalar('security.key_file', 'keys/certs/server.key'))
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        return None
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        return context
    except:
        return None

if __name__ == '__main__':
    host, port = pick_host_port()
    os.chdir(NS_WWW)
    
    ssl_context = create_ssl_context()
    protocol = 'https' if ssl_context else 'http'
    
    for h in (host, '127.0.0.1', '0.0.0.0'):
        try:
            httpd = ThreadingHTTPServer((h, port), Handler)
            if ssl_context:
                httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
            print(f"NovaShield Web Server on {protocol}://{h}:{port}")
            httpd.serve_forever()
        except Exception as e:
            print(f"Bind failed on {h}:{port}: {e}", file=sys.stderr)
            time.sleep(0.5)
            continue
PY
  chmod 700 "${NS_WWW}/server.py"
}

write_dashboard(){
  write_file "${NS_WWW}/index.html" 644 <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NovaShield — JARVIS Edition</title>
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
  <header>
    <div class="brand">
      <div class="ring"></div>
      <h1>NovaShield <span class="mini">JARVIS</span></h1>
      <div class="by">by niteas aka MrNova420</div>
    </div>
    <div class="actions">
      <button id="btn-refresh">Refresh</button>
      <button data-act="backup">Backup</button>
      <button data-act="version">Snapshot</button>
      <button data-act="restart_monitors">Restart Monitors</button>
    </div>
  </header>

  <nav class="tabs">
    <button data-tab="status" class="active">Status</button>
    <button data-tab="terminal">Terminal</button>
    <button data-tab="files">Files</button>
    <button data-tab="alerts">Alerts</button>
    <button data-tab="ai">Jarvis</button>
    <button data-tab="webgen">Web Builder</button>
    <button data-tab="config">Config</button>
  </nav>

  <main>
    <section id="tab-status" class="tab active">
      <section class="grid">
        <div class="card" id="card-cpu"><h2>CPU</h2><pre class="value" id="cpu"></pre></div>
        <div class="card" id="card-mem"><h2>Memory</h2><pre class="value" id="mem"></pre></div>
        <div class="card" id="card-disk"><h2>Disk</h2><pre class="value" id="disk"></pre></div>
        <div class="card" id="card-net"><h2>Network</h2><pre class="value" id="net"></pre></div>
        <div class="card" id="card-int"><h2>Integrity</h2><pre class="value" id="int"></pre></div>
        <div class="card" id="card-proc"><h2>Processes</h2><pre class="value" id="proc"></pre></div>
        <div class="card" id="card-user"><h2>Users</h2><pre class="value" id="user"></pre></div>
        <div class="card" id="card-svc"><h2>Services</h2><pre class="value" id="svc"></pre></div>
        <div class="card" id="card-meta"><h2>Meta</h2><pre class="value" id="meta"></pre></div>
      </section>
      <div class="panel">
        <h3>Monitors Control</h3>
        <div class="toggles">
          <button class="toggle" data-target="cpu">CPU</button>
          <button class="toggle" data-target="memory">Memory</button>
          <button class="toggle" data-target="disk">Disk</button>
          <button class="toggle" data-target="network">Network</button>
          <button class="toggle" data-target="integrity">Integrity</button>
          <button class="toggle" data-target="process">Process</button>
          <button class="toggle" data-target="userlogins">Users</button>
          <button class="toggle" data-target="services">Services</button>
          <button class="toggle" data-target="logs">Logs</button>
          <button class="toggle" data-target="scheduler">Scheduler</button>
        </div>
      </div>
    </section>

    <section id="tab-terminal" class="tab">
      <div class="terminal-container">
        <div class="terminal-header">
          <h3>NovaShield Terminal</h3>
          <div class="terminal-controls">
            <button id="terminal-connect">Connect</button>
            <button id="terminal-disconnect" disabled>Disconnect</button>
            <button id="terminal-clear">Clear</button>
          </div>
        </div>
        <div id="terminal" class="terminal-output"></div>
        <div class="terminal-input-container">
          <input type="text" id="terminal-input" placeholder="Type commands here..." disabled>
        </div>
      </div>
    </section>

    <section id="tab-alerts" class="tab">
      <div class="panel">
        <h3>Alerts</h3>
        <ul id="alerts"></ul>
      </div>
    </section>

    <section id="tab-files" class="tab">
      <div class="panel">
        <h3>File Manager <span class="version">v3.1.0</span></h3>
        <div class="filebar">
          <input id="file-path" value="/" placeholder="Current path" />
          <button id="btn-refresh-files">Refresh</button>
          <button id="btn-new-file">New File</button>
          <button id="btn-new-folder">New Folder</button>
          <button id="btn-upload">Upload</button>
        </div>
        <div class="file-browser">
          <div id="file-list" class="file-list"></div>
        </div>
        <div class="file-editor" id="file-editor" style="display:none;">
          <div class="editor-header">
            <span id="editing-file">No file selected</span>
            <div class="editor-controls">
              <button id="btn-save-file">Save</button>
              <button id="btn-close-editor">Close</button>
            </div>
          </div>
          <textarea id="file-content" placeholder="File content..."></textarea>
        </div>
      </div>
    </section>

    <section id="tab-ai" class="tab">
      <div class="panel">
        <h3>Jarvis Assistant</h3>
        <div id="chat">
          <div id="chatlog"></div>
          <div class="chatbox">
            <input id="prompt" placeholder="Ask Jarvis... try: status, backup, IP" />
            <button id="send">Send</button>
          </div>
        </div>
      </div>
    </section>

    <section id="tab-webgen" class="tab">
      <div class="panel">
        <h3>Webpage Builder</h3>
        <input id="wtitle" placeholder="Page title" />
        <textarea id="wcontent" placeholder="HTML content"></textarea>
        <button id="wmake">Create Page</button>
        <div id="wresult"></div>
      </div>
    </section>

    <section id="tab-config" class="tab">
      <div class="panel">
        <h3>Config (read-only here)</h3>
        <pre id="config"></pre>
      </div>
    </section>
  </main>

  <!-- Login Overlay for Authentication -->
  <div id="login-overlay" class="login-overlay" style="display:none;">
    <div class="login-modal">
      <div class="login-header">
        <h2>NovaShield Login</h2>
        <div class="version-badge">v3.1.0</div>
      </div>
      <form id="login-form">
        <div class="form-group">
          <label for="login-username">Username:</label>
          <input type="text" id="login-username" required>
        </div>
        <div class="form-group">
          <label for="login-password">Password:</label>
          <input type="password" id="login-password" required>
        </div>
        <div class="form-group" id="totp-group" style="display:none;">
          <label for="login-totp">2FA Code:</label>
          <input type="text" id="login-totp" placeholder="6-digit code">
        </div>
        <div class="form-actions">
          <button type="submit" id="login-submit">Login</button>
        </div>
        <div id="login-error" class="error-message" style="display:none;"></div>
      </form>
    </div>
  </div>

  <script src="/static/app.js"></script>
</body>
</html>
HTML

  write_file "${NS_WWW}/style.css" 644 <<'CSS'
:root { --bg:#050b12; --card:#0e1726; --text:#d7e3ff; --muted:#93a3c0; --ok:#10b981; --warn:#f59e0b; --crit:#ef4444; --accent:#00d0ff; --ring:#00ffe1;}
*{box-sizing:border-box} body{margin:0;background:radial-gradient(1200px 600px at 10% -20%,rgba(0,208,255,.12),transparent),linear-gradient(180deg,#03060c,#0a1220);color:var(--text);font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid #0e223a;background:linear-gradient(180deg,rgba(0,208,255,.06),transparent)}
.brand{display:flex;align-items:center;gap:12px}
.brand h1{margin:0;font-size:20px;letter-spacing:.6px}
.brand .mini{color:var(--accent);font-weight:700;margin-left:6px}
.by{font-size:12px;color:var(--muted)}
.ring{width:20px;height:20px;border-radius:50%;box-shadow:0 0 0 3px rgba(0,255,225,.3),inset 0 0 0 2px rgba(0,255,225,.6),0 0 18px 2px rgba(0,255,225,.4)}
.actions button{background:#091425;color:#fff;border:1px solid #143055;border-radius:10px;padding:8px 12px;margin-left:8px;cursor:pointer}
.tabs{display:flex;gap:8px;padding:8px 16px;border-bottom:1px solid #0e223a;background:rgba(0,12,24,.4)}
.tabs button{background:#0a1426;border:1px solid #173764;border-radius:8px;color:#cfe6ff;padding:8px 10px;cursor:pointer}
.tabs button.active{outline:2px solid var(--accent); color:#fff}
main{padding:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:var(--card);border:1px solid #112540;border-radius:14px;padding:12px;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.card h2{margin:0 0 8px 0;font-size:16px;color:#d1eaff}
.value{margin:0;font-size:13px;color:#cbd5e1;white-space:pre-wrap}
.panel{background:var(--card);border:1px solid #112540;border-radius:14px;padding:12px;margin-top:14px}
.panel h3{margin:0 0 8px 0;color:#d1eaff}
#alerts{list-style:none;margin:0;padding:0;max-height:360px;overflow:auto}
#alerts li{font-size:12px;border-bottom:1px solid #10233e;padding:6px 0;color:#e5e7eb}
.toggle{background:#081326;border:1px solid #15345f;border-radius:10px;color:#fff;padding:8px 10px;margin:4px;cursor:pointer}
.ok{outline:2px solid var(--ok)} .warn{outline:2px solid var(--warn)} .crit{outline:2px solid var(--crit)}
#chat{display:flex;flex-direction:column;gap:8px} #chatlog{height:220px;overflow:auto;border:1px solid #143055;border-radius:8px;padding:8px;background:#091425}
.chatbox{display:flex;gap:8px} .chatbox input{flex:1;padding:8px;border-radius:8px;border:1px solid #143055;background:#0b1830;color:#d7e3ff}
.filebar{display:flex;gap:8px;margin-bottom:8px} .filebar input{flex:1;padding:8px;border-radius:8px;border:1px solid #143055;background:#0b1830;color:#d7e3ff}
#filelist{font-size:13px;white-space:pre-wrap;background:#081426;border:1px solid #143055;border-radius:8px;padding:8px}
textarea#wcontent{width:100%;height:160px;background:#0b1830;color:#d7e3ff;border:1px solid #143055;border-radius:8px;padding:8px}

/* Terminal Styles */
.terminal-container{display:flex;flex-direction:column;height:600px}
.terminal-header{display:flex;justify-content:space-between;align-items:center;padding:8px;background:#081426;border:1px solid #143055;border-radius:8px 8px 0 0}
.terminal-controls{display:flex;gap:8px}
.terminal-controls button{background:#091425;color:#fff;border:1px solid #143055;border-radius:6px;padding:6px 10px;cursor:pointer}
.terminal-output{flex:1;background:#000;color:#00ff00;font-family:monospace;font-size:14px;padding:8px;overflow-y:auto;border:1px solid #143055;white-space:pre-wrap}
.terminal-input-container{display:flex;padding:8px;background:#081426;border:1px solid #143055;border-radius:0 0 8px 8px}
#terminal-input{flex:1;background:#000;color:#00ff00;border:none;padding:8px;font-family:monospace;outline:none}

/* Enhanced File Manager Styles */
.file-browser{margin-bottom:16px}
.file-list{background:#081426;border:1px solid #143055;border-radius:8px;max-height:300px;overflow-y:auto}
.file-item{display:flex;align-items:center;padding:8px;border-bottom:1px solid #10233e;cursor:pointer}
.file-item:hover{background:#0a1528}
.file-item.directory{color:#00d0ff}
.file-item.file{color:#d7e3ff}
.file-icon{width:20px;margin-right:8px}
.file-name{flex:1}
.file-size{color:#93a3c0;font-size:12px;margin-left:8px}
.file-editor{margin-top:16px;border:1px solid #143055;border-radius:8px}
.editor-header{display:flex;justify-content:space-between;align-items:center;padding:8px;background:#081426;border-bottom:1px solid #143055}
.editor-controls{display:flex;gap:8px}
#file-content{width:100%;height:300px;background:#000;color:#d7e3ff;border:none;padding:8px;font-family:monospace;resize:vertical}

/* Login Overlay Styles */
.login-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:1000}
.login-modal{background:var(--card);border:1px solid #143055;border-radius:12px;padding:24px;width:400px;max-width:90vw}
.login-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.login-header h2{margin:0;color:#d1eaff}
.version-badge{background:var(--accent);color:#000;padding:4px 8px;border-radius:6px;font-size:12px;font-weight:bold}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:4px;color:#d1eaff;font-size:14px}
.form-group input{width:100%;padding:8px;background:#081426;color:#d7e3ff;border:1px solid #143055;border-radius:6px}
.form-actions{margin-top:20px}
.form-actions button{width:100%;padding:10px;background:var(--accent);color:#000;border:none;border-radius:6px;font-weight:bold;cursor:pointer}
.error-message{color:var(--crit);font-size:14px;margin-top:8px;padding:8px;background:rgba(239,68,68,0.1);border-radius:6px}

@media (max-width:980px){ .grid{grid-template-columns:1fr} }
CSS

  write_file "${NS_WWW}/app.js" 644 <<'JS'
const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));
const tabs = $$('.tabs button');
tabs.forEach(b=>b.onclick=()=>{ tabs.forEach(x=>x.classList.remove('active')); b.classList.add('active'); $$('.tab').forEach(x=>x.classList.remove('active')); $('#tab-'+b.dataset.tab).classList.add('active'); });
$('#btn-refresh').onclick = refresh;

async function api(path, opts){ const r = await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}},opts||{})); if(!r.ok){ throw new Error('API error'); } return r; }

async function refresh(){
  try{
    const r = await api('/api/status'); const j = await r.json();
    $('#cpu').textContent = JSON.stringify(j.cpu,null,2);
    $('#mem').textContent = JSON.stringify(j.memory,null,2);
    $('#disk').textContent = JSON.stringify(j.disk,null,2);
    $('#net').textContent = JSON.stringify(j.network,null,2);
    $('#int').textContent = JSON.stringify(j.integrity,null,2);
    $('#proc').textContent = JSON.stringify(j.process,null,2);
    $('#user').textContent = JSON.stringify(j.user,null,2);
    $('#svc').textContent = JSON.stringify(j.services,null,2);
    $('#meta').textContent = JSON.stringify({projects:j.projects_count,modules:j.modules_count,version:j.version,ts:j.ts},null,2);
    const ul = $('#alerts'); ul.innerHTML='';
    (j.alerts||[]).slice(-200).reverse().forEach(line=>{ const li=document.createElement('li'); li.textContent=line; ul.appendChild(li);});
    const levels = {cpu:j.cpu?.level, memory:j.memory?.level, disk:j.disk?.level, network:j.network?.level};
    const map = {OK:'ok', WARN:'warn', CRIT:'crit'};
    Object.entries(levels).forEach(([k,v])=>{
      const ids = {memory:'mem', disk:'disk', network:'net', cpu:'cpu'};
      const el = $('#card-'+(ids[k]||k));
      if(!el) return; el.classList.remove('ok','warn','crit'); if(map[v]) el.classList.add(map[v]);
    });
    const conf = await (await api('/api/config')).text(); $('#config').textContent = conf;
  }catch(e){ console.error(e); }
}

async function post(action,target){ try{ await api('/api/control',{method:'POST',body:JSON.stringify({action,target})}); }catch(e){} }

$$('.toggle').forEach(b=>{
  b.onclick=async()=>{
    const t=b.dataset.target;
    try{ await post('disable',t); await post('enable',t); refresh(); }catch(e){}
  };
});

$('#btn-list').onclick=async()=>{
  const dir = $('#cwd').value.replace('~',''+(window.homedir||''));
  try{
    const j = await (await api('/api/fs?dir='+encodeURIComponent(dir))).json();
    $('#cwd').value = j.dir;
    $('#filelist').textContent = j.entries.map(e=> (e.is_dir?'[D] ':'[F] ')+e.name+(e.size?(' ('+e.size+'b)'):'') ).join('\n');
  }catch(e){ console.error(e); }
};

$('#send').onclick=async()=>{
  const prompt = $('#prompt').value.trim(); if(!prompt) return;
  const log = $('#chatlog'); const you = document.createElement('div'); you.textContent='You: '+prompt; log.appendChild(you);
  try{
    const j = await (await api('/api/chat',{method:'POST',body:JSON.stringify({prompt})})).json();
    const ai = document.createElement('div'); ai.textContent='Jarvis: '+j.reply; log.appendChild(ai); $('#prompt').value=''; log.scrollTop=log.scrollHeight;
  }catch(e){ console.error(e); }
};

$('#wmake').onclick=async()=>{
  const title = $('#wtitle').value.trim() || 'Untitled';
  const content = $('#wcontent').value.trim() || '<p>Hello</p>';
  try{
    const j = await (await api('/api/webgen',{method:'POST',body:JSON.stringify({title,content})})).json();
    $('#wresult').textContent = 'Created: '+j.page+' (visit: /site)';
  }catch(e){ console.error(e); }
};

refresh(); setInterval(refresh, 5000);
JS
}

setup_termux_service(){
  if ! command -v sv-enable >/dev/null 2>&1; then return 0; fi
  local svcdir="${HOME}/.termux/services/novashield"
  mkdir -p "$svcdir"
  write_file "$svcdir/run" 700 <<RUN
#!/data/data/com.termux/files/usr/bin/sh
exec python3 "${NS_WWW}/server.py" >>"${NS_HOME}/web.log" 2>&1
RUN
  sv-enable novashield || ns_warn "termux-services enable failed (non-blocking)"
  ns_ok "Termux service installed: sv-enable novashield"
}

setup_systemd_user(){
  if ! command -v systemctl >/dev/null 2>&1; then return 0; fi
  local udir="${HOME}/.config/systemd/user"; mkdir -p "$udir"
  write_file "$udir/novashield.service" 644 <<SERVICE
[Unit]
Description=NovaShield Web Server (User)
After=default.target

[Service]
Type=simple
ExecStart=${NS_WWW}/server.py
WorkingDirectory=${NS_WWW}
Restart=on-failure

[Install]
WantedBy=default.target
SERVICE
  systemctl --user daemon-reload || true
  ns_ok "systemd user service written. Enable with: systemctl --user enable --now novashield"
}

start_web(){
  ns_log "Starting web server..."
  stop_web || true
  python3 "${NS_WWW}/server.py" &
  echo $! >"${NS_PID}/web.pid"
  ns_ok "Web server started (PID $(cat "${NS_PID}/web.pid"))"
}

stop_web(){
  if [ -f "${NS_PID}/web.pid" ]; then
    kill "$(cat "${NS_PID}/web.pid")" 2>/dev/null || true
    rm -f "${NS_PID}/web.pid"
    ns_ok "Web server stopped"
  fi
}

open_session(){ echo "$(ns_now) START ${NS_VERSION}" >>"$NS_SESSION"; }
close_session(){ echo "$(ns_now) STOP" >>"$NS_SESSION"; }

install_all(){
  ensure_dirs
  install_dependencies
  write_default_config
  generate_keys
  generate_self_signed_cert
  write_notify_py
  write_server_py
  write_dashboard
  setup_termux_service || true
  setup_systemd_user || true
  ns_ok "Install complete. Use: $0 --start"
}

start_all(){
  ensure_dirs; write_default_config; generate_keys; generate_self_signed_cert; write_notify_py; write_server_py; write_dashboard
  open_session
  start_monitors
  start_web
  ns_ok "NovaShield v3.1.0 is running. Open the dashboard in your browser."
}

stop_all(){
  stop_monitors || true
  stop_web || true
  close_session
}

restart_monitors(){ stop_monitors || true; start_monitors; }

add_user(){
  local user pass salt
  read -rp "New username: " user
  read -rsp "Password (won't echo): " pass; echo
  salt=$(awk -F': ' '/auth_salt:/ {print $2}' "$NS_CONF" | tr -d ' "')
  [ -z "$salt" ] && salt="change-this-salt"
  local sha; sha=$(printf '%s' "${salt}:${pass}" | sha256sum | awk '{print $1}')
  if [ ! -f "$NS_SESS_DB" ]; then echo '{}' >"$NS_SESS_DB"; fi
  python3 - "$NS_SESS_DB" "$user" "$sha" <<'PY'
import json,sys
p,u,s=sys.argv[1],sys.argv[2],sys.argv[3]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{})
ud[u]=s
j['_userdb']=ud
open(p,'w').write(json.dumps(j))
print('User stored')
PY
  ns_ok "User '$user' added. Enable auth by setting security.auth_enabled: true in config.yaml"
  audit_log "add_user" "$user" "user account created"
}

enable_2fa(){
  local user
  read -rp "Username for 2FA enrollment: " user
  
  # Check if user exists
  if [ ! -f "$NS_SESS_DB" ]; then
    ns_err "No users found. Add a user first with --add-user"
    return 1
  fi
  
  local user_exists
  user_exists=$(python3 - "$NS_SESS_DB" "$user" <<'PY'
import json,sys
try:
    j=json.load(open(sys.argv[1]))
    ud=j.get('_userdb',{})
    if sys.argv[2] in ud:
        print("yes")
    else:
        print("no")
except:
    print("no")
PY
)
  
  if [ "$user_exists" != "yes" ]; then
    ns_err "User '$user' not found. Add user first with --add-user"
    return 1
  fi
  
  # Generate TOTP secret
  generate_totp_secret "$user"
  local secret; secret=$(get_totp_secret "$user")
  
  if [ -z "$secret" ]; then
    ns_err "Failed to generate TOTP secret"
    return 1
  fi
  
  # Generate QR code URL for user
  local issuer="NovaShield"
  local qr_url="otpauth://totp/${issuer}:${user}?secret=${secret}&issuer=${issuer}"
  
  ns_ok "TOTP enrollment for user '$user'"
  echo ""
  echo "Secret: $secret"
  echo ""
  echo "Scan this QR code with your authenticator app:"
  echo "$qr_url"
  echo ""
  echo "Or enter the secret manually in your authenticator app."
  echo ""
  echo "After setup, enable TOTP by setting security.totp_enabled: true in config.yaml"
  
  audit_log "enable_2fa" "$user" "TOTP enrollment completed"
}

usage(){ cat <<USG
NovaShield Terminal ${NS_VERSION} — JARVIS Edition
Usage: $0 [--install|--start|--stop|--restart-monitors|--status|--backup|--version-snapshot|--encrypt <path>|--decrypt <file.enc>|--web-start|--web-stop|--menu|--add-user|--enable-2fa]
USG
}

status(){
  echo "Version : ${NS_VERSION}"
  echo "Home    : ${NS_HOME}"
  echo "Termux  : ${IS_TERMUX}"
  echo "Web PID : $(cat "${NS_PID}/web.pid" 2>/dev/null || echo '-')"
  for p in cpu memory disk network integrity process userlogins services logs scheduler supervisor; do
    echo "$p PID: $(cat "${NS_PID}/${p}.pid" 2>/dev/null || echo '-')"
  done
}

menu(){
  PS3=$'\nSelect: '
  select opt in \
    "Start All" "Stop All" "Restart Monitors" "Status" \
    "Backup" "Version Snapshot" "Encrypt File/Dir" "Decrypt File" \
    "Add Web User" "Test Notification" "Open Dashboard URL" "Quit"; do
    case $REPLY in
      1) start_all;;
      2) stop_all;;
      3) restart_monitors;;
      4) status;;
      5) backup_snapshot;;
      6) version_snapshot;;
      7) read -rp "Path to file/dir: " p; if [ -d "$p" ]; then enc_dir "$p" "$p.tar.gz.enc"; else enc_file "$p" "$p.enc"; fi;;
      8) read -rp "Path to .enc: " p; read -rp "Output path: " o; dec_file "$p" "$o";;
      9) add_user;;
      10) python3 "${NS_BIN}/notify.py" "WARN" "NovaShield Test" "This is a test notification";;
      11) h=$(awk -F': ' '/host:/ {print $2}' "$NS_CONF" | head -n1 | tr -d '" '); prt=$(awk -F': ' '/port:/ {print $2}' "$NS_CONF" | head -n1 | tr -d '" '); [ -z "$h" ] && h="127.0.0.1"; [ -z "$prt" ] && prt=8765; echo "Open: http://${h}:${prt}";;
      12) break;;
      *) echo "?";;
    esac
  done
}

if [ $# -eq 0 ]; then usage; exit 0; fi

case "${1:-}" in
  --install) install_all;;
  --start) start_all;;
  --stop) stop_all;;
  --restart-monitors) restart_monitors;;
  --status) status;;
  --backup) backup_snapshot;;
  --version-snapshot) version_snapshot;;
  --encrypt)
    shift; p="${1:-}"; [ -z "$p" ] && die "--encrypt <path>"; if [ -d "$p" ]; then enc_dir "$p" "$p.tar.gz.enc"; else enc_file "$p" "$p.enc"; fi;;
  --decrypt)
    shift; p="${1:-}"; [ -z "$p" ] && die "--decrypt <file.enc>"; read -rp "Output path: " o; dec_file "$p" "$o";;
  --web-start) start_web;;
  --web-stop) stop_web;;
  --add-user) add_user;;
  --enable-2fa) enable_2fa;;
  --menu) menu;;
  *) usage; exit 1;;
esac
