#!/usr/bin/env bash
# ==============================================================================
# NovaShield Terminal 3.1.0 â€” JARVIS Edition â€” Allâ€‘inâ€‘One Installer & Runtime
# ==============================================================================
# Author  : niteas aka MrNova420
# Project : NovaShield (a.k.a. Nova)
# License : MIT
# Platform: Termux (Android) + Linux (Debian/Ubuntu/Arch/Fedora) auto-detect
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
NS_AUDIT="${NS_LOGS}/audit.log"
NS_CHATLOG="${NS_LOGS}/chat.log"
NS_SCHED_STATE="${NS_CTRL}/scheduler.state"
NS_SESS_DB="${NS_CTRL}/sessions.json"
NS_RL_DB="${NS_CTRL}/ratelimit.json"
NS_BANS_DB="${NS_CTRL}/bans.json"

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
ns_ok()  { echo -e "${GREEN}âœ” $*${NC}"; }

audit(){ echo "$(ns_now) $*" | tee -a "$NS_AUDIT" >/dev/null; }

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
           "$NS_LAUNCHER_BACKUPS" "${NS_HOME}/backups" "${NS_HOME}/site"
  : >"$NS_ALERTS" || true
  : >"$NS_CHATLOG" || true
  : >"$NS_AUDIT" || true
  [ -f "$NS_SESS_DB" ] || echo '{}' >"$NS_SESS_DB"
  [ -f "$NS_RL_DB" ] || echo '{}' >"$NS_RL_DB"
  [ -f "$NS_BANS_DB" ] || echo '{}' >"$NS_BANS_DB"
  echo "$NS_VERSION" >"$NS_VERSION_FILE"
  echo "$NS_SELF" >"$NS_SELF_PATH_FILE"
}

write_default_config(){
  if [ -f "$NS_CONF" ]; then return 0; fi
  ns_log "Writing default config to $NS_CONF"
  write_file "$NS_CONF" 600 <<'YAML'
version: "3.1.0"
http:
  host: 127.0.0.1
  port: 8765
  allow_lan: false

security:
  auth_enabled: true
  require_2fa: false
  users: []        # add via CLI: ./novashield.sh --add-user
  auth_salt: "change-this-salt"
  rate_limit_per_min: 60
  lockout_threshold: 10
  ip_allowlist: [] # e.g. ["127.0.0.1"]
  ip_denylist: []  # e.g. ["0.0.0.0/0"]
  csrf_required: true
  tls_enabled: false
  tls_cert: "keys/tls.crt"
  tls_key: "keys/tls.key"

terminal:
  enabled: true
  shell: ""             # auto-detect
  idle_timeout_sec: 900 # 15 minutes
  cols: 120
  rows: 32
  allow_write: true
  # Optional allowlist; if non-empty, warn on commands not matching any
  command_allowlist: []

monitors:
  cpu:         { enabled: true,  interval_sec: 3, warn_load: 2.00, crit_load: 4.00 }
  memory:      { enabled: true,  interval_sec: 3, warn_pct: 85,  crit_pct: 93 }
  # On Termux, "/" is tiny; we auto-switch to ~/.novashield runtime path if mount is "/".
  disk:        { enabled: true,  interval_sec: 10, warn_pct: 85, crit_pct: 95, mount: "/" }
  network:     { enabled: true,  interval_sec: 5, iface: "", ping_host: "1.1.1.1", loss_warn: 20 }
  integrity:   { enabled: true,  interval_sec: 60, watch_paths: ["/system/bin","/system/xbin","/usr/bin"] }
  process:     { enabled: true,  interval_sec: 10, suspicious: ["nc","nmap","hydra","netcat","telnet"] }
  userlogins:  { enabled: true,  interval_sec: 30 }
  services:    { enabled: false, interval_sec: 20, targets: ["cron","ssh","sshd"] }
  logs:        { enabled: true,  interval_sec: 15, files: ["/var/log/auth.log","/var/log/syslog"], patterns:["error","failed","denied","segfault"] }
  scheduler:   { enabled: true,  interval_sec: 30 }

logging:
  keep_days: 14
  alerts_enabled: true
  alert_sink: ["notify"]     # terminal/web logs always recorded; notify -> email/telegram/discord
  notify_levels: ["CRIT","WARN","ERROR"]

backup:
  enabled: true
  max_keep: 10
  encrypt: true
  paths: ["projects", "modules", "config.yaml"]

keys:
  rsa_bits: 4096
  aes_key_file: "keys/aes.key"

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

updates:
  enabled: false
  source: ""

sync:
  enabled: false
  method: "rclone"
  remote: ""

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
}

generate_self_signed_tls(){
  local enabled; enabled=$(awk -F': ' '/tls_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ')
  [ "$enabled" = "true" ] || return 0
  local crt key
  crt=$(awk -F': ' '/tls_cert:/ {print $2}' "$NS_CONF" | tr -d '" ')
  key=$(awk -F': ' '/tls_key:/ {print $2}' "$NS_CONF" | tr -d '" ')
  [ -z "$crt" ] && crt="keys/tls.crt"
  [ -z "$key" ] && key="keys/tls.key"
  [ -f "${NS_HOME}/${crt}" ] && [ -f "${NS_HOME}/${key}" ] && return 0
  ns_log "Generating self-signed TLS cert"
  (cd "$NS_HOME/keys" && \
    openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 825 \
      -subj "/CN=localhost/O=NovaShield/OU=SelfSigned") || ns_warn "TLS cert generation failed"
}

aes_key_path(){ awk -F': ' '/aes_key_file:/ {print $2}' "$NS_CONF" | tr -d '"' | tr -d ' ' ; }
enc_file(){ local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"; openssl enc -aes-256-cbc -salt -pbkdf2 -in "$in" -out "$out" -pass file:"$key"; }
dec_file(){ local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"; openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$out" -pass file:"$key"; }
enc_dir(){ local dir="$1"; local out="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"; tar -C "$dir" -czf "$tmp" . || tar -czf "$tmp" "$dir"; enc_file "$tmp" "$out"; rm -f "$tmp"; }
dec_dir(){ local in="$1"; local outdir="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"; dec_file "$in" "$tmp"; mkdir -p "$outdir"; tar -C "$outdir" -xzf "$tmp"; rm -f "$tmp"; }

write_notify_py(){
  write_file "${NS_BIN}/notify.py" 700 <<'PY'
#!/usr/bin/env python3
import os, sys, json, smtplib, ssl, urllib.request, urllib.parse, hmac, hashlib, base64, time
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
  audit "BACKUP CREATED $final"
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
  audit "VERSION SNAPSHOT ${vdir}"
}

monitor_enabled(){ local name="$1"; [ -f "${NS_CTRL}/${name}.disabled" ] && return 1 || return 0; }
write_json(){ local path="$1"; shift; printf '%s' "$*" >"$path"; }

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

# ------------------------------- MONITORS ------------------------------------
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
    local lvl; lvl=$(awk -v l="$load1" -v w="$warn" -v c="$crit" 'BEGIN{ if(l>=c){print "CRIT"} else if(l>=w){print "WARN"} else {print "OK"} }')
    write_json "${NS_LOGS}/cpu.json" "{\"ts\":\"$(ns_now)\",\"load1\":$load1,\"warn\":$warn,\"crit\":$crit,\"level\":\"$lvl\"}"
    [ "$lvl" = "CRIT" ] && alert CRIT "CPU load high: $load1" || { [ "$lvl" = "WARN" ] && alert WARN "CPU load elevated: $load1"; }
    sleep "$interval"
  done
}

_monitor_mem(){
  set +e; set +o pipefail
  local interval warn crit
  interval=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); interval=$(ensure_int "${interval:-}" 3)
  warn=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /warn_pct/) print $2 }' "$NS_CONF" | tr -d ' '); warn=$(ensure_int "${warn:-}" 85)
  crit=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /crit_pct/) print $2 }' "$NS_CONF" | tr -d ' '); crit=$(ensure_int "${crit:-}" 93)
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

# ------------------------------ PY WEB SERVER --------------------------------
write_server_py(){
  write_file "${NS_WWW}/server.py" 700 <<'PY'
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
  <title>NovaShield â€” JARVIS Edition</title>
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
    <button data-tab="alerts">Alerts</button>
    <button data-tab="files">Files</button>
    <button data-tab="terminal">Terminal</button>
    <button data-tab="ai">Jarvis</button>
    <button data-tab="webgen">Web Builder</button>
    <button data-tab="config">Config</button>
  </nav>

  <main>
    <section id="tab-status" class="tab active">
      <section class="grid">
        <div class="card" id="card-cpu"><h2>CPU</h2><div class="value" id="cpu"></div></div>
        <div class="card" id="card-mem"><h2>Memory</h2><div class="value" id="mem"></div></div>
        <div class="card" id="card-disk"><h2>Disk</h2><div class="value" id="disk"></div></div>
        <div class="card" id="card-net"><h2>Network</h2><div class="value" id="net"></div></div>
        <div class="card" id="card-int"><h2>Integrity</h2><div class="value" id="int"></div></div>
        <div class="card" id="card-proc"><h2>Processes</h2><div class="value" id="proc"></div></div>
        <div class="card" id="card-user"><h2>Users</h2><div class="value" id="user"></div></div>
        <div class="card" id="card-svc"><h2>Services</h2><div class="value" id="svc"></div></div>
        <div class="card" id="card-meta"><h2>Meta</h2><div class="value" id="meta"></div></div>
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

    <section id="tab-alerts" class="tab">
      <div class="panel">
        <h3>Alerts</h3>
        <ul id="alerts"></ul>
      </div>
    </section>

    <section id="tab-files" class="tab">
      <div class="panel">
        <h3>File Manager</h3>
        <div class="filebar">
          <input id="cwd" value="~/.novashield" />
          <button id="btn-list">List</button>
        </div>
        <div id="filelist"></div>
        <div id="viewer" class="panel" style="display:none; margin-top:10px;">
          <h3 id="viewer-title">Viewer</h3>
          <pre id="viewer-content" style="white-space:pre-wrap; overflow-x:auto;"></pre>
        </div>
        <div class="file-actions">
          <input id="newpath" placeholder="Path to create or save" />
          <button id="btn-mkdir">Mkdir</button>
          <button id="btn-save">Save Viewer -> Path</button>
        </div>
      </div>
    </section>

    <section id="tab-terminal" class="tab">
      <div class="panel">
        <h3>Web Terminal</h3>
        <div id="term" tabindex="0"></div>
        <div class="term-hint">Type here. Press Ctrl-C to interrupt. Idle timeout applies.</div>
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
        <pre id="config" style="white-space:pre-wrap;"></pre>
      </div>
    </section>
  </main>

  <div id="login" class="login" style="display:none;">
    <div class="login-card">
      <h3>Login</h3>
      <input id="li-user" placeholder="Username" />
      <input id="li-pass" placeholder="Password" type="password" />
      <input id="li-otp" placeholder="2FA Code (if enabled)" />
      <button id="li-btn">Sign in</button>
      <div id="li-msg"></div>
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
.login{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center}
.login-card{background:#0c162b;border:1px solid #15345f;border-radius:12px;width:320px;padding:16px;color:#e5f0ff}
.login-card input{width:100%;margin:6px 0;padding:8px;border-radius:8px;border:1px solid #143055;background:#0b1830;color:#d7e3ff}
.login-card button{width:100%;padding:10px;border-radius:8px;background:#0a1426;border:1px solid #173764;color:#cfe6ff;cursor:pointer}
#term{background:#000;color:#9fe4b9;border:1px solid #173764;border-radius:10px;height:300px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;padding:8px;white-space:pre-wrap;outline:none}
.term-hint{color:#93a3c0;font-size:12px;margin-top:6px}
@media (max-width:980px){ .grid{grid-template-columns:1fr} }
CSS

  write_file "${NS_WWW}/app.js" 644 <<'JS'
const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

const tabs = $$('.tabs button');
tabs.forEach(b=>b.onclick=()=>{ tabs.forEach(x=>x.classList.remove('active')); b.classList.add('active'); $$('.tab').forEach(x=>x.classList.remove('active')); $('#tab-'+b.dataset.tab).classList.add('active'); });

let CSRF = '';

$('#btn-refresh').onclick = refresh;

// Header actions
$$('header .actions button[data-act]').forEach(btn=>{
  btn.onclick = async () => {
    const act = btn.dataset.act;
    btn.disabled = true;
    try {
      await fetch('/api/control', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body: JSON.stringify({action: act})});
      toast(`Triggered: ${act}`);
    } catch(e) {
      console.error(e); toast(`Failed: ${act}`);
    } finally {
      btn.disabled = false;
    }
  };
});

function toast(msg){
  const t = document.createElement('div');
  t.textContent = msg;
  t.style.position='fixed'; t.style.right='14px'; t.style.bottom='14px';
  t.style.background='#0a1426'; t.style.border='1px solid #173764'; t.style.borderRadius='8px'; t.style.padding='8px 10px'; t.style.color='#cfe6ff'; t.style.zIndex=9999;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 2500);
}

async function api(path, opts){
  const r = await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}},opts||{}));
  if(r.status===401){
    showLogin(); throw new Error('unauthorized');
  }
  if(r.status===403){
    toast('Forbidden or CSRF'); throw new Error('forbidden');
  }
  if(!r.ok){ throw new Error('API error'); }
  return r;
}

function human(val, unit=''){ if(val===undefined || val===null) return '?'; return `${val}${unit}`; }
function setCard(id, text){ const el = $('#'+id); el.textContent = text; }

async function refresh(){
  try{
    const r = await api('/api/status'); const j = await r.json();
    CSRF = j.csrf || '';
    const cpu = j.cpu || {};
    setCard('cpu', `Load: ${human(cpu.load1)} | Level: ${cpu.level || 'OK'}`);
    const mem = j.memory || {};
    setCard('mem', `Used: ${human(mem.used_pct, '%')} | Warn: ${human(mem.warn, '%')} | Crit: ${human(mem.crit, '%')} | Level: ${mem.level || 'OK'}`);
    const dsk = j.disk || {};
    setCard('disk', `Mount: ${dsk.mount || '/'} | Used: ${human(dsk.use_pct, '%')} | Level: ${dsk.level || 'OK'}`);
    const net = j.network || {};
    setCard('net', `IP: ${net.ip || '?'} | Public: ${net.public_ip || '?'} | Loss: ${human(net.loss_pct, '%')} | RTT: ${human(net.rtt_avg_ms, 'ms')} | Level: ${net.level || 'OK'}`);
    setCard('int', `Integrity monitor active`);
    setCard('proc', `Process watch active`);
    setCard('user', `User sessions tracked`);
    setCard('svc', `Service checks ${j.services ? 'active' : 'n/a'}`);
    setCard('meta', `Projects: ${j.projects_count} | Modules: ${j.modules_count} | Version: ${j.version} | TS: ${j.ts}`);
    const ul = $('#alerts'); ul.innerHTML='';
    (j.alerts||[]).slice(-200).reverse().forEach(line=>{ const li=document.createElement('li'); li.textContent=line; ul.appendChild(li);});
    const levels = {cpu:j.cpu?.level, memory:j.memory?.level, disk:j.disk?.level, network:j.network?.level};
    const map = {OK:'ok', WARN:'warn', CRIT:'crit'};
    Object.entries(levels).forEach(([k,v])=>{
      const ids = {memory:'mem', disk:'disk', network:'net', cpu:'cpu'};
      const cardId = {memory:'card-mem', disk:'card-disk', network:'card-net', cpu:'card-cpu'}[k];
      const el = $('#'+cardId);
      if(!el) return; el.classList.remove('ok','warn','crit'); if(map[v]) el.classList.add(map[v]);
    });
    const conf = await (await api('/api/config')).text(); $('#config').textContent = conf;
  }catch(e){ console.error(e); }
}

// Monitors toggles
async function post(action,target){
  try{ await api('/api/control',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({action,target})}); toast(`${action} ${target}`); }catch(e){ toast('Action failed'); }
}
$$('.toggle').forEach(b=>{
  b.onclick=async()=>{
    const t=b.dataset.target;
    try{ await post('disable',t); await post('enable',t); refresh(); }catch(e){}
  };
});

// File Manager
$('#btn-list').onclick=()=>list($('#cwd').value);
async function list(dir){
  try{
    const j = await (await api('/api/fs?dir='+encodeURIComponent(dir.replace(/^~\//, (window.homedir||'')+'/')))).json();
    $('#cwd').value = j.dir;
    const wrap = $('#filelist'); wrap.innerHTML='';
    (j.entries||[]).forEach(e=>{
      const row = document.createElement('div');
      row.style.cursor='pointer';
      row.textContent = (e.is_dir?'[D] ':'[F] ') + e.name + (e.size?(' ('+e.size+'b)'):'');
      row.onclick = ()=>{
        if(e.is_dir){
          list(j.dir.replace(/\/+$/,'') + '/' + e.name);
        } else {
          viewFile(j.dir.replace(/\/+$/,'') + '/' + e.name);
        }
      };
      wrap.appendChild(row);
    });
  }catch(e){ console.error(e); toast('List failed'); }
}
async function viewFile(path){
  try{
    const j = await (await api('/api/fs_read?path='+encodeURIComponent(path))).json();
    if(!j.ok){ toast('Open failed'); return; }
    $('#viewer-title').textContent = `Viewer â€” ${j.path} (${j.size} bytes)`;
    $('#viewer-content').textContent = j.content || '';
    $('#viewer').style.display = '';
  }catch(e){ console.error(e); toast('Open failed'); }
}
$('#btn-mkdir').onclick=async()=>{
  const p=$('#newpath').value.trim(); if(!p) return;
  try{ await api('/api/fs_mkdir',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path:p})}); toast('mkdir ok'); list($('#cwd').value);}catch(e){toast('mkdir failed')}
}
$('#btn-save').onclick=async()=>{
  const p=$('#newpath').value.trim(); const c=$('#viewer-content').textContent;
  if(!p) return; try{ await api('/api/fs_write',{method:'POST', headers:{'Content-Type':'application/json','X-CSRF':CSRF}, body:JSON.stringify({path:p,content:c})}); toast('saved'); list($('#cwd').value);}catch(e){toast('save failed')}
}

// Jarvis chat
$('#send').onclick=async()=>{
  const prompt = $('#prompt').value.trim(); if(!prompt) return;
  const log = $('#chatlog'); const you = document.createElement('div'); you.textContent='You: '+prompt; log.appendChild(you);
  try{
    const j = await (await api('/api/chat',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({prompt})})).json();
    const ai = document.createElement('div'); ai.textContent='Jarvis: '+j.reply; log.appendChild(ai); $('#prompt').value=''; log.scrollTop=log.scrollHeight;
  }catch(e){ console.error(e); }
};

// Web Terminal
let ws=null;
function connectTerm(){
  try{
    const proto = location.protocol==='https:'?'wss':'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/term`);
    const term = $('#term');
    term.textContent='';
    ws.binaryType='arraybuffer';
    ws.onopen=()=>{ term.focus(); toast('Terminal connected'); };
    ws.onmessage=(ev)=>{
      if(ev.data instanceof ArrayBuffer){
        const dec = new TextDecoder('utf-8',{fatal:false}); const txt = dec.decode(new Uint8Array(ev.data));
        term.textContent += txt; term.scrollTop = term.scrollHeight;
      }else{
        term.textContent += ev.data; term.scrollTop = term.scrollHeight;
      }
    };
    ws.onclose=()=>{ toast('Terminal closed'); ws=null; };
    term.onkeydown=(e)=>{
      if(!ws || ws.readyState!==1) return;
      e.preventDefault();
      let out='';
      if(e.key==='Enter') out='\r';
      else if(e.key==='Backspace') out='\x7f';
      else if(e.key==='Tab') out='\t';
      else if(e.key==='ArrowUp') out='\x1b[A';
      else if(e.key==='ArrowDown') out='\x1b[B';
      else if(e.key==='ArrowRight') out='\x1b[C';
      else if(e.key==='ArrowLeft') out='\x1b[D';
      else if(e.ctrlKey && e.key.toLowerCase()==='c') out='\x03';
      else if(e.ctrlKey && e.key.toLowerCase()==='d') out='\x04';
      else if(e.key.length===1) out=e.key;
      if(out){ ws.send(new TextEncoder().encode(out)); }
    };
  }catch(e){ console.error(e); toast('Terminal connection failed'); }
}
$('#tab-terminal').addEventListener('click', ()=>{ if(!ws) connectTerm(); });

function showLogin(){
  $('#login').style.display='';
}
$('#li-btn').onclick=async()=>{
  const user=$('#li-user').value.trim(), pass=$('#li-pass').value, otp=$('#li-otp').value.trim();
  try{
    const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'}, body:JSON.stringify({user,pass,otp})});
    if(r.ok){ const j=await r.json(); CSRF=j.csrf||''; $('#login').style.display='none'; refresh(); }
    else{ $('#li-msg').textContent='Login failed'; }
  }catch(e){ $('#li-msg').textContent='Login error'; }
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

# ADD: drop this right after enable_2fa() and before usage()
ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)

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

# ADD: drop this right after enable_2fa() and before usage()
ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)

open_session(){ echo "$(ns_now) START ${NS_VERSION}" >>"$NS_SESSION"; }
close_session(){ echo "$(ns_now) STOP" >>"$NS_SESSION"; }

install_all(){
  ensure_dirs
  install_dependencies
  write_default_config
  generate_keys
  generate_self_signed_tls
  write_notify_py
  write_server_py
  write_dashboard
  ensure_auth_bootstrap     # <--- add this line
  setup_termux_service || true
  setup_systemd_user || true
  ns_ok "Install complete. Use: $0 --start"
}

# ADD: drop this right after enable_2fa() and before usage()
ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)


start_all(){
  ensure_dirs; write_default_config; generate_keys; generate_self_signed_tls; write_notify_py; write_server_py; write_dashboard
  ensure_auth_bootstrap     # <--- add this line
  open_session
  start_monitors
  start_web
  ns_ok "NovaShield is running. Open the dashboard in your browser."
}

# ADD: drop this right after enable_2fa() and before usage()
ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)

stop_all(){
  stop_monitors || true
  stop_web || true
  close_session
}

# ADD: drop this right after enable_2fa() and before usage()
ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)

restart_monitors(){ stop_monitors || true; start_monitors; }

# ADD: drop this right after enable_2fa() and before usage()
ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)

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
  ns_ok "User '$user' added. Enable/confirm auth in config.yaml (security.auth_enabled: true)"
}

# ADD: drop this right after enable_2fa() and before usage()
ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)
  if [ "$have_user" = "yes" ]; then return 0; fi
  echo
  ns_warn "No web users found but auth_enabled is true. Creating the first user."
  add_user
  echo
  read -r -p "Enable 2FA for this user now? [y/N]: " yn
  case "$yn" in [Yy]*) enable_2fa ;; esac
}

enable_2fa(){
  local user secret
  read -rp "Username to set 2FA: " user
  # generate base32 secret
  secret=$(python3 - <<'PY'
import os,base64; print(base64.b32encode(os.urandom(10)).decode().strip('='))
PY
)

# ADD: drop this right after enable_2fa() and before usage()
ensure_auth_bootstrap(){
  local enabled; enabled=$(awk -F': ' '/auth_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ' | tr 'A-Z' 'a-z')
  [ "$enabled" = "true" ] || return 0
  local have_user
  have_user=$(python3 - "$NS_SESS_DB" <<'PY'
import json,sys
p=sys.argv[1]
try: j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{}) or {}
print('yes' if len(ud)>0 else 'no')
PY
)
  if [ "$have_user" = "yes" ]; then return 0; fi
  echo
  ns_warn "No web users found but auth_enabled is true. Creating the first user."
  add_user
  echo
  read -r -p "Enable 2FA for this user now? [y/N]: " yn
  case "$yn" in [Yy]*) enable_2fa ;; esac
}

  echo "TOTP secret (Base32): $secret"
  echo "Add to your authenticator app (issuer: NovaShield, account: $user)."
  python3 - "$NS_SESS_DB" "$user" "$secret" <<'PY'
import json,sys
p,u,s=sys.argv[1],sys.argv[2],sys.argv[3]
try: j=json.load(open(p))
except: j={}
t=j.get('_2fa',{})
t[u]=s
j['_2fa']=t
open(p,'w').write(json.dumps(j))
print('2FA secret stored')
PY
  ns_ok "2FA set for '$user'. Set security.require_2fa: true to enforce."
}

usage(){ cat <<USG
NovaShield Terminal ${NS_VERSION} â€” JARVIS Edition
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
    "Add Web User" "Enable 2FA for User" "Test Notification" "Open Dashboard URL" "Quit"; do
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
      10) enable_2fa;;
      11) python3 "${NS_BIN}/notify.py" "WARN" "NovaShield Test" "This is a test notification";;
      12) h=$(awk -F': ' '/host:/ {print $2}' "$NS_CONF" | head -n1 | tr -d '" '); prt=$(awk -F': ' '/port:/ {print $2}' "$NS_CONF" | head -n1 | tr -d '" '); [ -z "$h" ] && h="127.0.0.1"; [ -z "$prt" ] && prt=8765; echo "Open: http://${h}:${prt}";;
      13) break;;
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
