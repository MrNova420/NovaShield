#!/usr/bin/env bash
# ==============================================================================
# NovaShield Terminal 3.0 — JARVIS Edition — All‑in‑One Installer & Runtime
# ==============================================================================
# Author  : niteas aka MrNova420
# Project : NovaShield (a.k.a. Nova)
# License : MIT
# Platform: Termux (Android) + Linux (Debian/Ubuntu/Arch/Fedora) auto-detect
#
# Mission:
# - Keep original NovaShield 2.0 code as the foundation, fully debugged.
# - Deep security hardening, multi-layer monitors, alerts, error analytics.
# - Supervisor + fallback auto-heal for monitors and web UI.
# - Optional web dashboard authentication with session tokens.
# - Notifications (email/Telegram/Discord) via built-in Python helper.
# - Automation scheduler (cron-like) driven by config.yaml.
# - File tools (encrypt/decrypt, backup/versioning) + File Manager API.
# - AI "Jarvis"-inspired assistant panel (local rule-based responder).
# - Simple webpage builder (static pages) with panel + CLI.
# - Extensible plugins/panels; everything generated from this single script.
#
# Result:
# - Single file you can commit to GitHub. Running it creates ~/.novashield/*
# - Cross-platform. No external Python libs required.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------------- VERSION ----------------------------------
NS_VERSION="3.0.0"

# ------------------------------- GLOBAL PATHS ---------------------------------
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

# ---------------------------- RUNTIME CONSTANTS ------------------------------
NS_DEFAULT_PORT=8765
NS_DEFAULT_HOST="127.0.0.1"

# ------------------------------ SELF RESOLUTION ------------------------------
NS_SELF="${BASH_SOURCE[0]}"
if command -v realpath >/dev/null 2>&1; then
  NS_SELF="$(realpath "${NS_SELF}")" || true
elif command -v readlink >/dev/null 2>&1; then
  NS_SELF="$(readlink -f "${NS_SELF}" 2>/dev/null || echo "${NS_SELF}")"
fi

# ---------------------------------- COLORS -----------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --------------------------------- LOGGING -----------------------------------
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

# -------------------------------- UTILITIES ----------------------------------
die(){ ns_err "$*"; alert "CRIT" "$*"; exit 1; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }
write_file(){ local path="$1"; local mode="$2"; shift 2; install -m "$mode" /dev/null "$path" 2>/dev/null || true; cat >"$path"; }
append_file(){ local path="$1"; shift; cat >>"$path"; }
slurp(){ [ -f "$1" ] && cat "$1" || true; }
safe_json(){ printf '%s' "$1" | tr -d '\000'; } # crude sanitization

# --------------------------- ENVIRONMENT DETECTION ---------------------------
IS_TERMUX=0
if uname -a | grep -iq termux || { [ -n "${PREFIX:-}" ] && echo "$PREFIX" | grep -q "/com.termux/"; }; then
  IS_TERMUX=1
fi

OS_FAMILY="linux"
[ "$(uname -s)" = "Linux" ] || OS_FAMILY="other"

# ------------------------------ PACKAGE INSTALL ------------------------------
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

# ---------------------------- DIRECTORY LAYOUT -------------------------------
ensure_dirs(){
  mkdir -p "$NS_BIN" "$NS_LOGS" "$NS_WWW" "$NS_MODULES" "$NS_PROJECTS" \
           "$NS_VERSIONS" "$NS_KEYS" "$NS_CTRL" "$NS_TMP" "$NS_PID" \
           "$NS_LAUNCHER_BACKUPS" "${NS_HOME}/backups" "${NS_HOME}/site"
  : >"$NS_ALERTS" || true
  : >"$NS_CHATLOG" || true
  [ -f "$NS_SESS_DB" ] || echo '{}' >"$NS_SESS_DB"
  echo "$NS_VERSION" >"$NS_VERSION_FILE"
  echo "$NS_SELF" >"$NS_SELF_PATH_FILE"
}

# ------------------------------- DEFAULT CONF --------------------------------
write_default_config(){
  if [ -f "$NS_CONF" ]; then return 0; fi
  ns_log "Writing default config to $NS_CONF"
  write_file "$NS_CONF" 600 <<'YAML'
# NovaShield Terminal 3.0 — config.yaml
version: "3.0.0"
http:
  host: 127.0.0.1
  port: 8765
  # If true, bind 0.0.0.0 (LAN access). Use with caution.
  allow_lan: false

security:
  auth_enabled: false
  # Users for dashboard auth. Passwords are hex sha256 of "salt:password".
  # Use CLI: ./novashield.sh --add-user
  users: []
  auth_salt: "change-this-salt"
  rate_limit_per_min: 60

monitors:
  cpu:         { enabled: true,  interval_sec: 3, warn_load: 2.00, crit_load: 4.00 }
  memory:      { enabled: true,  interval_sec: 3, warn_pct: 80,  crit_pct: 92 }
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
  alert_sink: ["terminal", "web", "notify"]
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
  source: ""  # optional git URL or local path

sync:
  enabled: false
  method: "rclone"
  remote: ""

scheduler:
  # Simple cron-like tasks. time: "HH:MM" daily, or every_n_min: 15
  tasks:
    - name: "daily-backup"
      action: "backup"
      time: "02:30"
    - name: "version-snapshot-weekly"
      action: "version"
      time: "03:00"

webgen:
  # Default site output: ~/.novashield/site
  enabled: true
  site_name: "NovaShield Site"
  theme: "jarvis-dark"
YAML
}

# -------------------------------- DEPENDENCIES -------------------------------
install_dependencies(){
  ns_log "Checking dependencies..."
  local need=(python3 openssl awk sed grep tar gzip df du ps top uname head tail cut tr sha256sum curl ping find xargs)
  for c in "${need[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      ns_warn "$c missing; attempting install"
      case "$c" in
        sha256sum) PKG_INSTALL coreutils || true;;
        python3) PKG_INSTALL python python3 || true;;
        openssl) PKG_INSTALL openssl || true;;
        tar) PKG_INSTALL tar || true;;
        gzip) PKG_INSTALL gzip || true;;
        curl) PKG_INSTALL curl || true;;
        ping) PKG_INSTALL iputils-ping inetutils-ping || true;;
        *) PKG_INSTALL "$c" || true;;
      esac
    fi
  done
  if [ "$IS_TERMUX" -eq 1 ]; then
    if ! command -v sv-enable >/dev/null 2>&1; then
      ns_warn "Installing termux-services (optional)"
      PKG_INSTALL termux-services || true
    fi
  fi
}

# --------------------------------- KEY GEN -----------------------------------
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

# ------------------------------ ENCRYPTION UTIL ------------------------------
aes_key_path(){ awk -F': ' '/aes_key_file:/ {print $2}' "$NS_CONF" | tr -d '"' | tr -d ' ' ; }
enc_file(){ local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"; openssl enc -aes-256-cbc -salt -pbkdf2 -in "$in" -out "$out" -pass file:"$key"; }
dec_file(){ local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"; openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$out" -pass file:"$key"; }
enc_dir(){ local dir="$1"; local out="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"; tar -C "$dir" -czf "$tmp" . || tar -czf "$tmp" "$dir"; enc_file "$tmp" "$out"; rm -f "$tmp"; }
dec_dir(){ local in="$1"; local outdir="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"; dec_file "$in" "$tmp"; mkdir -p "$outdir"; tar -C "$outdir" -xzf "$tmp"; rm -f "$tmp"; }

# ----------------------------- NOTIFICATION HELPER ---------------------------
write_notify_py(){
  write_file "${NS_BIN}/notify.py" 700 <<'PY'
#!/usr/bin/env python3
import os, sys, json, smtplib, ssl, urllib.request
from email.mime.text import MIMEText

NS_HOME = os.path.expanduser('~/.novashield')
CONF = os.path.join(NS_HOME, 'config.yaml')

def load_conf():
  d = {}
  try:
    with open(CONF,'r',encoding='utf-8') as f:
      for line in f:
        if line.strip().startswith('#'): continue
        if ':' in line:
          k,v = line.split(':',1)
          d[k.strip()] = v.strip()
  except Exception:
    pass
  return d

def get_yaml_block(prefix):
  # naive YAML puller
  lines = []
  try:
    with open(CONF,'r',encoding='utf-8') as f:
      collect=False
      indent=None
      for raw in f:
        if raw.strip().startswith(prefix+':'):
          collect=True; indent=len(raw)-len(raw.lstrip()); lines.append(raw); continue
        if collect:
          if raw.strip()=='':
            lines.append(raw); continue
          cur_indent = len(raw)-len(raw.lstrip())
          if cur_indent<=indent and not raw.strip().startswith('-'):
            break
          lines.append(raw)
  except Exception:
    pass
  return ''.join(lines)

def yaml_get(path, default=None):
  # path like notifications.email.enabled
  try:
    with open(CONF,'r',encoding='utf-8') as f:
      tree = {}
      stack = [(-1, tree)]
      for line in f:
        if not line.strip() or line.strip().startswith('#'): continue
        indent = len(line)-len(line.lstrip())
        keyval = line.strip()
        while stack and indent <= stack[-1][0]:
          stack.pop()
        parent = stack[-1][1] if stack else tree
        if ':' in keyval:
          k,v = keyval.split(':',1)
          k=k.strip(); v=v.strip()
          if v=='':
            parent[k] = {}
            stack.append((indent, parent[k]))
          else:
            parent[k] = v.strip().strip('"')
        elif keyval.startswith('- '):
          k = keyval[2:].strip().strip('"')
          parent.setdefault('_list', []).append(k)
      # walk
      cur = tree
      for p in path.split('.'):
        if isinstance(cur, dict) and p in cur:
          cur = cur[p]
        else:
          return default
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
  if not (host and user and pwd and to): return
  msg = MIMEText(body, 'plain', 'utf-8')
  msg['Subject'] = subject
  msg['From'] = user
  msg['To'] = ','.join([t.strip() for t in to if t.strip()])
  try:
    if use_tls:
      context = ssl.create_default_context()
      with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls(context=context)
        server.login(user, pwd)
        server.sendmail(user, [t.strip() for t in to if t.strip()], msg.as_string())
    else:
      with smtplib.SMTP(host, port, timeout=10) as server:
        server.login(user, pwd)
        server.sendmail(user, [t.strip() for t in to if t.strip()], msg.as_string())
  except Exception as e:
    pass

def send_telegram(body):
  if not yaml_get('notifications.telegram.enabled') == 'true': return
  token = yaml_get('notifications.telegram.bot_token','')
  chat  = yaml_get('notifications.telegram.chat_id','')
  if not (token and chat): return
  data = urllib.parse.urlencode({'chat_id':chat,'text':body}).encode('utf-8')
  try:
    urllib.request.urlopen(urllib.request.Request(f'https://api.telegram.org/bot{token}/sendMessage', data=data), timeout=5)
  except Exception:
    pass

def send_discord(body):
  if not yaml_get('notifications.discord.enabled') == 'true': return
  hook = yaml_get('notifications.discord.webhook_url','')
  if not hook: return
  payload = json.dumps({'content': body}).encode('utf-8')
  req = urllib.request.Request(hook, data=payload, headers={'Content-Type':'application/json'})
  try:
    urllib.request.urlopen(req, timeout=5)
  except Exception:
    pass

if __name__ == '__main__':
  # argv: level subject body
  level = sys.argv[1] if len(sys.argv)>1 else 'INFO'
  subject = sys.argv[2] if len(sys.argv)>2 else 'NovaShield Notification'
  body = sys.argv[3] if len(sys.argv)>3 else ''
  allow = (yaml_get('logging.notify_levels','["CRIT","WARN"]') or '').upper()
  if (level or '').upper() in allow:
    send_email(subject, body)
    send_telegram(f'{subject}\n{body}')
    send_discord(f'{subject}\n{body}')
PY
}

notify_dispatch(){
  # Decide whether to notify based on config
  local enabled; enabled=$(awk -F': ' '/alerts_enabled:/ {print $2}' "$NS_CONF" | tr -d ' ')
  local sinks; sinks=$(awk -F'\[|\]' '/alert_sink:/ {print $2}' "$NS_CONF" | tr -d ' "' | tr ',' ' ')
  [ "$enabled" = "true" ] || return 0
  for s in $sinks; do
    case "$s" in
      notify)
        python3 "${NS_BIN}/notify.py" "$1" "NovaShield [$1]" "$2" >/dev/null 2>&1 || true
        ;;
      *) : ;;
    esac
  done
}

# ------------------------------- BACKUPS/VERS --------------------------------
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
    final="${dest_dir}/backup-${stamp}.tar.gz.enc"; enc_file "$tmp_tar" "$final"; rm -f "$tmp_tar"
  else
    final="${dest_dir}/backup-${stamp}.tar.gz"; mv "$tmp_tar" "$final"
  fi
  ns_ok "Backup created: $final"; rotate_backups
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

# ------------------------------- MONITORS ------------------------------------
monitor_enabled(){ local name="$1"; [ -f "${NS_CTRL}/${name}.disabled" ] && return 1 || return 0; }
write_json(){ local path="$1"; shift; printf '%s' "$*" >"$path"; }

_monitor_cpu(){
  local interval warn crit; interval=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=3
  warn=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /warn_load/) print $2 }' "$NS_CONF" | tr -d ' ')
  crit=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /crit_load/) print $2 }' "$NS_CONF" | tr -d ' ')
  while true; do
    monitor_enabled cpu || { sleep "$interval"; continue; }
    local load1; load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
    local lvl="OK"; awk -v l="$load1" -v w="$warn" -v c="$crit" 'BEGIN{lvl="OK"; if(l>=c){print "CRIT"} else if(l>=w){print "WARN"} else {print "OK"}}' >/tmp/ns-cpu-lvl
    lvl=$(cat /tmp/ns-cpu-lvl)
    write_json "${NS_LOGS}/cpu.json" "{\"ts\":\"$(ns_now)\",\"load1\":$load1,\"warn\":$warn,\"crit\":$crit,\"level\":\"$lvl\"}"
    [ "$lvl" = "CRIT" ] && alert CRIT "CPU load high: $load1" || { [ "$lvl" = "WARN" ] && alert WARN "CPU load elevated: $load1"; }
    sleep "$interval"
  done
}

_monitor_mem(){
  local interval warn crit; interval=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=3
  warn=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /warn_pct/) print $2 }' "$NS_CONF" | tr -d ' ')
  crit=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /crit_pct/) print $2 }' "$NS_CONF" | tr -d ' ')
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
  local interval warn crit mount
  interval=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=10
  warn=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /warn_pct/) print $2 }' "$NS_CONF" | tr -d ' ')
  crit=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /crit_pct/) print $2 }' "$NS_CONF" | tr -d ' ')
  mount=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /mount:/) print $2 }' "$NS_CONF" | tr -d '" ')
  [ -z "$mount" ] && mount="/"
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
  local interval iface pingh warnloss
  interval=$(awk -F': ' '/network:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=5
  iface=$(awk -F': ' '/network:/,/}/ { if($1 ~ /iface:/) print $2 }' "$NS_CONF" | tr -d '" ')
  pingh=$(awk -F': ' '/network:/,/}/ { if($1 ~ /ping_host/) print $2 }' "$NS_CONF" | tr -d '" '); [ -z "$pingh" ] && pingh="1.1.1.1"
  warnloss=$(awk -F': ' '/network:/,/}/ { if($1 ~ /loss_warn/) print $2 }' "$NS_CONF" | tr -d ' ')
  while true; do
    monitor_enabled network || { sleep "$interval"; continue; }
    local ip pubip loss=0 avg=0
    if command -v ip >/dev/null 2>&1; then
      ip=$(ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
      [ -z "$ip" ] && ip=$(ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.' | head -n1)
    else
      ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1)
      [ -z "$ip" ] && ip=$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | head -n1)
    fi
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
    local lvl="OK"; [ "${loss:-0}" -ge "${warnloss:-1000}" ] && lvl="WARN"
    write_json "${NS_LOGS}/network.json" "{\"ts\":\"$(ns_now)\",\"ip\":\"${ip:-}\",\"public_ip\":\"${pubip:-}\",\"loss_pct\":${loss:-0},\"rtt_avg_ms\":${avg:-0},\"level\":\"$lvl\"}"
    [ "$lvl" = "WARN" ] && alert WARN "Network loss ${loss}% to ${pingh}"
    sleep "$interval"
  done
}

_monitor_integrity(){
  local interval; interval=$(awk -F': ' '/integrity:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=60
  local list; list=$(awk -F'\- ' '/watch_paths:/{flag=1;next}/]/{flag=0}flag{print $2}' "$NS_CONF" 2>/dev/null || true)
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
  local interval suspicious; interval=$(awk -F': ' '/process:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=10
  suspicious=$(awk -F'\[|\]' '/process:/,/\}/ { if($0 ~ /suspicious:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' '\n')
  while true; do
    monitor_enabled process || { sleep "$interval"; continue; }
    local procs; procs=$(ps aux || ps -ef)
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
  local interval; interval=$(awk -F': ' '/userlogins:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=30
  local prev=""; while true; do
    monitor_enabled userlogins || { sleep "$interval"; continue; }
    local users; users=$(who 2>/dev/null || true)
    if [ "$users" != "$prev" ] && [ -n "$prev" ]; then
      alert INFO "User sessions changed: $(echo "$users" | tr '\n' '; ')" || true
    fi
    prev="$users"
    write_json "${NS_LOGS}/user.json" "{\"ts\":\"$(ns_now)\",\"who\":$(printf '%s' "$(echo "$users" | sed 's/"/\\"/g' | awk '{printf "%s\\n",$0}')" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')}"
    sleep "$interval"
  done
}

_monitor_services(){
  local interval targets; interval=$(awk -F': ' '/services:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=20
  targets=$(awk -F'\[|\]' '/services:/,/\}/ { if($0 ~ /targets:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' '\n')
  while true; do
    monitor_enabled services || { sleep "$interval"; continue; }
    for svc in $targets; do
      [ -z "$svc" ] && continue
      if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then alert CRIT "Service $svc is not active!"; fi
      else
        pgrep -f "$svc" >/dev/null 2>&1 || alert WARN "Service process not found: $svc"
      fi
    done
    write_json "${NS_LOGS}/service.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

_monitor_logs(){
  local interval; interval=$(awk -F': ' '/logs:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=15
  local files patterns; files=$(awk -F'\[|\]' '/logs:/,/\}/ { if($0 ~ /files:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' ' ')
  patterns=$(awk -F'\[|\]' '/logs:/,/\}/ { if($0 ~ /patterns:/) print $2 }' "$NS_CONF" | tr -d '"' | tr ',' '|')
  [ -z "$patterns" ] && patterns="error|failed|denied|segfault"
  declare -A last_sizes
  while true; do
    monitor_enabled logs || { sleep "$interval"; continue; }
    for f in $files; do
      [ -f "$f" ] || continue
      local size; size=$(stat -c%s "$f" 2>/dev/null || wc -c <"$f" 2>/dev/null || echo 0)
      local from=${last_sizes["$f"]:-0}
      if [ "$size" -gt "$from" ]; then
        tail -c +"$((from+1))" "$f" | grep -Eai "$patterns" | while IFS= read -r line; do
          alert WARN "Log anomaly in $(basename "$f"): $line"
        done
      fi
      last_sizes["$f"]="$size"
    done
    write_json "${NS_LOGS}/logwatch.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

# Supervisor: auto-heal monitors and web server
_supervisor(){
  local interval=10
  while true; do
    # monitors
    for p in cpu memory disk network integrity process userlogins services logs; do
      if [ -f "${NS_PID}/${p}.pid" ]; then
        local pid; pid=$(cat "${NS_PID}/${p}.pid" 2>/dev/null || echo 0)
        if ! kill -0 "$pid" 2>/dev/null; then
          alert ERROR "Monitor $p crashed. Restarting."
          "_monitor_${p}" & echo $! >"${NS_PID}/${p}.pid"
        fi
      fi
    done
    # web
    if [ -f "${NS_PID}/web.pid" ]; then
      local wpid; wpid=$(cat "${NS_PID}/web.pid" 2>/dev/null || echo 0)
      if ! kill -0 "$wpid" 2>/dev/null; then
        alert ERROR "Web server crashed. Restarting."; start_web || true
      fi
    fi
    sleep "$interval"
  done
}

# Scheduler monitor (cron-like)
_monitor_scheduler(){
  local interval; interval=$(awk -F': ' '/scheduler:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' '); [ -z "$interval" ] && interval=30
  : >"$NS_SCHED_STATE" || true
  while true; do
    monitor_enabled scheduler || { sleep "$interval"; continue; }
    local now_hm; now_hm=$(date +%H:%M)
    local ran_today_key="$(date +%Y-%m-%d)"
    awk '/scheduler:/,/tasks:/{print}' "$NS_CONF" >/dev/null 2>&1 || { sleep "$interval"; continue; }
    # Parse tasks
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
    *) # custom module command under modules/
       if [ -x "${NS_MODULES}/${act}.sh" ]; then "${NS_MODULES}/${act}.sh" || alert ERROR "Module ${act} failed"; else ns_warn "Unknown scheduler action: $act"; fi
       ;;
  esac
}

start_monitors(){
  ns_log "Starting monitors..."
  stop_monitors || true
  (_monitor_cpu &)          echo $! >"${NS_PID}/cpu.pid"
  (_monitor_mem &)          echo $! >"${NS_PID}/memory.pid"
  (_monitor_disk &)         echo $! >"${NS_PID}/disk.pid"
  (_monitor_net &)          echo $! >"${NS_PID}/network.pid"
  (_monitor_integrity &)    echo $! >"${NS_PID}/integrity.pid"
  (_monitor_process &)      echo $! >"${NS_PID}/process.pid"
  (_monitor_userlogins &)   echo $! >"${NS_PID}/userlogins.pid"
  (_monitor_services &)     echo $! >"${NS_PID}/services.pid"
  (_monitor_logs &)         echo $! >"${NS_PID}/logs.pid"
  (_monitor_scheduler &)    echo $! >"${NS_PID}/scheduler.pid"
  (_supervisor &)           echo $! >"${NS_PID}/supervisor.pid"
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
import json, os, sys, time, hashlib, http.cookies
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
SITE_DIR = os.path.join(NS_HOME, 'site')

def read_text(path, default=''):
    try:
        with open(path, 'r', encoding='utf-8') as f: return f.read()
    except Exception: return default

def write_text(path, data):
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    with open(path,'w',encoding='utf-8') as f: f.write(data)

def read_json(path, default=None):
    try:
        with open(path, 'r', encoding='utf-8') as f: return json.loads(f.read())
    except Exception: return default

def write_json(path, obj):
    Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
    with open(path,'w',encoding='utf-8') as f: f.write(json.dumps(obj))

def yaml_get(path, default=None):
    try:
        with open(CONFIG,'r',encoding='utf-8') as f:
            tree = {}
            stack=[(-1,tree)]
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

def auth_enabled():
    return (yaml_get('security.auth_enabled','false')=='true')

def auth_salt():
    return yaml_get('security.auth_salt','changeme')

def users_list():
    # users in yaml as list of objects is not fully parsed by naive yaml_get; allow flat list "users: [user:passsha,...]" or store in sessions.json once set.
    # For simplicity, read sessions.json for userdb if present.
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
    # Local rule-based "Jarvis"-inspired assistant. No external calls.
    prompt_low = (prompt or '').lower()
    now=time.strftime('%Y-%m-%d %H:%M:%S')
    status = {
        'cpu': read_json(os.path.join(NS_LOGS,'cpu.json'),{}),
        'mem': read_json(os.path.join(NS_LOGS,'memory.json'),{}),
        'disk': read_json(os.path.join(NS_LOGS,'disk.json'),{}),
        'net': read_json(os.path.join(NS_LOGS,'network.json'),{}),
    }
    if 'status' in prompt_low or 'health' in prompt_low:
        return f"[{now}] System status: CPU load {status['cpu'].get('load1','?')}, Mem {status['mem'].get('used_pct','?')}%, Disk {status['disk'].get('use_pct','?')}% used, Net loss {status['net'].get('loss_pct','?')}%."
    if 'backup' in prompt_low:
        os.system(f'"{read_text(SELF_PATH_FILE).strip()}" --backup >/dev/null 2>&1 &')
        return "Acknowledged. Initiated a backup snapshot. I will notify if anything fails."
    if 'version' in prompt_low or 'snapshot' in prompt_low:
        os.system(f'"{read_text(SELF_PATH_FILE).strip()}" --version-snapshot >/dev/null 2>&1 &')
        return "Understood. Creating a version snapshot right away."
    if 'restart monitor' in prompt_low or 'restart monitors' in prompt_low:
        os.system(f'"{read_text(SELF_PATH_FILE).strip()}" --restart-monitors >/dev/null 2>&1 &')
        return "Reinitializing all monitors. Stand by."
    if 'ip' in prompt_low:
        return f"Your internal IP appears to be {status['net'].get('ip','?')} and public IP {status['net'].get('public_ip','?')}."
    if 'help' in prompt_low or 'what can you do' in prompt_low:
        return "I can report status, trigger backup/version, restart monitors, and answer about CPU/memory/disk/network. Ask me: 'status', 'backup', 'version', 'IP', or 'open config'."
    if 'open config' in prompt_low:
        return "Open the Config panel. You can edit ~/.novashield/config.yaml directly."
    return f"I hear you: '{prompt}'. I can perform status, backup, version snapshot, and restart monitors. Say 'help' for options."

class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, ctype='application/json', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        if extra_headers:
            for k,v in extra_headers.items(): self.send_header(k, v)
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200, 'text/plain', {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Methods':'GET,POST,OPTIONS'})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/':
            self._set_headers(200, 'text/html; charset=utf-8')
            html = read_text(INDEX, '<h1>NovaShield</h1>')
            self.wfile.write(html.encode('utf-8'))
            return
        if parsed.path.startswith('/static/'):
            p = os.path.join(NS_WWW, parsed.path[len('/static/'):])
            if not os.path.abspath(p).startswith(NS_WWW): self._set_headers(404); self.wfile.write(b'{}'); return
            if os.path.exists(p) and os.path.isfile(p):
                ctype = 'text/plain'
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
                'alerts': last_lines(os.path.join(NS_LOGS, 'alerts.log'), 200),
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
            self._set_headers(200); self.wfile.write(json.dumps({'name': name, 'lines': last_lines(p, 200)}).encode('utf-8')); return

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

        if parsed.path == '/site':
            # serve generated site
            index = os.path.join(SITE_DIR,'index.html')
            self._set_headers(200,'text/html; charset=utf-8'); self.wfile.write(read_text(index,'<h1>No site yet</h1>').encode('utf-8')); return

        self._set_headers(404); self.wfile.write(b'{"error":"not found"}')

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''
        if parsed.path == '/api/login':
            try:
                data = json.loads(body or '{}'); user=data.get('user'); pwd=data.get('pass')
            except Exception:
                data={}; user=''; pwd=''
            if auth_enabled() and check_login(user, pwd):
                tok = new_session(user)
                self._set_headers(200, 'application/json', {'Set-Cookie': f'NSSESS={tok}; Path=/; HttpOnly'})
                self.wfile.write(b'{"ok":true}'); return
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
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception: pass
            if action == 'disable' and target:
                try:
                    open(flag,'w').close()
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception: pass
            self_path = read_text(SELF_PATH_FILE).strip() or os.path.join(NS_HOME, 'bin', 'novashield.sh')
            if action in ('backup','version','restart_monitors'):
                try:
                    if action=='backup': os.system(f'"{self_path}" --backup >/dev/null 2>&1 &')
                    if action=='version': os.system(f'"{self_path}" --version-snapshot >/dev/null 2>&1 &')
                    if action=='restart_monitors': os.system(f'"{self_path}" --restart-monitors >/dev/null 2>&1 &')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception: pass
            self._set_headers(400); self.wfile.write(b'{"ok":false}'); return

        if parsed.path == '/api/chat':
            if not require_auth(self): return
            try: data = json.loads(body or '{}')
            except Exception: data={}
            prompt = data.get('prompt','')
            reply = ai_reply(prompt)
            log_line = f'{time.strftime("%Y-%m-%d %H:%M:%S")} Q:{prompt} A:{reply}\n'
            try: 
                with open(CHATLOG,'a',encoding='utf-8') as f: f.write(log_line)
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
            # update index
            pages = [p for p in os.listdir(SITE_DIR) if p.endswith('.html')]
            links = '\n'.join([f'<li><a href="/site/{p}">{p}</a></li>' for p in pages if p!='index.html'])
            write_text(os.path.join(SITE_DIR,'index.html'), f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>Site</title></head><body><h1>Site</h1><ul>{links}</ul></body></html>')
            self._set_headers(200); self.wfile.write(json.dumps({'ok':True,'page':f'/site/{slug}.html'}).encode('utf-8')); return

        if parsed.path.startswith('/site/'):
            # serve generated page
            p = parsed.path[len('/site/'):]
            full = os.path.join(SITE_DIR, p)
            if not os.path.abspath(full).startswith(SITE_DIR): self._set_headers(403); self.wfile.write(b'{}'); return
            if os.path.exists(full):
                self._set_headers(200, 'text/html; charset=utf-8'); self.wfile.write(read_text(full).encode('utf-8')); return
            self._set_headers(404); self.wfile.write(b'{}'); return

        self._set_headers(400); self.wfile.write(b'{"ok":false}')

if __name__ == '__main__':
    host='127.0.0.1'; port=8765
    try:
        with open(CONFIG,'r',encoding='utf-8') as f:
            t=f.read()
            for line in t.splitlines():
                if 'host:' in line and 'http:' not in line: host=line.split(':',1)[1].strip()
                if 'port:' in line and 'http:' not in line: 
                    try: port=int(line.split(':',1)[1].strip())
                    except: port=8765
                if 'allow_lan:' in line and 'true' in line: host='0.0.0.0'
    except Exception:
        pass
    os.chdir(NS_WWW)
    httpd = HTTPServer((host, port), Handler)
    print(f"NovaShield Web Server on http://{host}:{port}")
    httpd.serve_forever()
PY
  chmod 700 "${NS_WWW}/server.py"
}

write_dashboard(){
  # index.html
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
    <button data-tab="alerts">Alerts</button>
    <button data-tab="files">Files</button>
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

  <script src="/static/app.js"></script>
</body>
</html>
HTML

  # style.css
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
@media (max-width:980px){ .grid{grid-template-columns:1fr} }
CSS

  # app.js
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
    // Alerts
    const ul = $('#alerts'); ul.innerHTML='';
    (j.alerts||[]).slice(-200).reverse().forEach(line=>{ const li=document.createElement('li'); li.textContent=line; ul.appendChild(li);});
    // Levels coloring
    const levels = {cpu:j.cpu?.level, memory:j.memory?.level, disk:j.disk?.level, network:j.network?.level};
    const map = {OK:'ok', WARN:'warn', CRIT:'crit'};
    Object.entries(levels).forEach(([k,v])=>{
      const ids = {memory:'mem', disk:'disk', network:'net', cpu:'cpu'};
      const el = $('#card-'+(ids[k]||k));
      if(!el) return; el.classList.remove('ok','warn','crit'); if(map[v]) el.classList.add(map[v]);
    });
    // Config
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

# ------------------------------ SERVICES SETUP -------------------------------
setup_termux_service(){
  if ! command -v sv-enable >/dev/null 2>&1; then return 0; fi
  local svcdir="${HOME}/.termux/services/novashield"
  mkdir -p "$svcdir"
  write_file "$svcdir/run" 700 <<RUN
#!/data/data/com.termux/files/usr/bin/sh
exec python3 "${NS_WWW}/server.py" >>"${NS_HOME}/web.log" 2>&1
RUN
  sv-enable novashield || true
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

# -------------------------------- WEB CONTROL --------------------------------
start_web(){
  ns_log "Starting web server..."
  stop_web || true
  (python3 "${NS_WWW}/server.py" &)
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

# --------------------------------- SESSION -----------------------------------
open_session(){ echo "$(ns_now) START ${NS_VERSION}" >>"$NS_SESSION"; }
close_session(){ echo "$(ns_now) STOP" >>"$NS_SESSION"; }

# --------------------------------- INSTALL -----------------------------------
install_all(){
  ensure_dirs
  install_dependencies
  write_default_config
  generate_keys
  write_notify_py
  write_server_py
  write_dashboard
  setup_termux_service || true
  setup_systemd_user || true
  ns_ok "Install complete. Use: $0 --start"
}

# --------------------------------- STARTUP -----------------------------------
start_all(){
  ensure_dirs; write_default_config; generate_keys; write_notify_py; write_server_py; write_dashboard
  open_session
  start_monitors
  start_web
  ns_ok "NovaShield is running. Open the dashboard in your browser."
}

stop_all(){
  stop_monitors || true
  stop_web || true
  close_session
}

restart_monitors(){ stop_monitors || true; start_monitors; }

# ------------------------------ AUTH UTILITIES --------------------------------
add_user(){
  local user pass salt
  read -rp "New username: " user
  read -rsp "Password (won't echo): " pass; echo
  salt=$(awk -F': ' '/auth_salt:/ {print $2}' "$NS_CONF" | tr -d ' "')
  [ -z "$salt" ] && salt="change-this-salt"
  local sha; sha=$(printf '%s' "${salt}:${pass}" | sha256sum | awk '{print $1}')
  # store in sessions.JSON userdb
  if [ ! -f "$NS_SESS_DB" ]; then echo '{}' >"$NS_SESS_DB"; fi
  python3 - "$NS_SESS_DB" "$user" "$sha" <<'PY'
import json,sys
p,u,s=sys.argv[1],sys.argv[2],sys.argv[3]
try:
  j=json.load(open(p))
except: j={}
ud=j.get('_userdb',{})
ud[u]=s
j['_userdb']=ud
open(p,'w').write(json.dumps(j))
print('User stored')
PY
  ns_ok "User '$user' added. Enable auth by setting security.auth_enabled: true in config.yaml"
}

# ----------------------------------- CLI -------------------------------------
usage(){ cat <<USG
NovaShield Terminal ${NS_VERSION} — JARVIS Edition
Usage: $0 [--install|--start|--stop|--restart-monitors|--status|--backup|--version-snapshot|--encrypt <path>|--decrypt <file.enc>|--web-start|--web-stop|--menu|--add-user]
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
      11) local host port; host=$(awk -F': ' '/host:/ {print $2}' "$NS_CONF" | head -n1 | tr -d '" '); port=$(awk -F': ' '/port:/ {print $2}' "$NS_CONF" | head -n1 | tr -d '" '); [ -z "$host" ] && host="127.0.0.1"; [ -z "$port" ] && port=8765; echo "Open: http://${host}:${port}";;
      12) break;;
      *) echo "?";;
    esac
  done
}

# ------------------------------- ARG PARSING ---------------------------------
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
  --menu) menu;;
  *) usage; exit 1;;
esac
