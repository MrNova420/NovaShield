#!/usr/bin/env bash
# ==============================================================================
# NovaShield Terminal 2.0+ — All‑in‑One Installer & Runtime (Improved)
# ==============================================================================
# Author: Nova (MrNova) + Copilot Full Rewrite
# License: MIT
# Platform: Termux (Android) + Linux (Debian/Ubuntu/Arch/Fedora)
# Purpose: Fully private, modular terminal environment with monitors, web UI,
#          encryption, backups, versions, alerts, and manual overrides.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------------- VERSION ----------------------------------
NS_VERSION="2.1.0"

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
NS_BACKUP_DIR="${NS_HOME}/backups"

# ---------------------------- RUNTIME CONSTANTS ------------------------------
NS_DEFAULT_PORT=8765
NS_DEFAULT_HOST="127.0.0.1"

# ------------------------------ SELF RESOLUTION ------------------------------
NS_SELF="$(realpath "${BASH_SOURCE[0]}")"

# ---------------------------------- COLORS -----------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --------------------------------- LOGGING -----------------------------------
ns_now() { date '+%Y-%m-%d %H:%M:%S'; }
ns_log() { echo -e "$(ns_now) [INFO ] $*" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_warn(){ echo -e "${YELLOW}$(ns_now) [WARN ] $*${NC}" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_err() { echo -e "${RED}$(ns_now) [ERROR] $*${NC}" | tee -a "${NS_HOME}/launcher.log" >&2; }
ns_ok()  { echo -e "${GREEN}✔ $*${NC}"; }

error_handler() {
  ns_err "Unexpected error at line $1: $2"
  exit 1
}
trap 'error_handler $LINENO "$BASH_COMMAND"' ERR

# -------------------------------- UTILITIES ----------------------------------
die(){ ns_err "$*"; exit 1; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }
write_file(){ local path="$1"; local mode="$2"; shift 2; install -m "$mode" /dev/null "$path" 2>/dev/null || true; cat >"$path"; }
append_file(){ local path="$1"; shift; cat >>"$path"; }
safe_mkdir(){ mkdir -p "$1" && chmod 700 "$1"; }

# --------------------------- ENVIRONMENT DETECTION ---------------------------
IS_TERMUX=0
if uname -a | grep -iq termux || [[ -n "${PREFIX:-}" && "$PREFIX" == *"/com.termux/"* ]]; then
  IS_TERMUX=1
fi

OS_FAMILY="linux"
[[ "$(uname -s)" != "Linux" ]] && OS_FAMILY="other"

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
  for d in "$NS_BIN" "$NS_LOGS" "$NS_WWW" "$NS_MODULES" "$NS_PROJECTS" \
           "$NS_VERSIONS" "$NS_KEYS" "$NS_CTRL" "$NS_TMP" "$NS_PID" \
           "$NS_LAUNCHER_BACKUPS" "$NS_BACKUP_DIR"; do safe_mkdir "$d"; done
  : >"$NS_ALERTS" || true
  echo "$NS_VERSION" >"$NS_VERSION_FILE"
  echo "$NS_SELF" >"$NS_SELF_PATH_FILE"
}

# ------------------------------- DEFAULT CONF --------------------------------
write_default_config(){
  [[ -f "$NS_CONF" ]] && return 0
  ns_log "Writing default config to $NS_CONF"
  write_file "$NS_CONF" 600 <<'YAML'
version: "2.1.0"
http:
  host: 127.0.0.1
  port: 8765
  allow_lan: false
monitors:
  cpu:         { enabled: true,  interval_sec: 3, warn_load: 2.50, crit_load: 4.50 }
  memory:      { enabled: true,  interval_sec: 3, warn_pct: 80,  crit_pct: 92 }
  disk:        { enabled: true,  interval_sec: 10, warn_pct: 85, crit_pct: 95, mount: "/" }
  network:     { enabled: true,  interval_sec: 5, iface: "", ping_host: "1.1.1.1", loss_warn: 20 }
  integrity:   { enabled: true,  interval_sec: 60, watch_paths: ["/system/bin","/system/xbin","/usr/bin"] }
logging:
  keep_days: 14
  alerts_enabled: true
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
    smtp_host: ""
    smtp_port: 587
    username: ""
    password: ""
    to: []
  sms:
    enabled: false
    provider: ""
    sid: ""
    token: ""
    from: ""
    to: []
updates:
  enabled: false
  source: ""
sync:
  enabled: false
  method: ""
  remote: ""
YAML
}

# -------------------------------- DEPENDENCIES -------------------------------
install_dependencies(){
  ns_log "Checking dependencies..."
  local need=(python3 openssl awk sed grep tar gzip df du ps top uname head tail cut tr sha256sum curl)
  for c in "${need[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      ns_warn "$c missing; attempting install"
      PKG_INSTALL "$c" || true
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
  require_cmd openssl
  local bits
  bits=$(awk -F': ' '/rsa_bits:/ {print $2}' "$NS_CONF" 2>/dev/null || echo 4096)
  [[ ! -f "${NS_KEYS}/private.pem" || ! -f "${NS_KEYS}/public.pem" ]] && {
    ns_log "Generating RSA keypair (${bits} bits)"
    openssl genrsa -out "${NS_KEYS}/private.pem" "$bits"
    openssl rsa -in "${NS_KEYS}/private.pem" -pubout -out "${NS_KEYS}/public.pem"
    chmod 600 "${NS_KEYS}/private.pem"
  }
  local aesf
  aesf=$(awk -F': ' '/aes_key_file:/ {print $2}' "$NS_CONF" | tr -d '"' | tr -d ' ' || true)
  [[ -z "$aesf" ]] && aesf="keys/aes.key"
  [[ ! -f "${NS_HOME}/${aesf}" ]] && {
    ns_log "Generating AES key file: ${aesf}"
    head -c 64 /dev/urandom >"${NS_HOME}/${aesf}"
    chmod 600 "${NS_HOME}/${aesf}"
  }
}

# ------------------------------ ENCRYPTION UTIL ------------------------------
aes_key_path(){ awk -F': ' '/aes_key_file:/ {print $2}' "$NS_CONF" | tr -d '"' | tr -d ' ' ; }
enc_file(){
  local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"
  [[ ! -f "$in" ]] && die "Input file not found: $in"
  openssl enc -aes-256-cbc -salt -pbkdf2 -in "$in" -out "$out" -pass file:"$key"
  ns_ok "Encrypted: $in → $out"
}

dec_file(){
  local in="$1"; local out="$2"; local key="${NS_HOME}/$(aes_key_path)"
  [[ ! -f "$in" ]] && die "Input file not found: $in"
  openssl enc -d -aes-256-cbc -pbkdf2 -in "$in" -out "$out" -pass file:"$key"
  ns_ok "Decrypted: $in → $out"
}

enc_dir(){
  local dir="$1"; local out="$2"
  [[ ! -d "$dir" ]] && die "Input dir not found: $dir"
  local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"
  tar -C "$dir" -czf "$tmp" . || tar -czf "$tmp" "$dir"
  enc_file "$tmp" "$out"
  rm -f "$tmp"
}

dec_dir(){
  local in="$1"; local outdir="$2"; local tmp="${NS_TMP}/tmp-$(date +%s).tar.gz"
  dec_file "$in" "$tmp"
  mkdir -p "$outdir"
  tar -C "$outdir" -xzf "$tmp"
  rm -f "$tmp"
}

# ------------------------------- BACKUPS/VERS --------------------------------
backup_snapshot(){
  local stamp
  stamp=$(date '+%Y%m%d-%H%M%S')
  local tmp_tar="${NS_TMP}/backup-${stamp}.tar.gz"
  mkdir -p "$NS_BACKUP_DIR"
  ns_log "Creating backup snapshot: $stamp"
  local incl=( )
  while IFS= read -r line; do
    case "$line" in
      *projects*) incl+=("$NS_PROJECTS") ;;
      *modules*)  incl+=("$NS_MODULES") ;;
      *config.yaml*) incl+=("$NS_CONF") ;;
    esac
  done < <(awk '/backup:/,0' "$NS_CONF" 2>/dev/null || true)
  [[ ${#incl[@]} -eq 0 ]] && incl=("$NS_PROJECTS" "$NS_MODULES" "$NS_CONF")
  tar -czf "$tmp_tar" "${incl[@]}"
  local enc_enabled
  enc_enabled=$(awk -F': ' '/encrypt:/ {print $2}' "$NS_CONF" | head -n1 | tr -d ' ')
  local final
  if [[ "$enc_enabled" == "true" ]]; then
    final="${NS_BACKUP_DIR}/backup-${stamp}.tar.gz.enc"
    enc_file "$tmp_tar" "$final"
    rm -f "$tmp_tar"
  else
    final="${NS_BACKUP_DIR}/backup-${stamp}.tar.gz"
    mv "$tmp_tar" "$final"
  fi
  ns_ok "Backup created: $final"
  rotate_backups
}

rotate_backups(){
  local max_keep
  max_keep=$(awk -F': ' '/max_keep:/ {print $2}' "$NS_CONF" | tr -d ' ' || echo 10)
  ls -1t "$NS_BACKUP_DIR" 2>/dev/null | tail -n +$((max_keep+1)) | while read -r f; do
    ns_warn "Removing old backup: $f"; rm -f "$NS_BACKUP_DIR/$f" || true
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
  ns_ok "Version snapshot created: $vdir"
}

# -------------------------------- ALERTS -------------------------------------
alert(){
  local level="$1"; shift
  local msg="$*"; local line
  line="$(ns_now) [$level] $msg"
  echo "$line" | tee -a "$NS_ALERTS" >&2
}

# ------------------------------- MONITORS ------------------------------------
monitor_enabled(){
  local name="$1"
  [[ -f "${NS_CTRL}/${name}.disabled" ]] && return 1 || return 0
}

write_json(){ local path="$1"; shift; printf '%s' "$*" >"$path"; }

_monitor_cpu(){
  local interval warn crit
  interval=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' ')
  warn=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /warn_load/) print $2 }' "$NS_CONF" | tr -d ' ')
  crit=$(awk -F': ' '/cpu:/,/}/ { if($1 ~ /crit_load/) print $2 }' "$NS_CONF" | tr -d ' ')
  [[ -z "$interval" ]] && interval=3
  while true; do
    monitor_enabled cpu || { sleep "$interval"; continue; }
    local load1
    load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
    local lvl="OK"
    (( $(echo "$load1 >= $crit" | bc -l) )) && lvl="CRIT" || (( $(echo "$load1 >= $warn" | bc -l) )) && lvl="WARN"
    local js
    js="{\"ts\":\"$(ns_now)\",\"load1\":$load1,\"warn\":$warn,\"crit\":$crit,\"level\":\"$lvl\"}"
    write_json "${NS_LOGS}/cpu.json" "$js"
    [[ "$lvl" == "CRIT" ]] && alert CRIT "CPU load high: $load1" || [[ "$lvl" == "WARN" ]] && alert WARN "CPU load elevated: $load1"
    sleep "$interval"
  done
}

_monitor_mem(){
  local interval warn crit
  interval=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' ')
  warn=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /warn_pct/) print $2 }' "$NS_CONF" | tr -d ' ')
  crit=$(awk -F': ' '/memory:/,/}/ { if($1 ~ /crit_pct/) print $2 }' "$NS_CONF" | tr -d ' ')
  [[ -z "$interval" ]] && interval=3
  while true; do
    monitor_enabled memory || { sleep "$interval"; continue; }
    local mem_total mem_avail mem_used pct
    if grep -q MemAvailable /proc/meminfo 2>/dev/null; then
      mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
      mem_avail=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
      mem_used=$((mem_total-mem_avail))
      pct=$((mem_used*100/mem_total))
    else
      read -r _ mem_total _ < <(free -k | awk '/Mem:/ {print $2, $3, $4}')
      mem_used=$(free -k | awk '/Mem:/ {print $3}')
      pct=$((mem_used*100/mem_total))
    fi
    local lvl="OK"
    [[ "$pct" -ge "$crit" ]] && lvl="CRIT" || [[ "$pct" -ge "$warn" ]] && lvl="WARN"
    local js
    js="{\"ts\":\"$(ns_now)\",\"used_pct\":$pct,\"warn\":$warn,\"crit\":$crit,\"level\":\"$lvl\"}"
    write_json "${NS_LOGS}/memory.json" "$js"
    [[ "$lvl" == "CRIT" ]] && alert CRIT "Memory high: ${pct}%" || [[ "$lvl" == "WARN" ]] && alert WARN "Memory elevated: ${pct}%"
    sleep "$interval"
  done
}

_monitor_disk(){
  local interval warn crit mount
  interval=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' ')
  warn=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /warn_pct/) print $2 }' "$NS_CONF" | tr -d ' ')
  crit=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /crit_pct/) print $2 }' "$NS_CONF" | tr -d ' ')
  mount=$(awk -F': ' '/disk:/,/}/ { if($1 ~ /mount:/) print $2 }' "$NS_CONF" | tr -d '" ')
  [[ -z "$interval" ]] && interval=10
  [[ -z "$mount" ]] && mount="/"
  while true; do
    monitor_enabled disk || { sleep "$interval"; continue; }
    local use
    use=$(df -P "$mount" | awk 'END {gsub("%","",$5); print $5+0}')
    local lvl="OK"
    [[ "$use" -ge "$crit" ]] && lvl="CRIT" || [[ "$use" -ge "$warn" ]] && lvl="WARN"
    local js
    js="{\"ts\":\"$(ns_now)\",\"use_pct\":$use,\"warn\":$warn,\"crit\":$crit,\"mount\":\"$mount\",\"level\":\"$lvl\"}"
    write_json "${NS_LOGS}/disk.json" "$js"
    [[ "$lvl" == "CRIT" ]] && alert CRIT "Disk $mount high: ${use}%" || [[ "$lvl" == "WARN" ]] && alert WARN "Disk $mount elevated: ${use}%"
    sleep "$interval"
  done
}

_monitor_net(){
  local interval iface pingh warnloss
  interval=$(awk -F': ' '/network:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' ')
  iface=$(awk -F': ' '/network:/,/}/ { if($1 ~ /iface:/) print $2 }' "$NS_CONF" | tr -d '" ')
  pingh=$(awk -F': ' '/network:/,/}/ { if($1 ~ /ping_host/) print $2 }' "$NS_CONF" | tr -d '" ')
  warnloss=$(awk -F': ' '/network:/,/}/ { if($1 ~ /loss_warn/) print $2 }' "$NS_CONF" | tr -d ' ')
  [[ -z "$interval" ]] && interval=5
  [[ -z "$pingh" ]] && pingh="1.1.1.1"
  while true; do
    monitor_enabled network || { sleep "$interval"; continue; }
    local ip pubip loss=0 avg=0
    if command -v ip >/dev/null 2>&1; then
      ip=$(ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
      [[ -z "$ip" ]] && ip=$(ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.' | head -n1)
    else
      ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1)
      [[ -z "$ip" ]] && ip=$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | head -n1)
    fi
    if command -v ping >/dev/null 2>&1; then
      local out; out=$(ping -c 3 -w 3 "$pingh" 2>/dev/null || true)
      loss=$(echo "$out" | awk -F',' '/packet loss/ {gsub("%","",$3); gsub(" ","",$3); print $3+0}' 2>/dev/null || echo 0)
      avg=$(echo "$out" | awk -F'/' '/rtt/ {print $5}' 2>/dev/null || echo 0)
    fi
    pubip=""
    for e in icanhazip.com ifconfig.me api.ipify.org; do
      pubip=$(curl -s --max-time 2 "$e" || true)
      [[ -n "$pubip" ]] && break
    done
    local lvl="OK"; [[ "$loss" -ge "$warnloss" ]] && lvl="WARN"
    local js
    js="{\"ts\":\"$(ns_now)\",\"ip\":\"${ip:-}\",\"public_ip\":\"${pubip:-}\",\"loss_pct\":${loss:-0},\"rtt_avg_ms\":${avg:-0},\"level\":\"$lvl\"}"
    write_json "${NS_LOGS}/network.json" "$js"
    [[ "$lvl" == "WARN" ]] && alert WARN "Network loss ${loss}% to ${pingh}"
    sleep "$interval"
  done
}

_monitor_integrity(){
  local interval; interval=$(awk -F': ' '/integrity:/,/}/ { if($1 ~ /interval_sec/) print $2 }' "$NS_CONF" | tr -d ' ')
  [[ -z "$interval" ]] && interval=60
  local list
  list=$(awk -F'\- ' '/watch_paths:/{flag=1;next}/]/{flag=0}flag{print $2}' "$NS_CONF" 2>/dev/null || true)
  while true; do
    monitor_enabled integrity || { sleep "$interval"; continue; }
    for p in $list; do
      p=$(echo "$p" | tr -d '"' | tr -d ' ')
      [[ -d "$p" ]] || continue
      local sumfile="${NS_LOGS}/integrity.$(echo "$p" | tr '/' '_').sha"
      if [[ -f "$sumfile" ]]; then
        local changes=0
        while IFS= read -r line; do
          local have file
          have=$(echo "$line" | awk '{print $1}')
          file=$(echo "$line" | awk '{print $2}')
          if [[ -f "$file" ]]; then
            local now
            now=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            [[ "$now" != "$have" ]] && changes=$((changes+1))
          fi
        done <"$sumfile"
        [[ "$changes" -gt 0 ]] && alert WARN "Integrity changes in $p: $changes files"
      fi
      find "$p" -maxdepth 1 -type f -print0 2>/dev/null | head -zn 200 | xargs -0 sha256sum >"$sumfile" 2>/dev/null || true
    done
    write_json "${NS_LOGS}/integrity.json" "{\"ts\":\"$(ns_now)\"}"
    sleep "$interval"
  done
}

start_monitors(){
  ns_log "Starting monitors..."
  stop_monitors || true
  (_monitor_cpu &)  echo $! >"${NS_PID}/cpu.pid"
  (_monitor_mem &)  echo $! >"${NS_PID}/memory.pid"
  (_monitor_disk &) echo $! >"${NS_PID}/disk.pid"
  (_monitor_net &)  echo $! >"${NS_PID}/network.pid"
  (_monitor_integrity &) echo $! >"${NS_PID}/integrity.pid"
  ns_ok "Monitors started"
}

stop_monitors(){
  local any=0
  for p in cpu memory disk network integrity; do
    if [[ -f "${NS_PID}/${p}.pid" ]]; then
      kill "$(cat "${NS_PID}/${p}.pid")" 2>/dev/null || true
      rm -f "${NS_PID}/${p}.pid"
      any=1
    fi
  done
  [[ "$any" -eq 1 ]] && ns_ok "Monitors stopped"
}

# ------------------------------ PY WEB SERVER --------------------------------
write_server_py(){
  write_file "${NS_WWW}/server.py" 700 <<'PY'
#!/usr/bin/env python3
import json, os, sys, time, threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

NS_HOME = os.path.expanduser('~/.novashield')
NS_WWW  = os.path.join(NS_HOME, 'www')
NS_LOGS = os.path.join(NS_HOME, 'logs')
NS_CTRL = os.path.join(NS_HOME, 'control')
NS_BIN  = os.path.join(NS_HOME, 'bin')
SELF_PATH_FILE = os.path.join(NS_BIN, 'self_path')

INDEX = os.path.join(NS_WWW, 'index.html')
CONFIG = os.path.join(NS_HOME, 'config.yaml')

def read_text(path, default=''):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return default

def read_json(path, default=None):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.loads(f.read())
    except Exception:
        return default

def last_lines(path, n=100):
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 1024
            data = b''
            while size > 0 and n > 0:
                step = min(block, size)
                size -= step
                f.seek(size)
                buf = f.read(step)
                data = buf + data
                n -= buf.count(b'\n')
            return data.decode('utf-8', 'ignore').splitlines()[-100:]
    except Exception:
        return []

class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, status=200, ctype='application/json'):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/':
            self._set_headers(200, 'text/html; charset=utf-8')
            html = read_text(INDEX, '<h1>NovaShield</h1>')
            self.wfile.write(html.encode('utf-8'))
            return
        if parsed.path.startswith('/static/'):
            # Serve static files under www, but block .pem/.key/config.yaml
            p = os.path.join(NS_WWW, parsed.path[len('/static/'):])
            if os.path.commonpath([NS_WWW, os.path.abspath(os.path.dirname(p))]) != NS_WWW or any(x in p for x in ['.pem', '.key', 'config.yaml']):
                self._set_headers(404); self.wfile.write(b'{}'); return
            if os.path.exists(p) and os.path.isfile(p):
                ctype = 'text/plain'
                if p.endswith('.js'): ctype = 'application/javascript'
                if p.endswith('.css'): ctype = 'text/css'
                if p.endswith('.html'): ctype = 'text/html; charset=utf-8'
                self._set_headers(200, ctype)
                self.wfile.write(read_text(p).encode('utf-8'))
                return
            self._set_headers(404); self.wfile.write(b'{}'); return
        if parsed.path == '/api/status':
            data = {
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'cpu':   read_json(os.path.join(NS_LOGS, 'cpu.json'), {}),
                'memory':read_json(os.path.join(NS_LOGS, 'memory.json'), {}),
                'disk':  read_json(os.path.join(NS_LOGS, 'disk.json'), {}),
                'network':read_json(os.path.join(NS_LOGS, 'network.json'), {}),
                'integrity':read_json(os.path.join(NS_LOGS, 'integrity.json'), {}),
                'alerts': last_lines(os.path.join(NS_LOGS, 'alerts.log'), 200),
                'projects_count': len([x for x in os.listdir(os.path.join(NS_HOME, 'projects')) if not x.startswith('.')]) if os.path.exists(os.path.join(NS_HOME, 'projects')) else 0,
                'modules_count': len([x for x in os.listdir(os.path.join(NS_HOME, 'modules')) if not x.startswith('.')]) if os.path.exists(os.path.join(NS_HOME, 'modules')) else 0,
                'version': read_text(os.path.join(NS_HOME, 'version.txt'), 'unknown'),
            }
            self._set_headers(200)
            self.wfile.write(json.dumps(data).encode('utf-8'))
            return
        if parsed.path == '/api/logs':
            q = parse_qs(parsed.query)
            name = (q.get('name', ['launcher.log'])[0]).replace('..','')
            p = os.path.join(NS_HOME, name)
            if not os.path.exists(p): p = os.path.join(NS_LOGS, name)
            self._set_headers(200)
            self.wfile.write(json.dumps({'name': name, 'lines': last_lines(p, 200)}).encode('utf-8'))
            return
        if parsed.path == '/api/config':
            self._set_headers(200)
            self.wfile.write(read_text(CONFIG, '').encode('utf-8'))
            return
        self._set_headers(404); self.wfile.write(b'{"error":"not found"}')

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''
        if parsed.path == '/api/control':
            try:
                data = json.loads(body or '{}')
            except Exception:
                data = {}
            action = data.get('action','')
            target = data.get('target','')
            # Enable/disable monitors via control files
            flag = os.path.join(NS_CTRL, f'{target}.disabled')
            if action == 'enable' and target:
                try:
                    if os.path.exists(flag): os.remove(flag)
                    self._set_headers(200)
                    self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception:
                    pass
            if action == 'disable' and target:
                try:
                    open(flag,'w').close()
                    self._set_headers(200)
                    self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception:
                    pass
            self_path = read_text(SELF_PATH_FILE).strip() or os.path.join(NS_HOME, 'bin', 'novashield.sh')
            if action in ('backup','version','restart_monitors'):
                try:
                    if action=='backup': os.system(f'"{self_path}" --backup >/dev/null 2>&1 &')
                    if action=='version': os.system(f'"{self_path}" --version-snapshot >/dev/null 2>&1 &')
                    if action=='restart_monitors': os.system(f'"{self_path}" --restart-monitors >/dev/null 2>&1 &')
                    self._set_headers(200); self.wfile.write(json.dumps({'ok':True}).encode('utf-8')); return
                except Exception:
                    pass
        self._set_headers(400); self.wfile.write(b'{"ok":false}')

if __name__ == '__main__':
    host='127.0.0.1'; port=8765
    try:
        with open(CONFIG,'r',encoding='utf-8') as f:
            t=f.read()
            for line in t.splitlines():
                if 'host:' in line and 'http:' not in line:
                    host=line.split(':',1)[1].strip()
                if 'port:' in line and 'http:' not in line:
                    port=int(line.split(':',1)[1].strip())
                if 'allow_lan:' in line and 'true' in line:
                    host='0.0.0.0'
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
  write_file "${NS_WWW}/index.html" 644 <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NovaShield Terminal 2.1</title>
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
  <header>
    <h1>NovaShield Terminal <span class="ver">2.1</span></h1>
    <div class="actions">
      <button id="btn-refresh">Refresh</button>
      <button data-act="backup">Backup</button>
      <button data-act="version">Version Snapshot</button>
      <button data-act="restart_monitors">Restart Monitors</button>
    </div>
  </header>
  <main>
    <section class="grid">
      <div class="card" id="card-cpu"><h2>CPU</h2><pre class="value" id="cpu"></pre></div>
      <div class="card" id="card-mem"><h2>Memory</h2><pre class="value" id="mem"></pre></div>
      <div class="card" id="card-disk"><h2>Disk</h2><pre class="value" id="disk"></pre></div>
      <div class="card" id="card-net"><h2>Network</h2><pre class="value" id="net"></pre></div>
      <div class="card" id="card-int"><h2>Integrity</h2><pre class="value" id="int"></pre></div>
      <div class="card" id="card-meta"><h2>Meta</h2><pre class="value" id="meta"></pre></div>
    </section>
    <section class="panels">
      <div class="panel">
        <h3>Alerts</h3>
        <ul id="alerts"></ul>
      </div>
      <div class="panel">
        <h3>Monitors Control</h3>
        <div class="toggles">
          <button class="toggle" data-target="cpu">CPU toggle</button>
          <button class="toggle" data-target="memory">Memory toggle</button>
          <button class="toggle" data-target="disk">Disk toggle</button>
          <button class="toggle" data-target="network">Network toggle</button>
          <button class="toggle" data-target="integrity">Integrity toggle</button>
        </div>
      </div>
      <div class="panel">
        <h3>Config</h3>
        <pre id="config"></pre>
      </div>
    </section>
  </main>
  <script src="/static/app.js"></script>
</body>
</html>
HTML

  write_file "${NS_WWW}/style.css" 644 <<'CSS'
:root { --bg:#0b0f17; --card:#111827; --text:#e5e7eb; --muted:#9ca3af; --ok:#10b981; --warn:#f59e0b; --crit:#ef4444; --accent:#6366f1; }
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(180deg,#05070c,#0b0f17);color:var(--text);font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid #111}
h1{margin:0;font-size:20px;letter-spacing:.5px}
.ver{color:var(--accent);font-weight:600}
.actions button{background:#1f2937;color:#fff;border:1px solid #2b3240;border-radius:10px;padding:8px 12px;margin-left:8px;cursor:pointer}
main{padding:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:12px;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.card h2{margin:0 0 8px 0;font-size:16px;color:#d1d5db}
.value{margin:0;font-size:13px;color:#cbd5e1;white-space:pre-wrap}
.panels{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:14px}
.panel{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:12px}
.panel h3{margin:0 0 8px 0;color:#d1d5db}
#alerts{list-style:none;margin:0;padding:0;max-height:260px;overflow:auto}
#alerts li{font-size:12px;border-bottom:1px solid #1f2937;padding:6px 0;color:#e5e7eb}
.toggle{background:#0f172a;border:1px solid #334155;border-radius:10px;color:#fff;padding:8px 10px;margin:4px;cursor:pointer}
.ok{outline:2px solid var(--ok)}
.warn{outline:2px solid var(--warn)}
.crit{outline:2px solid var(--crit)}
@media (max-width: 980px){ .panels{grid-template-columns:1fr} }
CSS

  write_file "${NS_WWW}/app.js" 644 <<'JS'
async function refresh(){
  const r = await fetch('/api/status');
  const j = await r.json();
  document.getElementById('cpu').textContent = JSON.stringify(j.cpu,null,2);
  document.getElementById('mem').textContent = JSON.stringify(j.memory,null,2);
  document.getElementById('disk').textContent = JSON.stringify(j.disk,null,2);
  document.getElementById('net').textContent = JSON.stringify(j.network,null,2);
  document.getElementById('int').textContent = JSON.stringify(j.integrity,null,2);
  document.getElementById('meta').textContent = JSON.stringify({projects:j.projects_count,modules:j.modules_count,version:j.version,ts:j.ts},null,2);
  const ul = document.getElementById('alerts');
  ul.innerHTML='';
  (j.alerts||[]).slice(-100).reverse().forEach(line=>{ const li=document.createElement('li'); li.textContent=line; ul.appendChild(li);});
  const levels = {cpu:j.cpu?.level, memory:j.memory?.level, disk:j.disk?.level, network:j.network?.level};
  const map = {OK:'ok', WARN:'warn', CRIT:'crit'};
  Object.entries(levels).forEach(([k,v])=>{ const el=document.getElementById('card-'+(k==='memory'?'mem':k.substr(0,3))); if(!el) return; el.classList.remove('ok','warn','crit'); if(map[v]) el.classList.add(map[v]);});
  const conf = await (await fetch('/api/config')).text();
  document.getElementById('config').textContent = conf;
}

function post(action,target){
  return fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,target})});
}

document.getElementById('btn-refresh').onclick=refresh;
Array.from(document.querySelectorAll('.toggle')).forEach(b=>{
  b.onclick=async()=>{ const t=b.dataset.target; await post('disable',t); await post('enable',t); refresh(); };
});
Array.from(document.querySelectorAll('[data-act]')).forEach(b=>{
  b.onclick=async()=>{ const a=b.dataset.act; await post(a,''); setTimeout(refresh,1000); };
});

refresh(); setInterval(refresh, 4000);
JS
}

# ------------------------------ SERVICES SETUP -------------------------------
setup_termux_service(){
  if ! command -v sv-enable >/dev/null 2>&1; then ns_warn "termux-services not found"; return 0; fi
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
  if ! command -v systemctl >/dev/null 2>&1; then ns_warn "systemd not available"; return 0; fi
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
  if [[ -f "${NS_PID}/web.pid" ]]; then
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
  write_server_py
  write_dashboard
  setup_termux_service || true
  setup_systemd_user || true
  ns_ok "Install complete. Use: $0 --start"
}

# --------------------------------- STARTUP -----------------------------------
start_all(){
  ensure_dirs; write_default_config; generate_keys
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

# ----------------------------------- CLI -------------------------------------
usage(){ cat <<USG
NovaShield Terminal ${NS_VERSION}
Usage: $0 [--install|--start|--stop|--restart-monitors|--status|--backup|--version-snapshot|--encrypt <path>|--decrypt <file.enc>|--web-start|--web-stop|--menu]
USG
}

status(){
  echo "Version: ${NS_VERSION}"
  echo "Home   : ${NS_HOME}"
  echo "Termux : ${IS_TERMUX}"
  echo "Web PID: $(cat "${NS_PID}/web.pid" 2>/dev/null || echo '-')"
  for p in cpu memory disk network integrity; do
    echo "$p PID: $(cat "${NS_PID}/${p}.pid" 2>/dev/null || echo '-')"
  done
}

menu(){
  PS3=$'\nSelect: '
  select opt in "Start All" "Stop All" "Restart Monitors" "Status" "Backup" "Version Snapshot" "Encrypt File" "Decrypt File" "Quit"; do
    case $REPLY in
      1) start_all;;
      2) stop_all;;
      3) restart_monitors;;
      4) status;;
      5) backup_snapshot;;
      6) version_snapshot;;
      7) read -rp "Path to file/dir: " p; if [[ -d "$p" ]]; then enc_dir "$p" "$p.tar.gz.enc"; else enc_file "$p" "$p.enc"; fi;;
      8) read -rp "Path to .enc: " p; read -rp "Output path: " o; dec_file "$p" "$o";;
      9) break;;
      *) echo "?";;
    esac
  done
}

# ------------------------------- ARG PARSING ---------------------------------
if [[ $# -eq 0 ]]; then usage; exit 0; fi

case "${1:-}" in
  --install) install_all;;
  --start) start_all;;
  --stop) stop_all;;
  --restart-monitors) restart_monitors;;
  --status) status;;
  --backup) backup_snapshot;;
  --version-snapshot) version_snapshot;;
  --encrypt)
    shift; p="${1:-}"; [[ -z "$p" ]] && die "--encrypt <path>"; if [[ -d "$p" ]]; then enc_dir "$p" "$p.tar.gz.enc"; else enc_file "$p" "$p.enc"; fi;;
  --decrypt)
    shift; p="${1:-}"; [[ -z "$p" ]] && die "--decrypt <file.enc>"; read -rp "Output path: " o; dec_file "$p" "$o";;
  --web-start) start_web;;
  --web-stop) stop_web;;
  --menu) menu;;
  *) usage; exit 1;;
 esac
