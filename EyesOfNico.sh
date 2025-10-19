#!/usr/bin/env bash
# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ EyesOfNico — Terminal Server Monitor (Bash TUI)                     ┃
# ┃ Theme: Neon Synthwave | Gradient borders | Full black background    ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
set -o pipefail  # tolerant (no -e/-u)

# ======================== Colors / Theme ================================
c_supports_256() { tput colors 2>/dev/null | awk '{exit !($1>=256)}'; }
# ANSI helpers
fg256(){ printf "\e[38;5;%sm" "$1"; } # foreground
bg256(){ printf "\e[48;5;%sm" "$1"; } # background
RESET=$(tput sgr0 2>/dev/null || printf "\e[0m")
BOLD=$(tput bold 2>/dev/null || printf "\e[1m")
DIM=$(tput dim 2>/dev/null || printf "\e[2m")
UL=$(tput smul 2>/dev/null || printf "\e[4m")
CURSOR_HIDE(){ tput civis 2>/dev/null || true; }
CURSOR_SHOW(){ tput cnorm 2>/dev/null || true; }

# Synthwave palette (magenta → purple → blue)
if c_supports_256; then
  COL_MAG=199  # neon magenta
  COL_PUR=129  # neon purple
  COL_BLU=33   # neon blue
  COL_TITLE=15 # bright white
else
  COL_MAG=5; COL_PUR=5; COL_BLU=4; COL_TITLE=7
fi
# Status colors
COL_OK=46      # green
COL_BAD=196    # red
COL_DIV=240    # divider gray
COL_EMPTY=240

BG_BLACK="$(bg256 0)"
FG_TITLE="$(fg256 $COL_TITLE)$BOLD"
FG_DIM="$(fg256 245)$DIM"

# ======================== Config =======================================
REFRESH="1"
VIEW="dashboard"  # dashboard | single
SINGLE=""         # logins/cmds/net/services/docker/journal/help/sys
STOP=false
SAFE_MODE=0
NO_ALT_SCREEN=0
PAUSED=0

# Thresholds
CPU_WARN=70  # ≥ => vermelho
MEM_WARN=75  # ≥ => vermelho

# ======================== Environment ==================================
has_cmd() { command -v "$1" >/dev/null 2>&1; }
is_systemd() { has_cmd systemctl; }

AUTH_LOG_FILE=""
detect_auth_log() {
  if [[ -f /var/log/auth.log ]]; then AUTH_LOG_FILE="/var/log/auth.log"; fi
  if [[ -z "$AUTH_LOG_FILE" && -f /var/log/secure ]]; then AUTH_LOG_FILE="/var/log/secure"; fi
}

# ======================== LOGINS (today + geo) ==========================
has_cmd() { command -v "$1" >/dev/null 2>&1; }  # (garante que existe)

# cache simples na sessão para não bater no serviço a cada refresh
declare -A IPINFO_CACHE
IPINFO_TTL=3600  # (não usado no exemplo simples; cache de sessão já é suficiente)

# extrai IPs de uma linha de log (procura token "from <ip>")
extract_ips_from_line() {
  awk '{
    for (i=1;i<=NF;i++) if ($i=="from" && (i+1)<=NF) {
      ip=$(i+1);
      gsub(/[,;]$/, "", ip);                     # tira vírgula/ponto-e-vírgula do final
      if (ip ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/)  # IPv4
        print ip;
      else if (ip ~ /^[0-9A-Fa-f:]+$/)          # IPv6 simples
        print ip;
    }
  }'
}

ip_info_lookup() {
  local ip="$1"

  # SAFE_MODE: não faz rede
  if [[ "${SAFE_MODE:-0}" -eq 1 ]]; then
    echo "$ip - ? - ?"; return 0
  fi

  # evita consulta para IPs locais/privados
  if [[ "$ip" =~ ^127\. ]] || [[ "$ip" == "::1" ]] \
     || [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] \
     || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] \
     || [[ "$ip" =~ ^fe80: ]] || [[ "$ip" =~ ^fc00: ]] || [[ "$ip" =~ ^fd00: ]]; then
    echo "$ip - local - LAN"; return 0
  fi

  # cache de sessão
  if [[ -n "${IPINFO_CACHE[$ip]:-}" ]]; then
    echo "${IPINFO_CACHE[$ip]}"; return 0
  fi

  if has_cmd curl; then
    local response country org
    response=$(curl -m 4 --connect-timeout 3 -s -H 'User-Agent: EyesOfNico/1.0' "https://ipinfo.io/$ip/json" || echo "")
    country=$(printf "%s" "$response" | awk -F'"' '/"country":/ {print $4; exit}')
    org=$(printf "%s" "$response" | awk -F'"' '/"org":/ {print $4; exit}')
    [[ -z "$country" ]] && country="?"
    [[ -z "$org" ]] && org="?"
    IPINFO_CACHE[$ip]="$ip - $country - $org"
    echo "${IPINFO_CACHE[$ip]}"
  else
    echo "$ip - ? - ?"
  fi
}

logins_today_geo() {
  local LOG="${AUTH_LOG_FILE:-/var/log/auth.log}"

  # Se houver arquivo, detecta o formato da data (ISO vs "Oct 19")
  if [[ -r "$LOG" ]]; then
    # Olha algumas linhas para decidir o formato
    local head_sample
    head_sample=$(head -n 5 "$LOG" 2>/dev/null || true)

    local TODAY_ISO TODAY_MDE
    TODAY_ISO=$(date -u +'%Y-%m-%d')          # p/ linhas tipo 2025-10-19T...
    TODAY_MDE=$(LC_TIME=C date +'%b %e')      # p/ linhas tipo "Oct 19"

    if printf '%s\n' "$head_sample" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
      # Formato ISO no arquivo
      grep -E "^${TODAY_ISO}" "$LOG" 2>/dev/null || true
    else
      # Formato Mês/Dia no arquivo
      grep -E "^${TODAY_MDE}" "$LOG" 2>/dev/null || true
    fi

  # Fallback: journalctl dos serviços ssh/sshd, desde "today" (independente de formato)
  elif has_cmd journalctl; then
    journalctl -u ssh -u sshd --since today --no-pager -o short-iso 2>/dev/null || true
  else
    echo "-- No log source available --"
  fi
}

# função de alto nível: imprime relatório completo (de hoje, com geo)
render_logins_today_geo() {
  local LOG="${AUTH_LOG_FILE:-/var/log/auth.log}"
  local tmp; tmp=$(mktemp)

  if [[ -r "$LOG" ]]; then
    # Detecta formato do arquivo e filtra apenas o dia atual
    local head_sample TODAY_ISO TODAY_MDE
    head_sample=$(head -n 5 "$LOG" 2>/dev/null || true)
    TODAY_ISO=$(date -u +'%Y-%m-%d')
    TODAY_MDE=$(LC_TIME=C date +'%b %e')

    if printf '%s\n' "$head_sample" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
      grep -E "^${TODAY_ISO}" "$LOG" 2>/dev/null > "$tmp" || true
    else
      grep -E "^${TODAY_MDE}" "$LOG" 2>/dev/null > "$tmp" || true
    fi
    SRC="${LOG}"

  elif has_cmd journalctl; then
    # Pega somente de hoje (independente do locale) e força saída ISO
    journalctl -u ssh -u sshd --since today --no-pager -o short-iso 2>/dev/null > "$tmp" || true
    SRC="journalctl (ssh/sshd, today)"
  else
    echo "-- No log source available --"
    rm -f "$tmp"; return 0
  fi

  echo "Analyzing TODAY from ${SRC}..."
  echo "============================ SSH LOGINS (TODAY) ============================"

  echo
  echo "✅ Accepted (password/publickey):"
  grep -F "Accepted" "$tmp" 2>/dev/null \
    | extract_ips_from_line \
    | sort | uniq -c | sort -nr

  echo
  echo "❌ Failed password:"
  grep -F "Failed password" "$tmp" 2>/dev/null \
    | extract_ips_from_line \
    | sort | uniq -c | sort -nr

  echo
  echo "🚫 Invalid user:"
  grep -F "Invalid user" "$tmp" 2>/dev/null \
    | extract_ips_from_line \
    | sort | uniq -c | sort -nr

  echo
  echo "💻 sudo commands:"
  grep -F 'sudo:' "$tmp" 2>/dev/null | awk '{for(i=6;i<=NF;i++) printf (i==6?$i:" "$i); print ""}'

  echo
  echo "📍 Top IPs (geo-enriched):"
  awk '
    /Accepted/ || /Failed password/ || /Invalid user/ {
      for (i=1;i<=NF;i++) if ($i=="from" && (i+1)<=NF) {
        ip=$(i+1); gsub(/[,;]$/, "", ip);
        if (ip ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || ip ~ /^[0-9A-Fa-f:]+$/) print ip;
      }
    }
  ' "$tmp" \
  | sort | uniq -c | sort -nr \
  | while read -r count ip; do
      info=$(ip_info_lookup "$ip")
      printf " %4s %s\n" "$count" "$info"
    done

  echo
  echo "👤 Accepted as root:"
  grep -F "Accepted" "$tmp" 2>/dev/null | grep -F " for root " || true

  echo
  echo "👥 Users that tried to log in:"
  {
    grep -F "Failed password" "$tmp" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="for" && (i+1)<=NF){print $(i+1); break}}'
    grep -F "Invalid user"   "$tmp" 2>/dev/null | awk '{for(i=1;i<=NF-1;i++) if($i=="user"){print $(i+1); break}}'
  } | sort | uniq -c | sort -nr

  echo
  echo "Analysis finished."
  rm -f "$tmp"
}

# ======================== UI Helpers ===================================
cols=120; rows=40

grad_color_at(){
  local pos=$1 len=$2
  local t1=$((len/3)) t2=$((2*len/3))
  if (( pos < t1 )); then fg256 $COL_MAG
  elif (( pos < t2 )); then fg256 $COL_PUR
  else fg256 $COL_BLU
  fi
}

update_term_size() {
  cols=$(tput cols 2>/dev/null || echo 120)
  rows=$(tput lines 2>/dev/null || echo 40)
  ((cols<60)) && cols=60
  ((rows<20)) && rows=20
}

clear_alt() {
  printf "%s" "$BG_BLACK"
  if [[ -t 1 && "${NO_ALT_SCREEN}" != "1" ]]; then
    CURSOR_HIDE
    tput smcup 2>/dev/null || printf "\033[2J\033[H"
  else
    printf "\033[2J\033[H"
  fi
}
restore_screen() {
  if [[ -t 1 && "${NO_ALT_SCREEN}" != "1" ]]; then
    tput rmcup 2>/dev/null || true;
  fi
  CURSOR_SHOW
  printf "%s" "$RESET"
}
wipe_screen() { printf "%s\033[2J\033[H" "$BG_BLACK"; }

cuf() { printf "\033[%dC" "${1:-1}"; }   # move cursor para a direita
cub() { printf "\033[%dD" "${1:-1}"; }   # move cursor para a esquerda

# ── Header com gradiente ────────────────────────────────────────────────
header() {
  local title=" EyesOfNico — Neon Synthwave "
  local line_len=$((cols-2))
  tput cup 0 0
  printf "%s" "$BG_BLACK"
  printf "%s┏" "$(fg256 $COL_MAG)"
  for ((i=0;i<line_len;i++)); do printf "%s━" "$(grad_color_at "$i" "$line_len")"; done
  printf "%s┓%s\n" "$(fg256 $COL_BLU)" "$RESET"

  tput cup 1 2; printf "%s%s%s" "$FG_TITLE" "$title" "$RESET"
  tput cup 1 $((cols-38)); printf "%s%s | Refresh: %ss%s" "$FG_DIM" "$(date '+%F %T')" "$REFRESH" "$RESET"

  tput cup 2 0
  printf "%s" "$BG_BLACK"
  printf "%s┗" "$(fg256 $COL_MAG)"
  for ((i=0;i<line_len;i++)); do printf "%s━" "$(grad_color_at "$i" "$line_len")"; done
  printf "%s┛%s" "$(fg256 $COL_BLU)" "$RESET"
}

# ── Box com gradiente nos lados ─────────────────────────────────────────
box() {
  local y=$1 x=$2 h=$3 w=$4 title="$5"
  ((h<3||w<10)) && return
  local inner=$((w-2))
  # topo
  tput cup "$y" "$x"; printf "%s" "$BG_BLACK"
  printf "%s┏" "$(fg256 $COL_MAG)"
  for ((i=0;i<inner;i++)); do printf "%s━" "$(grad_color_at "$i" "$inner")"; done
  printf "%s┓%s" "$(fg256 $COL_BLU)" "$RESET"
  # título
  if [[ -n "$title" ]]; then
    tput cup "$y" $((x+2)); printf "%s%s%s" "$FG_TITLE" "$title" "$RESET"
  fi
  # laterais
  for ((i=1;i<h-1;i++)); do
    tput cup $((y+i)) "$x";         printf "%s%s┃%s" "$BG_BLACK" "$(fg256 $COL_MAG)" "$RESET"
    tput cup $((y+i)) $((x+w-1));   printf "%s%s┃%s" "$BG_BLACK" "$(fg256 $COL_BLU)" "$RESET"
  done
  # base
  tput cup $((y+h-1)) "$x"; printf "%s" "$BG_BLACK"
  printf "%s┗" "$(fg256 $COL_MAG)"
  for ((i=0;i<inner;i++)); do printf "%s━" "$(grad_color_at "$i" "$inner")"; done
  printf "%s┛%s" "$(fg256 $COL_BLU)" "$RESET"
}

# Keybars
keybar_dash() {
  tput cup $((rows-1)) 0
  printf "%s[D]ashboard [Y]Sys+ [L]ogins [C]mds [N]et [S]ervices [K]Docker [J]ournal [H]elp [P]ause [Q]uit (paused=%s)%s" \
    "$FG_DIM" "$PAUSED" "$RESET"
}
keybar_single() {
  tput cup $((rows-1)) 0
  printf "%s[D]ashboard [Q]uit%s" "$FG_DIM" "$RESET"
}

# print helpers
print_in_box() {
  local y=$1 x=$2 h=$3 w=$4
  local max_lines=$((h-2)); ((max_lines<=0)) && return
  local width=$((w-2)); ((width<1)) && width=1
  local buf=() line
  while IFS= read -r line; do
    line=${line%$'\r'}; buf+=("${line}")
    (( ${#buf[@]} >= max_lines )) && break
  done
  local i
  for ((i=0;i<max_lines;i++)); do
    local out="${buf[i]-}"
    tput cup $((y+1+i)) $((x+1)); printf "%s%-*s%s" "$BG_BLACK" "$width" "${out:0:$width}" "$RESET"
  done
}
render_in_box() { local y=$1 x=$2 h=$3 w=$4; shift 4; local tmp; tmp=$(mktemp); "$@" > "$tmp"; print_in_box "$y" "$x" "$h" "$w" < "$tmp"; rm -f "$tmp"; }

# read key
read_key() {
  local k k1 k2; key=""
  IFS= read -rsn1 -t "$REFRESH" k || { key=""; return; }
  if [[ "$k" == $'\e' ]]; then
    IFS= read -rsn1 -t 0.001 k1 || true
    IFS= read -rsn1 -t 0.001 k2 || true
    key=""; return
  fi
  key="$k"
}

on_exit() { STOP=true; restore_screen; }
trap on_exit INT TERM
RESIZED=0
on_resize() { RESIZED=1; }
trap on_resize WINCH

# ======================== Metrics / Collectors ==========================
get_loadavg() { awk '{print $1, $2, $3}' /proc/loadavg 2>/dev/null || echo "N/A"; }
get_uptime()  { awk '{printf "%.1f h", $1/3600}' /proc/uptime 2>/dev/null || echo "N/A"; }
get_cpu_usage() {
  local a b c idle_a idle_b total_a total_b
  read -r _ a b c idle_a _ < /proc/stat; total_a=$((a+b+c+idle_a))
  sleep 0.12
  read -r _ a b c idle_b _ < /proc/stat; total_b=$((a+b+c+idle_b))
  local dt=$((total_b-total_a)) di=$((idle_b-idle_a))
  [[ $dt -gt 0 ]] && awk -v dt=$dt -v di=$di 'BEGIN{ printf "%.1f", 100*(1 - di/dt) }' || echo "N/A"
}
get_mem() {
  awk '/MemTotal:/{t=$2}/MemAvailable:/{a=$2}END{if(t>0) printf "%.1f/%.1f GB (%.0f%%)", (t-a)/1048576, t/1048576, 100*(t-a)/t}' /proc/meminfo 2>/dev/null || echo "N/A";
}
get_mem_pct() {
  awk '/MemTotal:/{t=$2}/MemAvailable:/{a=$2}END{if(t>0) printf "%.0f", 100*(t-a)/t; else print 0}' /proc/meminfo 2>/dev/null || echo 0
}
get_disks() {
  df -h --output=source,pcent,size,used,avail,target -x tmpfs -x devtmpfs 2>/dev/null | sed 1d | head -n 8;
}
get_top_cpu() { ps -eo pid,comm,%cpu,%mem --sort=-%cpu 2>/dev/null | head -n 20; }
get_top_mem() { ps -eo pid,comm,%cpu,%mem --sort=-%mem 2>/dev/null | head -n 20; }

# ===================== Dashboard NET: per-interface throughput ==========
declare -A NET_LAST_RX NET_LAST_TX
NET_LAST_T_NS=0
net_now_ns() { date +%s%N; }
net_snapshot_ifaces() {
  local ifn rx tx
  for d in /sys/class/net/*; do
    ifn=$(basename "$d"); [[ "$ifn" == "lo" ]] && continue
    rx=$(cat "$d/statistics/rx_bytes" 2>/dev/null || echo 0)
    tx=$(cat "$d/statistics/tx_bytes" 2>/dev/null || echo 0)
    printf "%s:%s:%s\n" "$ifn" "$rx" "$tx"
  done
}
fmt_rate_bytes() {
  local bps="$1"
  if command -v numfmt >/dev/null 2>&1; then
    printf "%s/s" "$(numfmt --to=iec "$bps" 2>/dev/null)"
  else
    if (( bps < 1024 )); then printf "%d B/s" "$bps"
    else awk -v x="$bps" 'BEGIN{ s="KMGTPE"; i=0; while (x>=1024 && i<length(s)) {x/=1024; i++} printf "%.1f %cB/s", x, substr(s,i,1) }'
    fi
  fi
}
get_net_throughput_table() {
  local now_ns=$(net_now_ns) dt_ns=$(( now_ns - NET_LAST_T_NS )) have_baseline=1
  (( NET_LAST_T_NS == 0 )) && have_baseline=0
  local lines=() line ifn rx tx last_rx last_tx dr dt rxps txps
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    IFS=: read -r ifn rx tx <<<"$line"
    if (( have_baseline == 1 )); then
      last_rx=${NET_LAST_RX[$ifn]:-0}; last_tx=${NET_LAST_TX[$ifn]:-0}
      dr=$(( rx - last_rx )); (( dr < 0 )) && dr=0
      dt=$(( tx - last_tx )); (( dt < 0 )) && dt=0
      rxps=$(awk -v d="$dr" -v ns="$dt_ns" 'BEGIN{ if(ns<=0) ns=1; printf "%.0f", d/(ns/1e9) }')
      txps=$(awk -v d="$dt" -v ns="$dt_ns" 'BEGIN{ if(ns<=0) ns=1; printf "%.0f", d/(ns/1e9) }')
      lines+=( "$(printf "%-8s %12s %12s" "$ifn" "$(fmt_rate_bytes "$rxps")" "$(fmt_rate_bytes "$txps")")" )
    fi
    NET_LAST_RX[$ifn]="$rx"
    NET_LAST_TX[$ifn]="$tx"
  done < <(net_snapshot_ifaces)
  NET_LAST_T_NS="$now_ns"
  printf "IFACE      RX/s         TX/s\n"
  if (( have_baseline == 0 )); then printf "(collecting baseline...)\n"; return; fi
  printf "%s\n" "${lines[@]}" | sort -k2nr
}

# ======================== NET (single: btop-like graphs) ================
NET_LAST_RX=0; NET_LAST_TX=0; NET_LAST_T=0
NET_HIST_RX=(); NET_HIST_TX=()
NET_MAXPTS=60
NET_PEAK_RX=0; NET_PEAK_TX=0
arr_last() { local -n A=$1; local n=${#A[@]}; if ((n>0)); then printf "%s" "${A[n-1]}"; else printf "0"; fi; }
net_now_bytes() {
  local sum_rx=0 sum_tx=0 v
  for d in /sys/class/net/*; do
    local n=$(basename "$d"); [[ "$n" == "lo" ]] && continue
    v=$(cat "$d/statistics/rx_bytes" 2>/dev/null || echo 0); ((sum_rx+=v))
    v=$(cat "$d/statistics/tx_bytes" 2>/dev/null || echo 0); ((sum_tx+=v))
  done
  printf "%s %s\n" "$sum_rx" "$sum_tx"
}
net_human() {
  local b=$1
  if has_cmd numfmt; then numfmt --to=iec "$b" 2>/dev/null || echo "$b";
  else awk -v b="$b" 'function f(x){if (x<1024){printf "%.0f B/s",x; exit} s="KMGTPE"; i=0; while (x>=1024 && i<length(s)) {x/=1024; i++} printf "%.1f %cB/s", x, substr(s,i,1)} BEGIN{f(b)}'
  fi
}
net_init_chart() {
  NET_HIST_RX=(); NET_HIST_TX=()
  NET_PEAK_RX=0; NET_PEAK_TX=0
  local axis_margin=12
  local inner_w=$((SV_w-2))
  local chart_w=$(( inner_w - axis_margin ))
  ((chart_w<10)) && chart_w=10
  NET_MAXPTS=$chart_w
  read -r NET_LAST_RX NET_LAST_TX < <(net_now_bytes)
  NET_LAST_T=$(date +%s%N)
}
net_sample_bps() {
  local now_rx now_tx; read -r now_rx now_tx < <(net_now_bytes)
  local tnow=$(date +%s%N)
  local dt_ns=$((tnow - NET_LAST_T)); ((dt_ns<=0)) && dt_ns=1
  local dt_s=$(awk -v n="$dt_ns" 'BEGIN{printf "%.6f", n/1e9}')
  local dr=$((now_rx - NET_LAST_RX)); ((dr<0)) && dr=0
  local dtb=$((now_tx - NET_LAST_TX)); ((dtb<0)) && dtb=0
  local rxps=$(awk -v d="$dr" -v s="$dt_s" 'BEGIN{printf "%.0f", d/s}')
  local txps=$(awk -v d="$dtb" -v s="$dt_s" 'BEGIN{printf "%.0f", d/s}')
  NET_LAST_RX=$now_rx; NET_LAST_TX=$now_tx; NET_LAST_T=$tnow
  NET_HIST_RX+=("$rxps"); NET_HIST_TX+=("$txps")
  ((${#NET_HIST_RX[@]}>NET_MAXPTS)) && NET_HIST_RX=("${NET_HIST_RX[@]: -NET_MAXPTS}")
  ((${#NET_HIST_TX[@]}>NET_MAXPTS)) && NET_HIST_TX=("${NET_HIST_TX[@]: -NET_MAXPTS}")
  ((rxps>NET_PEAK_RX)) && NET_PEAK_RX=$rxps
  ((txps>NET_PEAK_TX)) && NET_PEAK_TX=$txps
}
net_draw_graph_text() {
  local h=$((SV_h-6)); ((h<8)) && h=8
  local half=$((h/2))
  local inner_w=$((SV_w-2))
  local axis_margin=12
  local chart_w=$(( inner_w - axis_margin ))
  ((chart_w<10)) && chart_w=10
  local max=1 v
  for v in "${NET_HIST_RX[@]}" "${NET_HIST_TX[@]}"; do ((v>max)) && max=$v; done
  local chars=(" " "▁" "▂" "▃" "▄" "▅" "▆" "▇" "█")
  build_panel() {
    local -n hist=$1; local height=$2; local title="$3"
    local -a rows=(); local i
    for ((i=0;i<height;i++)); do rows[i]=$(printf "%-${inner_w}s" ""); done
    local -a tick_rows tick_vals
    tick_rows=(0 $((height*1/4)) $((height*2/4)) $((height*3/4)) $((height-1)))
    tick_vals=("$max" $((max*75/100)) $((max*50/100)) $((max*25/100)) 0)
    for ((i=0;i<height;i++)); do
      local label="" local t
      for t in 0 1 2 3 4; do if (( i == tick_rows[t] )); then label=$(net_human "${tick_vals[t]}"); break; fi; done
      printf -v left "%-*s" $((axis_margin-1)) "${label}"
      rows[i]="${left}│$(printf "%-${chart_w}s" "")"
    done
    local len=${#hist[@]}
    if ((len>0)); then
      local start=$((len - chart_w)); ((start<0)) && start=0
      local col=0 idx
      for ((idx=start; idx<len; idx++)); do
        local val=${hist[idx]:-0}; local level=0
        if ((max>0)); then
          level=$(awk -v v="$val" -v m="$max" -v H="$height" 'BEGIN{ x=v/m*H; if (x<0) x=0; if (x>H) x=H; printf "%d",(x<1 && v>0)?1:int(x) }')
        fi
        ((col>=chart_w)) && break
        local r
        for ((r=0; r<height; r++)); do
          local ch=" "
          if ((r < level)); then local step=$(( (r*8)/height )); ((step>8)) && step=8; ch=${chars[step]}; fi
          local row_index=$((height-1-r))
          local line="${rows[row_index]}"; local pos=$((axis_margin + 1 + col))
          rows[row_index]="${line:0:pos}${ch}${line:pos+1}"
        done
        ((col++))
      done
    fi
    printf "%s\n" " ${title} scale: window max $(net_human "$max") | points: ${#hist[@]}"
    printf "%s\n" "${rows[@]}"
  }
  {
    local cur_rx cur_tx; cur_rx=$(arr_last NET_HIST_RX); cur_tx=$(arr_last NET_HIST_TX)
    printf " RX: %s (peak %s)  TX: %s (peak %s)\n" \
      "$(net_human "$cur_rx")" "$(net_human "$NET_PEAK_RX")" \
      "$(net_human "$cur_tx")" "$(net_human "$NET_PEAK_TX")"
    build_panel NET_HIST_RX "$half" "RX"
    build_panel NET_HIST_TX "$half" "TX"
    printf "\nTop IFs (instant):\n"
    local snap1=() snap2=() ifs=() ifn rx1 tx1 rx2 tx2
    for d in /sys/class/net/*; do
      ifn=$(basename "$d"); [[ "$ifn" == "lo" ]] && continue
      rx1=$(cat "$d/statistics/rx_bytes" 2>/dev/null || echo 0)
      tx1=$(cat "$d/statistics/tx_bytes" 2>/dev/null || echo 0)
      ifs+=("$ifn"); snap1+=("$rx1:$tx1")
    done
    sleep 0.2
    for d in /sys/class/net/*; do
      ifn=$(basename "$d"); [[ "$ifn" == "lo" ]] && continue
      rx2=$(cat "$d/statistics/rx_bytes" 2>/dev/null || echo 0)
      tx2=$(cat "$d/statistics/tx_bytes" 2>/dev/null || echo 0)
      snap2+=("$rx2:$tx2")
    done
    {
      local i n=${#ifs[@]}
      for ((i=0;i<n;i++)); do
        IFS=: read -r a b <<< "${snap1[i]}"
        IFS=: read -r c d <<< "${snap2[i]}"
        local dr=$((c-a)); ((dr<0)) && dr=0
        local dt=$((d-b)); ((dt<0)) && dt=0
        printf "%-8s %12d %12d\n" "${ifs[i]}" "$dr" "$dt"
      done
    } | sort -k2nr | head -n 6
  }
}

# ======================== Histories (other views) =======================
detect_auth_log
get_recent_logins() {
  if [[ -n "$AUTH_LOG_FILE" && -r "$AUTH_LOG_FILE" ]]; then
    grep -E "(Accepted|Failed).*ssh" "$AUTH_LOG_FILE" | tail -n 50
  elif has_cmd journalctl; then
    journalctl -u ssh -n 80 --no-pager 2>/dev/null | tail -n 50
  else
    echo "-- No entries --"
  fi
}

# ======================== CMDS (hist) — robust fallbacks ===============
_parse_bash_history() {
  local file="$1" ts line
  [[ -r "$file" ]] || return 1
  while IFS= read -r line; do
    if [[ "$line" =~ ^\#([0-9]{9,})$ ]]; then
      ts="${BASH_REMATCH[1]}"
    else
      if [[ -n "$ts" ]]; then
        date -d "@$ts" '+%F %T' 2>/dev/null | awk -v cmd="$line" '{printf "%s %s\n",$0,cmd}'
        ts=""
      else
        printf "%s\n" "$line"
      fi
    fi
  done < "$file"
}

_parse_zsh_history() {
  local file="$1" line ts cmd
  [[ -r "$file" ]] || return 1
  while IFS= read -r line; do
    if [[ "$line" =~ ^:[\ \t]*([0-9]{9,})\:[0-9]+\;(.*)$ ]]; then
      ts="${BASH_REMATCH[1]}"; cmd="${BASH_REMATCH[2]}"
      date -d "@$ts" '+%F %T' 2>/dev/null | awk -v cmd="$cmd" '{printf "%s %s\n",$0,cmd}'
    elif [[ -n "$line" ]]; then
      printf "%s\n" "$line"
    fi
  done < "$file"
}

_parse_fish_history() {
  local file="$1" line cmd when
  [[ -r "$file" ]] || return 1
  while IFS= read -r line; do
    if [[ "$line" =~ ^[\ \t]*-\ cmd:\ (.*)$ ]]; then
      cmd="${BASH_REMATCH[1]}"
      cmd="${cmd%$'\r'}"
      IFS= read -r line || true
      if [[ "$line" =~ ^[\ \t]*when:\ ([0-9]{9,})$ ]]; then
        when="${BASH_REMATCH[1]}"
        date -d "@$when" '+%F %T' 2>/dev/null | awk -v cmd="$cmd" '{printf "%s %s\n",$0,cmd}'
      else
        printf "%s\n" "$cmd"
      fi
    fi
  done < "$file"
}

get_recent_cmds() {
  if command -v ausearch >/dev/null 2>&1 && [[ -r /var/log/audit/audit.log ]]; then
    ausearch -k cmdlog --start recent 2>/dev/null \
    | awk -F ' exe=| comm=| cwd=' ' /type=EXECVE/ || / comm=| exe=| cwd=/ {
        exe=""; comm=""; cwd="";
        for (i=1;i<=NF;i++){
          if ($i ~ /^\/.*$/ && $(i-1) ~ /exe=$/) exe=$i
          if ($(i) ~ /^[^ ]+$/ && $(i-1) ~ /comm=$/) comm=$i
          if ($i ~ /^\/.*$/ && $(i-1) ~ /cwd=$/) cwd=$i
        }
        if (comm!="" || exe!="") printf "%-20s exe=%s cwd=%s\n", comm, exe, cwd
      }' \
    | tail -n 60
    [[ ${PIPESTATUS[0]} -eq 0 ]] && return 0
  fi
  if command -v lastcomm >/dev/null 2.1; then
    lastcomm 2>/dev/null | head -n 60
    [[ ${PIPESTATUS[0]} -eq 0 ]] && return 0
  fi
  local H="$HOME/.bash_history"
  if [[ -r "$H" ]]; then _parse_bash_history "$H" | tail -n 60; [[ ${PIPESTATUS[0]} -eq 0 ]] && return 0; fi
  local Z="$HOME/.zsh_history"
  if [[ -r "$Z" ]]; then _parse_zsh_history "$Z" | tail -n 60; [[ ${PIPESTATUS[0]} -eq 0 ]] && return 0; fi
  local F="$HOME/.local/share/fish/fish_history"
  if [[ -r "$F" ]]; then _parse_fish_history "$F" | tail -n 60; [[ ${PIPESTATUS[0]} -eq 0 ]] && return 0; fi
  cat <<'MSG'
No command history available. Enable one of the options below and this box will fill automatically:
• auditd (recommended – with args/UID):
  sudo apt install -y auditd audispd-plugins
  sudo tee /etc/audit/rules.d/99-cmdlog.rules >/dev/null <<'EOF'
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k cmdlog
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k cmdlog
EOF
  sudo augenrules --load || sudo systemctl restart auditd
• psacct/acct (lightweight):
  sudo apt install -y acct
  sudo systemctl enable --now acct
• Interactive shell history:
  # bash: export HISTTIMEFORMAT='%F %T ' and write-on-prompt
  # zsh : ~/.zsh_history (': EPOCH:FLAGS;CMD')
  # fish: ~/.local/share/fish/fish_history
MSG
}

get_services_summary() {
  if [[ "${SAFE_MODE:-0}" -eq 1 ]] || ! is_systemd; then echo "(SAFE) no systemd."; return; fi
  echo "Failed units:"; (systemctl --failed --no-legend 2>/dev/null || true) | head -n 20
  echo "Key active units:"; for u in sshd ssh docker nginx apache2 cron crond redis mysql mariadb postgresql; do
    systemctl is-active "$u" >/dev/null 2>&1 && printf "%-10s %s\n" "$u" "$(systemctl is-active "$u" 2>/dev/null || echo inactive)"
  done
}
get_docker_summary() {
  if [[ "${SAFE_MODE:-0}" -eq 1 ]] || ! has_cmd docker; then echo "(SAFE) Docker disabled"; return; fi
  docker ps --format '{{.Names}}\t{{.Status}}' 2>/dev/null | head -n 30
}
get_journal_tail() {
  if [[ "${SAFE_MODE:-0}" -eq 1 ]] || ! has_cmd journalctl; then echo "(SAFE) journalctl unavailable"; return; fi
  journalctl -n 80 --no-pager 2>/dev/null
}

# ======================== SYS: barras coloridas =========================
# Retorna cor verde/vermelha conforme threshold
color_for_value() {
  local val=$1 warn=$2
  if (( ${val%%.*} >= warn )); then fg256 $COL_BAD; else fg256 $COL_OK; fi
}

# Barra com FUNDO CINZA (100%) e preenchimento progressivo 1/8 por célula
# Sem movimentos de cursor e com pouquíssimos códigos ANSI (compatível com print_in_box)
draw_bar() {
  local label="$1" pct="$2" width="$3" warn="$4" suffix="$5"
  ((width<10)) && width=10

  # normaliza %
  local p=${pct%%.*}; ((p<0)) && p=0; ((p>100)) && p=100

  # passos fracionários (cada célula = 8 passos)
  local total_steps=$(( width * 8 ))
  local filled_steps=$(( (p * total_steps + 50) / 100 ))  # arredonda
  ((filled_steps<0)) && filled_steps=0
  ((filled_steps>total_steps)) && filled_steps=$total_steps
  local full_cells=$(( filled_steps / 8 ))
  local rem_steps=$(( filled_steps % 8 ))
  local used_cells=$full_cells; ((rem_steps>0)) && used_cells=$((used_cells+1))
  local empty_cells=$(( width - used_cells ))

  # frações 0..7
  local FRACS=(" " "▏" "▎" "▍" "▌" "▋" "▊" "▉")

  # monta strings (sem ANSI por caractere)
  local filled_str="" empty_str=""
  local i
  for ((i=0;i<full_cells;i++)); do filled_str+="█"; done
  ((rem_steps>0)) && filled_str+="${FRACS[$rem_steps]}"
  for ((i=0;i<empty_cells;i++)); do empty_str+="░"; done

  # cabeçalho da métrica
  local col_val; col_val=$(color_for_value "$p" "$warn")
  printf "%s%-8s%s " "$BOLD" "$label" "$RESET"
  printf "%s%3d%%%s" "$col_val" "$p" "$RESET"
  [[ -n "$suffix" ]] && printf " %s" "$suffix"
  printf "\n  "

  # barra final: [ <verde/vermelho>filled </reset><cinza>empty</reset> ]
  printf "["
  printf "%s%s%s" "$col_val" "$filled_str" "$RESET"
  printf "%s%s%s" "$(fg256 $COL_EMPTY)" "$empty_str" "$RESET"
  printf "]\n"
}

# Função que imprime o conteúdo da SYS box (dashboard)
print_sys_summary() {
  local cpu mem_line mem_pct
  cpu=$(get_cpu_usage)
  mem_line=$(get_mem)
  mem_pct=$(get_mem_pct)
  local cpu_int=$(printf "%.0f" "${cpu%.*}.${cpu#*.}" 2>/dev/null || echo 0)

  # CPU
  draw_bar "CPU" "$cpu_int" 28 "$CPU_WARN" "(load: $(get_loadavg))"

  # divisor (não segue a cor do layout — cinza discreto)
  local d=""; for ((i=0;i<34;i++)); do d+="─"; done
  printf "%s%s%s\n" "$(fg256 $COL_DIV)" "$d" "$RESET"

  # MEM
  draw_bar "MEM" "$mem_pct" 28 "$MEM_WARN" "($mem_line)"

  # Uptime
  printf "\n%sUptime:%s %s\n" "$FG_DIM" "$RESET" "$(get_uptime)"
}

# Função que imprime a visão expandida do SYS
print_sys_fullscreen() {
  local cpu mem_line mem_pct
  cpu=$(get_cpu_usage)
  mem_line=$(get_mem)
  mem_pct=$(get_mem_pct)
  local cpu_int=$(printf "%.0f" "${cpu%.*}.${cpu#*.}" 2>/dev/null || echo 0)

  # Barras maiores
  draw_bar "CPU" "$cpu_int" 50 "$CPU_WARN" "(load: $(get_loadavg))"
  local d=""; for ((i=0;i<64;i++)); do d+="─"; done
  printf "%s%s%s\n" "$(fg256 $COL_DIV)" "$d" "$RESET"
  draw_bar "MEM" "$mem_pct" 50 "$MEM_WARN" "($mem_line)"
  printf "%s%s%s\n" "$(fg256 $COL_DIV)" "$d" "$RESET"
  printf "%sUptime:%s %s\n\n" "$FG_DIM" "$RESET" "$(get_uptime)"

  # Tabelas lado a lado: Top CPU | Top MEM
  # Calcula largura simples
  local W=$((cols-6)); ((W<40)) && W=40
  local half=$((W/2))
  # Cabeçalhos
  printf "%s%-*s%s  %s%-*s%s\n" "$BOLD" "$half" "Top CPU (pid/comm/%cpu/%mem)" "$RESET" "$BOLD" "$half" "Top MEM (pid/comm/%cpu/%mem)" "$RESET"
  # Linhas
  paste <(get_top_cpu) <(get_top_mem) | while IFS=$'\t' read -r left right; do
    # Em alguns shells paste usa \t; garantimos largura fixa
    printf "%-*.*s  %-*.*s\n" "$half" "$half" "${left:0:$half}" "$half" "$half" "${right:0:$half}"
  done
}

# ======================== Dashboard ====================================
draw_dashboard_frame() {
  wipe_screen; update_term_size; header
  local y0=3; local h0=$((rows/3)); ((h0<6)) && h0=6
  local w=$((cols/3)); ((w<20)) && w=20
  local x1=0; local x2=$w; local x3=$((2*w))
  local y1=$((y0+h0)); local h1=$((rows/3)); ((h1<6)) && h1=6
  local y2=$((y1+h1)); local h2=$((rows - y2 - 2)); ((h2<5)) && h2=5

  box "$y0" "$x1" "$h0" "$w" " SYS "
  box "$y0" "$x2" "$h0" "$w" " DISKS "
  box "$y0" "$x3" "$h0" "$w" " NET "

  box "$y1" "$x1" "$h1" "$w" " TOP PROCS "
  box "$y1" "$x2" "$h1" "$w" " LOGINS (hist) "
  box "$y1" "$x3" "$h1" "$w" " CMDS (hist) "

  box "$y2" "$x1" "$h2" "$w" " SERVICES "
  box "$y2" "$x2" "$h2" "$w" " DOCKER "
  box "$y2" "$x3" "$h2" "$w" " JOURNAL "

  # SYS (nova renderização bonita)
  render_in_box "$y0" "$x1" "$h0" "$w" print_sys_summary
  # DISKS
  { get_disks; } | print_in_box "$y0" "$x2" "$h0" "$w"
  # NET
  render_in_box "$y0" "$x3" "$h0" "$w" get_net_throughput_table
  # TOP procs (por CPU)
  { get_top_cpu; } | print_in_box "$y1" "$x1" "$h1" "$w"
  # LOGINS
  { get_recent_logins; } | print_in_box "$y1" "$x2" "$h1" "$w"
  # CMDS
  { get_recent_cmds; } | print_in_box "$y1" "$x3" "$h1" "$w"
  # SERVICES
  { get_services_summary; } | print_in_box "$y2" "$x1" "$h2" "$w"
  # DOCKER
  { get_docker_summary; } | print_in_box "$y2" "$x2" "$h2" "$w"
  # JOURNAL
  { get_journal_tail; } | print_in_box "$y2" "$x3" "$h2" "$w"

  keybar_dash
}

update_dashboard() {
  header
  local y0=3; local h0=$((rows/3)); ((h0<6)) && h0=6
  local w=$((cols/3)); local x1=0; local x2=$w; local x3=$((2*w))
  local y1=$((y0+h0)); local h1=$((rows/3)); ((h1<6)) && h1=6
  local y2=$((y1+h1)); local h2=$((rows - y2 - 2)); ((h2<5)) && h2=5

  render_in_box "$y0" "$x1" "$h0" "$w" print_sys_summary
  render_in_box "$y0" "$x3" "$h0" "$w" get_net_throughput_table
  { get_top_cpu; } | print_in_box "$y1" "$x1" "$h1" "$w"
  { get_recent_logins; } | print_in_box "$y1" "$x2" "$h1" "$w"
  { get_recent_cmds; } | print_in_box "$y1" "$x3" "$h1" "$w"
  { get_services_summary; } | print_in_box "$y2" "$x1" "$h2" "$w"
  { get_docker_summary; } | print_in_box "$y2" "$x2" "$h2" "$w"
  { get_journal_tail; } | print_in_box "$y2" "$x3" "$h2" "$w"

  keybar_dash
}

# ======================== Single View (no flicker) ======================
SV_y=3; SV_x=0; SV_h=0; SV_w=0; SV_title=""; SV_fn=""; SV_frame_drawn=0
single_enter() {
  SV_title="$1"; SV_fn="$2"
  wipe_screen; update_term_size; header
  SV_y=3; SV_x=0; SV_h=$((rows-5)); SV_w=$cols
  box "$SV_y" "$SV_x" "$SV_h" "$SV_w" " ${SV_title} "
  keybar_single
  SV_frame_drawn=1
  if [[ "$SINGLE" == "net" ]]; then net_init_chart; fi
}
single_update() {
  header
  if [[ "$SINGLE" == "net" ]]; then
    net_sample_bps
    net_draw_graph_text | print_in_box "$SV_y" "$SV_x" "$SV_h" "$SV_w"
  elif [[ "$SINGLE" == "sys" ]]; then
    print_sys_fullscreen | print_in_box "$SV_y" "$SV_x" "$SV_h" "$SV_w"
  else
    { "$SV_fn"; } | print_in_box "$SV_y" "$SV_x" "$SV_h" "$SV_w"
  fi
  keybar_single
}

# Recalcula medidas e redesenha a moldura atual após resize de terminal
reframe_dashboard() {
  wipe_screen
  update_term_size
  draw_dashboard_frame
}

reframe_single() {
  wipe_screen
  update_term_size
  header
  # recalcula a área da single view
  SV_y=3; SV_x=0; SV_h=$((rows-5)); SV_w=$cols
  box "$SV_y" "$SV_x" "$SV_h" "$SV_w" " ${SV_title} "
  # se for NET, precisamos recalibrar a largura do gráfico
  if [[ "$SINGLE" == "net" ]]; then
    net_init_chart   # reacomoda NET_MAXPTS ao novo SV_w
  fi
  keybar_single
}

# ======================== HELP (content) ================================
help_text() {
  cat <<'EOS'
Keys:
  D = Back to Dashboard
  Y = SYS (expanded)
  L = Logins
  C = Cmds
  N = Net
  S = Services
  K = Docker
  J = Journal
  H = Help
  P = Pause dashboard auto-refresh
  Q = Quit

Flow: Dashboard (summary) → Single View (full screen, live updates).
SYS+: Barras coloridas (verde/normal, vermelho/alto), divisor, uptime, e tabelas Top CPU e Top MEM lado a lado.
NET:
  • Dashboard: per-interface RX/TX (B/s), sorted by RX.
  • Single (N): real-time RX/TX graphs (B/s), labeled Y-axis.
EOS
}

# ======================== Main loop ====================================
main_loop() {
  # assume que existe uma trap:  on_resize() { RESIZED=1; }; trap on_resize WINCH
  RESIZED=${RESIZED:-0}

  clear_alt; update_term_size; draw_dashboard_frame
  while ! $STOP; do
    # Se a janela foi redimensionada, redesenha o frame atual
    if (( RESIZED == 1 )); then
      RESIZED=0
      if [[ "$VIEW" == "dashboard" ]]; then
        wipe_screen
        update_term_size
        draw_dashboard_frame
      else
        # single view: recalcula área e redesenha moldura
        wipe_screen
        update_term_size
        header
        SV_y=3; SV_x=0; SV_h=$((rows-5)); SV_w=$cols
        box "$SV_y" "$SV_x" "$SV_h" "$SV_w" " ${SV_title} "
        [[ "$SINGLE" == "net" ]] && net_init_chart   # recalibra largura do gráfico
        keybar_single
      fi
    fi

    case "$VIEW" in
      dashboard)
        ((PAUSED==0)) && update_dashboard
        read_key
        case "${key:-}" in
          [yY]) VIEW="single"; SINGLE="sys";     single_enter "SYS (expanded)" print_sys_fullscreen ;;
          [lL]) VIEW="single"; SINGLE="logins";  single_enter "LOGINS (today + geo)" render_logins_today_geo ;;
          [cC]) VIEW="single"; SINGLE="cmds";    single_enter "CMDS (hist)"     get_recent_cmds ;;
          [nN]) VIEW="single"; SINGLE="net";     single_enter "NET (graphs + Y axis)" get_net_throughput_table ;;
          [sS]) VIEW="single"; SINGLE="services";single_enter "SERVICES"        get_services_summary ;;
          [kK]) VIEW="single"; SINGLE="docker";  single_enter "DOCKER"          get_docker_summary ;;
          [jJ]) VIEW="single"; SINGLE="journal"; single_enter "JOURNAL"         get_journal_tail ;;
          [hH]) VIEW="single"; SINGLE="help";    single_enter "HELP"            help_text ;;
          [pP]) PAUSED=$((1-PAUSED)) ;;
          [qQ]) break ;;
          *) : ;;
        esac
      ;;
      single)
        single_update
        read_key
        case "${key:-}" in
          [dD]) VIEW="dashboard"; draw_dashboard_frame ;;
          [qQ]) break ;;
          *) : ;;
        esac
      ;;
    esac
  done
}


# ======================== CLI ==========================================
usage() {
  cat <<'EOF'
EyesOfNico — Neon Synthwave Bash TUI
Usage:
  EyesOfNico.sh [--refresh N] [--safe] [--no-alt] [--help]

Options:
  --refresh N   Refresh interval in seconds (default: 1)
  --safe        Fallbacks when docker/systemd/journal are missing
  --no-alt      Do not use the alternate screen (avoid flicker)
  --help        Show this help
EOF
}

while [[ ${1:-} ]]; do
  case "$1" in
    --refresh) REFRESH="${2:-1}"; shift 2;;
    --safe)    SAFE_MODE=1; shift;;
    --no-alt)  NO_ALT_SCREEN=1; shift;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

main_loop
restore_screen
exit 0
