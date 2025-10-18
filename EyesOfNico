#!/usr/bin/env bash
# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃  EyesOfNico — Terminal Hacker 80s Server Monitor (Bash TUI)         ┃
# ┃  Tema: Roxo Neon (Magenta brilhante)                                 ┃
# ┃  Autor: Nathan Menezes (default) / Adaptável                        ┃
# ┃  Licença: MIT                                                       ┃
# ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
# ┃  Recursos:                                                          ┃
# ┃   • Dashboard+ único: tudo em uma tela, por seções/caixas           ┃
# ┃   • CPU/Mem/Load/Uptime, Discos, Rede (delta), Top processos        ┃
# ┃   • Históricos: últimos logins SSH, últimos comandos executados     ┃
# ┃   • Serviços falhando/ativos, Docker (se instalado)                 ┃
# ┃   • Journal: eventos recentes (timestamp)                           ┃
# ┃  Navegação: D=Dashboard+ | L=Logins | C=Cmds | N=Net | S=Services   ┃
# ┃             K=Docker | J=Journal | H=Ajuda | Q=Quit                ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

set -o pipefail  # Tolerante: não aborta em erros não-críticos

# ======================== Tema Roxo Neon ================================
# Preferimos magenta brilhante (13) se disponível; fallback para 5.
# Usamos também reverse, bold e sublinhado para vibe "neon".
c_supports_256() { tput colors 2>/dev/null | awk '{exit !($1>=256)}'; }
if c_supports_256; then
  ACCENT=$(tput setaf 13 || true)   # bright magenta
else
  ACCENT=$(tput setaf 5 || true)    # magenta (roxo)
fi
BOLD=$(tput bold || true)
DIM=$(tput dim || true)
RESET=$(tput sgr0 || true)
REV=$(tput rev || true)
UL=$(tput smul || true)

# degrade suave: bordas mais “brilhantes”
EDGE="$ACCENT$BOLD"
TEXT="$ACCENT"

# Se não for TTY, não usar estilos
if [[ ! -t 1 ]]; then ACCENT=""; BOLD=""; DIM=""; RESET=""; REV=""; UL=""; EDGE=""; TEXT=""; fi

# ======================== Configuração =================================
REFRESH="1"                  # intervalo de atualização (s)
CURRENT_VIEW="dashboard"     # dashboard completo
STOP=false
SAFE_MODE=0                  # --safe desativa chamadas “frágeis”
NO_ALT_SCREEN=0              # --no-alt evita tela alternativa

# ======================== Ambiente / detecções ==========================
has_cmd() { command -v "$1" >/dev/null 2>&1; }
is_systemd() { has_cmd systemctl; }

AUTH_LOG_FILE=""
detect_auth_log() {
  if [[ -f /var/log/auth.log ]]; then AUTH_LOG_FILE="/var/log/auth.log"; fi
  if [[ -z "$AUTH_LOG_FILE" && -f /var/log/secure ]]; then AUTH_LOG_FILE="/var/log/secure"; fi
}

# ======================== UI helpers (anti-flicker) =====================
cols=120
rows=40
update_term_size() {
  cols=$(tput cols 2>/dev/null || echo 120)
  rows=$(tput lines 2>/dev/null || echo 40)
}

# Desenha uma caixa com bordas neon
# box y x h w "TITLE"
box() {
  local y=$1 x=$2 h=$3 w=$4 title="$5"
  tput cup "$y" "$x"; printf "${EDGE}┏%0.s━" $(seq 1 $((w-2))); printf "┓${RESET}"
  if [[ -n "$title" ]]; then
    tput cup "$y" $((x+2)); printf "${EDGE}%s${RESET}" "$title"
  fi
  for ((i=1;i< h-1;i++)); do
    tput cup $((y+i)) "$x"; printf "${EDGE}┃${RESET}"
    tput cup $((y+i)) $((x+w-1)); printf "${EDGE}┃${RESET}"
  done
  tput cup $((y+h-1)) "$x"; printf "${EDGE}┗%0.s━" $(seq 1 $((w-2))); printf "┛${RESET}"
}

# Imprime conteúdo dentro da caixa (recorta e limpa excedente)
# print_in_box y x h w <<< "texto"
print_in_box() {
  local y=$1 x=$2 h=$3 w=$4
  local max_lines=$((h-2))
  local line i=0
  while IFS= read -r line; do
    ((i++>max_lines)) && break
    line=${line%$'\r'}
    printf -v line '%-.%ds' $((w-2)) "$line"
    tput cup $((y+i)) $((x+1)); printf "%-${w-2}s" "$line"
  done
  for ((; i<max_lines; i++)); do
    tput cup $((y+1+i)) $((x+1)); printf "%-${w-2}s" ""
  done
}

# Header neon
header() {
  local title=" EyesOfNico — Monitor 80s (Roxo Neon) "
  tput cup 0 0
  printf "${EDGE}┏%0.s━" $(seq 1 $((cols-2))); printf "┓${RESET}\n"
  tput cup 1 2; printf "${EDGE}%s${RESET}" "$title"
  tput cup 1 $((cols-38)); printf "${DIM}Atualização: ${REFRESH}s | %s${RESET}" "$(date '+%F %T')"
  tput cup 2 0; printf "${EDGE}┗%0.s━" $(seq 1 $((cols-2))); printf "┛${RESET}"
}

keybar() {
  tput cup $((rows-1)) 0
  printf "${DIM}[D]ashboard [L]ogins [C]mds [N]et [S]ervices [K]Docker [J]ournal [H]elp [Q]uit${RESET}"
}

# Controle de tela alternativa c/ fallback
clear_alt() {
  if [[ -t 1 && "${NO_ALT_SCREEN}" != "1" ]]; then
    tput civis 2>/dev/null || true
    tput smcup 2>/dev/null || clear
  else
    clear
  fi
}
restore_screen() {
  if [[ -t 1 && "${NO_ALT_SCREEN}" != "1" ]]; then
    tput rmcup 2>/dev/null || true
  fi
  tput cnorm 2>/dev/null || true
}
on_exit() { STOP=true; restore_screen; }
trap on_exit INT TERM
trap 'update_term_size; full_frame=true' WINCH

# ======================== Métricas rápidas ==============================
get_loadavg() { awk '{print $1, $2, $3}' /proc/loadavg 2>/dev/null || echo "N/A"; }
get_uptime()  { awk '{printf "%.1f h", $1/3600}' /proc/uptime 2>/dev/null || echo "N/A"; }
get_cpu_usage() {
  local a b c d idle_a idle_b total_a total_b
  read -r _ a b c idle_a _ < /proc/stat
  total_a=$((a+b+c+idle_a))
  sleep 0.12
  read -r _ a b c idle_b _ < /proc/stat
  total_b=$((a+b+c+idle_b))
  local dt=$((total_b-total_a)) di=$((idle_b-idle_a))
  [[ $dt -gt 0 ]] && awk -v dt=$dt -v di=$di 'BEGIN{ printf "%.1f", 100*(1 - di/dt) }' || echo "N/A"
}
get_mem() {
  awk '/MemTotal:/{t=$2}/MemAvailable:/{a=$2}END{if(t>0) printf "%.1f/%.1f GB (%.0f%%)", (t-a)/1048576, t/1048576, 100*(t-a)/t}' /proc/meminfo 2>/dev/null || echo "N/A"
}
get_disks() { df -h --output=source,pcent,size,used,avail,target -x tmpfs -x devtmpfs 2>/dev/null | sed 1d | head -n 8; }
get_top()   { ps -eo pid,comm,%cpu,%mem --sort=-%cpu 2>/dev/null | head -n 8; }

# Throughput de rede (delta)
last_net_sample=""
get_net_throughput() {
  local sample line ifn rx tx key out; sample=""; out="IFACE   RX/s   TX/s"
  for if in /sys/class/net/*; do
    ifn=$(basename "$if"); [[ "$ifn" == "lo" ]] && continue
    rx=$(cat "$if/statistics/rx_bytes" 2>/dev/null || echo 0)
    tx=$(cat "$if/statistics/tx_bytes" 2>/dev/null || echo 0)
    sample+="$ifn:$rx:$tx\n"
  done
  if [[ -n "$last_net_sample" ]]; then
    while read -r line; do
      [[ -z "$line" ]] && continue
      IFS=":" read -r ifn rx2 tx2 <<< "$line"
      key=$(printf "%s" "$last_net_sample" | grep "^$ifn:" || true)
      if [[ -n "$key" ]]; then
        IFS=":" read -r _ rx1 tx1 <<< "$key"
        local dr=$((rx2-rx1)); local dt=$((tx2-tx1))
        ((dr<0)) && dr=0; ((dt<0)) && dt=0
        out+=$(printf "\n%-6s %6s %6s" "$ifn" "$(numfmt --to=iec $dr 2>/dev/null || echo $dr)" "$(numfmt --to=iec $dt 2>/dev/null || echo $dt)")
      fi
    done <<< "$(printf "%b" "$sample")"
  fi
  last_net_sample="$sample"; printf "%s\n" "$out"
}

# ======================== Históricos com horário =======================
detect_auth_log
get_recent_logins() {
  if [[ -n "$AUTH_LOG_FILE" && -r "$AUTH_LOG_FILE" ]]; then
    grep -E "(Accepted|Failed).*ssh" "$AUTH_LOG_FILE" | tail -n 8
  elif has_cmd journalctl; then
    journalctl -u ssh -n 12 --no-pager 2>/dev/null | tail -n 8
  else
    echo "N/D"
  fi
}
get_recent_cmds() {
  if has_cmd ausearch && [[ -r /var/log/audit/audit.log ]]; then
    # Mostra linhas com exe/comm (últimos eventos)
    ausearch -k cmdlog 2>/dev/null | tail -n 200 | awk -F 'exe=|comm=' '/(exe=|comm=)/{print $0}' | tail -n 8
  elif [[ -r /var/log/audit/audit.log ]]; then
    grep -E "type=EXECVE|exe=" /var/log/audit/audit.log | tail -n 8
  elif has_cmd lastcomm; then
    lastcomm 2>/dev/null | head -n 8
  else
    echo "Habilite auditd ou psacct para histórico."
  fi
}
get_services_summary() {
  if is_systemd; then
    echo "Falhando:"; (systemctl --failed --no-legend 2>/dev/null || true) | head -n 5
    echo "Ativos-chave:"; for u in sshd ssh docker nginx apache2 cron crond redis mysql mariadb postgresql; do
      systemctl is-active "$u" >/dev/null 2>&1 && printf "%-10s %s\n" "$u" "$(systemctl is-active "$u" 2>/dev/null || echo inactive)"
    done
  else
    echo "Sem systemd."
  fi
}
get_docker_summary() {
  if has_cmd docker; then
    docker ps --format '{{.Names}}\t{{.Status}}' 2>/dev/null | head -n 8
  else
    echo "Docker indisponível."
  fi
}
get_journal_tail() {
  if has_cmd journalctl; then
    journalctl -n 10 --no-pager 2>/dev/null || echo "(sem eventos)"
  else
    echo "journalctl indisponível"
  fi
}

# ======================== Layout do Dashboard+ ==========================
# 3 colunas x 3 linhas de painéis (conforme altura do terminal)
frame_positions() {
  y0=3; h0=$((rows/3))
  w_col=$((cols/3))
  x1=0; x2=$w_col; x3=$((2*w_col))

  y1=$((y0+h0)); h1=$((rows/3))

  y2=$((y1+h1)); h2=$((rows - y2 - 2))
  ((h2<5)) && h2=5
}
full_frame=true

draw_frame() {
  update_term_size
  frame_positions
  header
  # linha 0
  box "$y0" "$x1" "$h0" "$w_col" " ${UL}${BOLD}${TEXT}SYS${RESET} "
  box "$y0" "$x2" "$h0" "$w_col" " ${UL}${BOLD}${TEXT}DISKS${RESET} "
  box "$y0" "$x3" "$h0" "$w_col" " ${UL}${BOLD}${TEXT}NET${RESET} "
  # linha 1
  box "$y1" "$x1" "$h1" "$w_col" " ${UL}${BOLD}${TEXT}TOP PROCS${RESET} "
  box "$y1" "$x2" "$h1" "$w_col" " ${UL}${BOLD}${TEXT}LOGINS (hist)${RESET} "
  box "$y1" "$x3" "$h1" "$w_col" " ${UL}${BOLD}${TEXT}CMDS (hist)${RESET} "
  # linha 2
  box "$y2" "$x1" "$h2" "$w_col" " ${UL}${BOLD}${TEXT}SERVICES${RESET} "
  box "$y2" "$x2" "$h2" "$w_col" " ${UL}${BOLD}${TEXT}DOCKER${RESET} "
  box "$y2" "$x3" "$h2" "$w_col" " ${UL}${BOLD}${TEXT}JOURNAL${RESET} "
  keybar
}
update_dashboard() {
  {
    printf "CPU: %s%%   Load: %s   Mem: %s   Uptime: %s\n" "$(get_cpu_usage)" "$(get_loadavg)" "$(get_mem)" "$(get_uptime)"
  } | print_in_box "$y0" "$x1" "$h0" "$w_col"

  { get_disks; }           | print_in_box "$y0" "$x2" "$h0" "$w_col"
  { get_net_throughput; }  | print_in_box "$y0" "$x3" "$h0" "$w_col"

  { get_top; }             | print_in_box "$y1" "$x1" "$h1" "$w_col"
  { get_recent_logins; }   | print_in_box "$y1" "$x2" "$h1" "$w_col"
  { get_recent_cmds; }     | print_in_box "$y1" "$x3" "$h1" "$w_col"

  { get_services_summary; }| print_in_box "$y2" "$x1" "$h2" "$w_col"
  { get_docker_summary; }  | print_in_box "$y2" "$x2" "$h2" "$w_col"
  { get_journal_tail; }    | print_in_box "$y2" "$x3" "$h2" "$w_col"

  header  # atualiza relógio
}

# ======================== Views legadas (opcionais) =====================
view_logins()   { draw_frame; { get_recent_logins; }  | print_in_box "$y1" "$x2" "$h1" "$w_col"; keybar; }
view_cmds()     { draw_frame; { get_recent_cmds; }    | print_in_box "$y1" "$x3" "$h1" "$w_col"; keybar; }
view_net()      { draw_frame; { get_net_throughput; } | print_in_box "$y0" "$x3" "$h0" "$w_col"; keybar; }
view_services() { draw_frame; { get_services_summary; }| print_in_box "$y2" "$x1" "$h2" "$w_col"; keybar; }
view_docker()   { draw_frame; { get_docker_summary; } | print_in_box "$y2" "$x2" "$h2" "$w_col"; keybar; }
view_journal()  { draw_frame; { get_journal_tail; }   | print_in_box "$y2" "$x3" "$h2" "$w_col"; keybar; }
view_help() {
  draw_frame
  {
    cat <<'EOS'
Teclas:
  D = Dashboard+ (tudo em uma tela)   L = Logs de acesso   C = Comandos
  N = Rede                            S = Serviços        K = Docker
  J = Journal                         H = Ajuda           Q = Sair

Novidades:
  • Tema Roxo Neon (magenta brilhante), bordas neon e títulos sublinhados.
  • Sem flicker: não limpamos a tela inteira; atualizamos apenas áreas.
  • Dashboard+ com caixas: SYS, DISKS, NET, TOP PROCS, LOGINS, CMDS,
    SERVICES, DOCKER, JOURNAL — tudo com timestamps onde aplicável.

Dicas:
  • Rode com sudo para máxima visibilidade.
  • Para comandos, habilite auditd (execve) ou psacct (lastcomm).
  • Ajuste --refresh N (1–2s é ótimo). Use --no-alt se seu terminal piscar.

Atalhos rápidos para habilitar auditd:
  sudo apt-get install -y auditd  # ou dnf/pacman equivalente
  echo '-a always,exit -F arch=b64 -S execve -k cmdlog
-a always,exit -F arch=b32 -S execve -k cmdlog' | sudo tee /etc/audit/rules.d/99-cmdlog.rules
  sudo augenrules --load || sudo systemctl restart auditd
EOS
  } | print_in_box "$y1" "$x1" "$h1" "$w_col"
  keybar
}

# ======================== Loop principal ================================
main_loop() {
  clear_alt; update_term_size; frame_positions; draw_frame
  while ! $STOP; do
    case "$CURRENT_VIEW" in
      dashboard) ((full_frame)) && { draw_frame; full_frame=false; }; update_dashboard ;;
      logins)    view_logins    ;;
      cmds)      view_cmds      ;;
      net)       view_net       ;;
      services)  view_services  ;;
      docker)    view_docker    ;;
      journal)   view_journal   ;;
      help)      view_help      ;;
    esac
    IFS= read -rsn1 -t "$REFRESH" key || true
    case "${key:-}" in
      [dD]) CURRENT_VIEW="dashboard" ;;
      [lL]) CURRENT_VIEW="logins"    ;;
      [cC]) CURRENT_VIEW="cmds"      ;;
      [nN]) CURRENT_VIEW="net"       ;;
      [sS]) CURRENT_VIEW="services"  ;;
      [kK]) CURRENT_VIEW="docker"    ;;
      [jJ]) CURRENT_VIEW="journal"   ;;
      [hH]) CURRENT_VIEW="help"      ;;
      [qQ]) break                    ;;
    esac
  done
}

# ======================== CLI ==========================================
usage() {
  cat <<'EOF'
EyesOfNico — Monitor hacker 80s (Bash TUI) — Tema Roxo Neon
Uso: EyesOfNico.sh [--refresh N] [--safe] [--no-alt] [--help]

Opções:
  --refresh N   Tempo de atualização em segundos (padrão: 1)
  --safe        Desativa consultas potencialmente problemáticas (docker/systemd/journal ausentes)
  --no-alt      Não usa a tela alternativa do terminal (evita "piscar")
  --help        Mostra esta ajuda

Atalhos: D L C N S K J H Q
EOF
}

while [[ ${1:-} ]]; do
  case "$1" in
    --refresh) REFRESH="${2:-1}"; shift 2;;
    --safe)    SAFE_MODE=1; shift;;
    --no-alt)  NO_ALT_SCREEN=1; shift;;
    --help|-h) usage; exit 0;;
    *) echo "Opção desconhecida: $1"; usage; exit 1;;
  esac
done

# SAFE MODE: substitui funções “frágeis” se tooling não existir
if [[ "$SAFE_MODE" -eq 1 ]]; then
  has_cmd docker     || get_docker_summary()   { echo "(SAFE) Docker desativado"; };
  is_systemd         || get_services_summary() { echo "(SAFE) Sem systemd"; };
  has_cmd journalctl || get_journal_tail()     { echo "(SAFE) journalctl indisponível"; };
fi

main_loop
restore_screen
exit 0
