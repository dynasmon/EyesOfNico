# EyesOfNico — Terminal Server Monitor (Bash TUI)

**Version:** Neon Synthwave 
**File:** `EyesOfNico.sh`
<img width="1702" height="795" alt="image" src="https://github.com/user-attachments/assets/4ca5325c-8e8c-49a2-978c-c7f8d2a39672" />

---

## 1) What is it?

**EyesOfNico** is a terminal-based server monitor (Bash TUI) with a neon gradient frame and black background. It provides a responsive dashboard and single-focus views:

- **SYS**: CPU %, Load Average, Memory usage, Uptime  
  - Progressive bars (1/8 per cell) with a **fixed gray background (100%)** and a **green/red overlay** based on thresholds.
- **DISKS**: disk usage (`df -h`)
- **NET**: RX/TX throughput per interface
- **TOP PROCS**: processes using the most CPU
- **LOGINS (hist)**: recent SSH events from `auth.log` or `journalctl`
- **CMDS (hist)**: recent command history (multiple fallbacks)
- **SERVICES**: systemd summary (failed + selected active units)
- **DOCKER**: running containers
- **JOURNAL**: recent system logs

**Single views (full screen):**
- **SYS (expanded)** → larger bars + **Top CPU** and **Top MEM** tables side by side
- **NET (live chart)** with Y-axis, window peak, and per-interface instant stats
- Other views (logins, cmds, services, docker, journal)

**Live resize support**: the layout automatically reflows when the terminal is resized (SIGWINCH).

---

## 2) Requirements

**Essential**
- Linux with Bash 4+ (or compatible)
- UTF‑8 terminal with **256 colors** (`tput colors >= 256`)
- Tools: `awk`, `ps`, `df`, `date`, `tput`, `stty`
- `/proc` mounted (for CPU/memory)

**Recommended**
- `coreutils` with `numfmt` (nicer NET throughput formatting)
- `systemd` + `journalctl` (for SERVICES/JOURNAL)
- `docker` (for DOCKER tab)

**Optional (for richer CMDS history)**
- `auditd` + `ausearch` **or** `acct/psacct` **or** a configured shell history

**Tested on**
- Arch/Manjaro, Debian/Ubuntu, Fedora, and WSL2 (UTF‑8 terminal required).

---

## 3) Installation

### 3.1. Get the script
Save the file as `EyesOfNico.sh` anywhere (e.g., your `$HOME`).

### 3.2. Make it executable
```bash
chmod +x EyesOfNico.sh
```

### 3.3. Install dependencies (examples)

**Arch/Manjaro**
```bash
sudo pacman -S --needed coreutils gawk procps-ng util-linux systemd
# optional
sudo pacman -S docker audit acct
```

**Debian/Ubuntu**
```bash
sudo apt update
sudo apt install -y coreutils gawk procps util-linux systemd
# optional
sudo apt install -y docker.io auditd acct
```

**Fedora**
```bash
sudo dnf install -y coreutils gawk procps-ng util-linux systemd
# optional
sudo dnf install -y docker audit auditd psacct
```

### 3.4. Terminal/Locale
- Use a monospaced font and UTF‑8. If needed: `export LC_ALL=C.UTF-8`.
- 256 colors are recommended. Quick color test:
```bash
for i in {0..255}; do printf "\e[48;5;%sm %3s \e[0m" $i $i; (( (i+1)%16==0 )) && echo; done
```

---

## 4) Usage

Basic:
```bash
./EyesOfNico.sh
```

Options:
```bash
--refresh N   # update interval in seconds (default: 1)
--safe        # avoid docker/systemd/journal calls when missing
--no-alt      # do not use the alternate screen (helps some terminals)
--help        # show usage
```

Examples:
```bash
./EyesOfNico.sh --refresh 1
./EyesOfNico.sh --safe
./EyesOfNico.sh --no-alt
```

Keyboard shortcuts:
- **D** = Dashboard
- **Y** = SYS (expanded)
- **L** = Logins
- **C** = Cmds
- **N** = Net (live chart)
- **S** = Services
- **K** = Docker
- **J** = Journal
- **H** = Help
- **P** = Pause/resume dashboard auto-refresh
- **Q** = Quit

---

## 5) Quick Configuration

**Thresholds (colors in SYS)**
Edit near the top of the script (Config section):
```bash
CPU_WARN=70   # turn red when >= 70%
MEM_WARN=75   # turn red when >= 75%
```

**Refresh speed**
- CLI: `--refresh 1`
- or change `REFRESH="1"` near the top.

**Palette (colors)**
In the “Colors / Theme” section:
```bash
COL_EMPTY=240   # gray background for 100% of the bar
```
The bar uses this fixed gray background plus a green/red overlay that grows/shrinks with the percentage (fractional blocks ▏▎▍▌▋▊▉).

**Resize behavior**
Handled via `SIGWINCH`. The script recalculates sizes and redraws frames automatically.

---

## 6) What each panel shows

**SYS**
- CPU % with progressive bar (overlay on fixed gray background)
- Load Average (1/5/15 min)
- Memory used/total and %
- Uptime (hours)

**DISKS**
- `df -h` output (excludes tmpfs/devtmpfs), top 8 lines

**NET**
- Dashboard: RX/s and TX/s per interface (sorted by RX)
- Single view (N): live textual graphs (RX and TX) with labeled Y-axis, window peak, and instant top interfaces

**TOP PROCS**
- `ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head`

**LOGINS (hist)**
- From `auth.log` or `journalctl -u ssh` (last ~50–80 lines)

**CMDS (hist)**
- Tries `ausearch` (auditd) → `lastcomm` (acct) → shell history (bash/zsh/fish)

**SERVICES**
- `systemctl --failed` and selected active units (sshd, docker, nginx, apache2, cron, redis, mysql/mariadb, postgresql)

**DOCKER**
- `docker ps --format '{{.Names}}\t{{.Status}}' | head -n 30`

**JOURNAL**
- `journalctl -n 80`

---

## 7) Screenshots (placeholders)

Insert your screenshots in the sections below:

- **[Screenshot: Full Dashboard]**

- **[Screenshot: SYS (expanded) — bars + Top CPU/MEM]**

- **[Screenshot: NET (live chart)]**

- **[Screenshot: DISKS / LOGINS / CMDS / SERVICES / DOCKER / JOURNAL]**

---

## 8) Tips & Notes

- Keep `--refresh 1` for smooth NET/SYS; you can try `0.5` if your terminal handles it.
- On servers without `systemd`/`docker`, use `--safe` to avoid errors.
- For richer command history, consider enabling **auditd**:
```bash
sudo apt install -y auditd audispd-plugins   # Debian/Ubuntu example
sudo tee /etc/audit/rules.d/99-cmdlog.rules >/dev/null <<'EOF'
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k cmdlog
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k cmdlog
EOF
sudo augenrules --load || sudo systemctl restart auditd
```
Alternative: `acct/psacct` (`lastcomm`).

- Use a monospaced font and UTF‑8; if you see weird characters, adjust your terminal font or set `LC_ALL=C.UTF-8`.

---

## 9) Troubleshooting

**`local: '-r': not a valid identifier`**  
Fixed in current version (separate `local` declarations from `[[ -r ... ]]` checks).

**SYS bars not filling / always empty**  
Use the **overlay bar implementation without cursor moves** (bar is rendered as a single string). Ensure `COL_EMPTY=240` and UTF‑8 terminal.

**Layout breaks on resize**  
Current version handles `SIGWINCH` and redraws. Ensure these exist outside functions:
```bash
RESIZED=0
on_resize() { RESIZED=1; }
trap on_resize WINCH
```
and the `main_loop()` contains a block that reframes when `RESIZED==1`.

**NET shows 0 B/s**  
Wait 1–2 refresh cycles (a baseline is collected). Also check permissions on `/sys/class/net/*/statistics`.

**No output in Docker/Services/Journal**  
Use `--safe` or install/enable those components on your system.

---

## 10) Uninstall

Remove the file:
```bash
rm -f EyesOfNico.sh
```

---

## 11) License / Credits

Free to use for personal/educational purposes.  
Credits: *EyesOfNico — Terminal Server Monitor (Bash TUI), Neon Synthwave theme*.
