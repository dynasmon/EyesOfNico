# EyesOfNico

A Linux terminal monitor with a neon magenta → purple → blue theme. Version 2 replaces the Bash loop with a Go binary, with no external runtime dependencies and no external commands executed during collection.

## Getting started

Requirements: Linux, `/proc`, a terminal with cursor control, and Go **1.22+** to build. `/sys` provides optional device and sensor information. The compiled binary does not require Go, Bash, ncurses, Docker, or systemd.

```bash
./nicotop.sh
```

The launcher builds on the first run and rebuilds when source files change. You can also build and run the binary directly:

```bash
make build
./bin/nicotop
```

To install the binary:

```bash
make install PREFIX="$HOME/.local"
# Or install system-wide:
sudo make install
```

The interface adapts to the terminal's actual size. **120×40** fits all panels; at **80×24**, the overview prioritizes the system summary and processes. The minimum is **40×12**. Smaller terminals display a resize prompt. History is preserved when resizing or switching views.

## Monitored metrics

| View | Metrics |
| --- | --- |
| **1 · Overview** | CPU, RAM, swap, network traffic, disks, and an interactive process table |
| **2 · CPU** | Per-core usage, user/system time, iowait, steal, 1/5/15-minute load averages, context switches, forks, frequency, temperature, and PSI |
| **3 · Memory** | Available and used memory, cache, buffers, slab, dirty/writeback pages, swap, pressure, and processes |
| **4 · Network** | RX/TX, per-interface or aggregate graphs, packets/s in JSON, errors, drops, and byte counters |
| **5 · Disks** | Read/write throughput, IOPS, busy time, latency, queue depth, and local filesystem capacity/inodes |
| **6 · Processes** | PID, user, state, CPU, RSS, memory %, nice value, threads, CPU time, command, and optional I/O |

Columns and graphs adapt to the available width. In the CPU, network, and disk views, use the arrow keys to scroll through lists longer than the screen. Temperature and frequency readings depend on the sensors exposed by the kernel.

The process table supports incremental search, sorting, a process tree, a current-user filter, and process details. Once you navigate, the selection follows the process identity even when its position changes. Tree searches retain the ancestors needed to understand the hierarchy.

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| `1` … `6`, `Tab` | Select or cycle through views |
| `↑` / `↓`, `PgUp` / `PgDn`, `Home` / `End` | Select a process or scroll through the current view's list |
| `/` | Search by PID, user, name, or command; Enter applies, Esc cancels |
| `Esc` | Clear the filter, close a dialog, or return to the overview |
| `c`, `m` | Sort by CPU or memory |
| `s`, `r` | Cycle through sort criteria / reverse the order |
| `t`, `u`, `f` | Toggle tree / current user only / full command or name |
| `i` | Enable/disable per-process I/O collection |
| `Enter` | Show details for the selected process |
| `k`, `x`, `z` | SIGTERM / SIGKILL / stop or resume the process |
| `[` / `]`, `←` / `→` | Select an interface or disk |
| `p` or Space | Pause/resume sampling |
| `+` / `-` | Sample faster/slower, from 0.2 to 10 seconds |
| `?` or `h` | Show help; arrow keys scroll through dialogs on small terminals |
| `Ctrl-Z` | Suspend the monitor and return the terminal to the shell |
| `q` or `Ctrl-C` | Quit |

The original `d` (overview), `y` (CPU), and `n` (network) shortcuts remain available.

Signals require confirmation with **y** and use **pidfd** to verify process identity before acting. This requires Linux 5.3+ on amd64/arm64; on older kernels, monitoring works, but process actions are refused. PID 1 and the monitor itself are protected. Normal Linux permissions apply; the program does not elevate privileges. Pasted text cannot confirm actions.

## Options

```bash
./bin/nicotop --refresh 0.5
./bin/nicotop --view processes --sort mem --filter postgres
./bin/nicotop --process-io
./bin/nicotop --ascii --no-color
./bin/nicotop --no-alt
./bin/nicotop --help
```

`NO_COLOR` also disables colors. The `C` and `POSIX` locales enable ASCII borders automatically. Basic ANSI terminals use a 16-color palette; terminals with 256-color support use the neon palette. `--safe` remains as a compatibility option: all collection is already local.

For use without a terminal, including through cron, pipes, or SSH:

```bash
# One JSON line per sample, after establishing a baseline.
./bin/nicotop --json --count 5 --refresh 1

# Continuous output; Ctrl-C/SIGTERM stops the stream.
./bin/nicotop --json

# Readable snapshot without ANSI codes; uses two samples 200 ms apart.
./bin/nicotop --snapshot 120x40
./bin/nicotop --snapshot 100x30 --view disks
```

JSON includes counters, rates, process identities, PSI/I/O availability, timestamps, measured intervals, collection duration, and warnings. The first line already contains calculated rates. Throughput fields use bytes/s; memory and capacity fields use bytes.

## How metrics are calculated

- CPU usage comes from differences across all relevant `/proc/stat` fields. Guest time is not counted twice, and iowait is shown separately. In the process table, **100% means one core**; a multithreaded process can exceed 100%.
- Used memory is `MemTotal - MemAvailable`. Reclaimable cache is not treated entirely as unavailable memory. RSS is the kernel's fast estimate of resident memory.
- Network, disk, and per-process CPU rates use **actual elapsed monotonic time**. Collectors do not sleep. New interfaces and reused PIDs start with a fresh baseline; decreasing counters do not cause underflow.
- `diskstats` sectors are converted using **512 bytes**, regardless of physical sector size. Await and IOPS account for reads and writes. Busy time measures device activity; it does not represent the full parallel capacity of an NVMe device.
- PSI shows averages over 10, 60, and 300 seconds. `some` measures time when one or more tasks are stalled; `full` measures time when all non-idle tasks are stalled. Missing support is shown as unavailable.
- Aggregate network traffic sums all interfaces except loopback. Bridges, tunnels, and veth devices can represent the same traffic at multiple layers; select an individual interface to inspect its traffic. Disks are shown individually, without summing partitions or device-mapper layers.
- Filesystem usage percentage is `used / (used + available)`, accounting for reserved blocks. Remote mounts, autofs, FUSE, and internal container overlay mounts are excluded.
- The scope is **the `/proc` filesystem visible to the monitor**. Inside containers, CPU/memory may reflect the host while processes may be restricted by the namespace. Cgroup quota normalization, GPU metrics, and service management are not implemented.
- Local usernames are resolved through `/etc/passwd`; other users are shown by UID. Processes that exit during collection are skipped. Restrictions such as `hidepid` or missing access to `/proc/PID/io` can limit the available data.

Kernel references: [procfs](https://docs.kernel.org/filesystems/proc.html), [block statistics](https://docs.kernel.org/block/stat.html), and [PSI](https://docs.kernel.org/accounting/psi.html).

## Efficiency and architecture

The normal collection path reads one `stat` record per process and the kernel's aggregate counters. A reusable buffer and parsing with a fixed array avoid an extra `stat()` call and large allocations per PID. Commands and UIDs are cached for 5 seconds. Per-process I/O collection stays disabled until requested.

Filesystem, sensor, and frequency collection share a single worker with a bounded queue and a 5-second cache. A blocked `statfs` call does not freeze the interface or cause workers to accumulate. Block device discovery is refreshed every 10 seconds.

Sampling runs separately from keyboard handling. There are no high-frequency animation ticks. The renderer outputs only changed rows in a single write per frame, and history is limited to 240 samples per series. Pausing prevents new sampling; a collection already in progress may finish in the background.

```text
cmd/nicotop/         CLI, JSON, and snapshots
internal/monitor/    Collection, parsing, caching, and pidfd signals
internal/ui/         State, interaction, layout, and terminal handling
scripts/pty_check.py  Tests the binary in a real pseudoterminal
nicotop.sh           Compatibility launcher
```

The nine-panel dashboard, repeated systemd/Docker/journal queries, shell/audit history collection, and external IP geolocation have been removed. The previous implementation remains in Git history.

## Verification

```bash
make test          # Counters, hotplug, PID reuse, tree, search, layouts, and CLI
make check         # go vet and the data race detector
make integration   # PTY: keyboard, resize, pause, signals, Ctrl-Z, and restoration
make bench         # Parsing, host collection, and rendering; includes allocations
```

Signal tests use only disposable processes created by the tests themselves. The PTY test requires Python 3; the race detector requires the C toolchain used by Go. Optional screenshot capture uses Pillow and fontconfig:

```bash
python3 scripts/pty_check.py --capture /tmp/nicotop.png
```

To cross-compile without CGO:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/nicotop-arm64 ./cmd/nicotop
```

Benchmarks depend on process count, hardware, permissions, and sampling interval. Compare under equivalent conditions and use `collection_ms` in JSON output to track collection cost on your own host.
