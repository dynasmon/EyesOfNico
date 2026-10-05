# EyesOfNico

A terminal monitor for **Linux, macOS, and Windows**, with a neon magenta → purple → blue theme. The interface, JSON output, and snapshots run from a single Go binary. Intel/AMD (amd64) and ARM64 builds are supported on all three systems.

## Getting started

Requirements: Go **1.24+** to build and a terminal with ANSI cursor control for interactive use. Dependencies are downloaded by Go on the first build and compiled into the binary. The compiled monitor does not require Go, Bash, ncurses, Docker, or systemd. Linux uses `/proc` and optional `/sys` metrics; macOS and Windows use native system APIs. macOS also uses its built-in `/bin/ps` to fill basic statistics for processes whose native API access is restricted. On Windows, use Windows Terminal or a Windows 10+ console.

On Linux or macOS (including the stock macOS shell):

```bash
./nicotop.sh
```

The launcher builds on the first run and rebuilds when source files change. You can also build and run the binary directly:

```bash
make build
./bin/nicotop
```

On Windows, from PowerShell:

```powershell
.\nicotop.ps1
# Or build and run directly, without Make or a script launcher:
go build -trimpath -o bin/nicotop.exe ./cmd/nicotop
.\bin\nicotop.exe
```

If your PowerShell policy blocks scripts, use the direct build commands above. All command-line options below also work with `nicotop.exe`.

To install the binary on Linux or macOS:

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

Availability differs by platform:

| Feature | Linux | macOS | Windows |
| --- | --- | --- | --- |
| CPU per core, RAM, swap, network, disk throughput, processes | Yes | Yes | Yes |
| Local filesystem capacity | Yes | APFS, HFS, FAT/exFAT, etc. | NTFS, ReFS, FAT/exFAT, etc. |
| Load averages | Yes | Yes | Unavailable |
| PSI, iowait/steal, forks/context-switch rate, Linux buffers/slab/dirty | Kernel-dependent | Unavailable; omitted from Mac panels | Unavailable |
| File-backed cache, wired/compressed/active/inactive/purgeable memory | Platform-specific | Native VM counters | Unavailable |
| Memory pressure level (normal/warning/critical) | PSI percentages instead | Yes | Unavailable |
| Temperature sensors | Kernel-dependent | Hardware/OS-dependent, Intel and Apple Silicon | Unavailable |
| Disk busy/queue, physical device size | Kernel-dependent | Unavailable; panels show IOPS/latency | Unavailable |
| Disk latency | Yes | Yes | Unavailable |
| Process state, nice/priority | Yes | Yes | Unavailable |
| Per-process I/O | Disk bytes, permission-dependent | Disk bytes, permission-dependent | OS I/O bytes (may include non-disk I/O) |
| Process actions | TERM, KILL, STOP, CONT | TERM, KILL, STOP, CONT | Forced termination only (`x`) |
| Ctrl-Z monitor suspension | Yes | Yes | Unavailable; use `p` to pause |

Unavailable fields display `n/a` or `unavailable` (process state uses `?`). JSON lists unsupported metrics in `unavailable_metrics` at snapshot and process level; their numeric placeholders must not be interpreted as measured zeroes. PSI and per-process I/O also retain their individual availability flags. Windows does not expose Unix UIDs: the current-user filter compares account names. Permissions can hide protected processes or some of their metrics on every platform. Thread and running-process totals include only accessible counters. Frequency may represent a nominal/maximum value on macOS and Windows, rather than a live clock.

The process table supports incremental search, sorting, a process tree, a current-user filter, and process details. Once you navigate, the selection follows the process identity even when its position changes. Tree searches retain the ancestors needed to understand the hierarchy.

### Why some metrics may be unavailable on macOS

Linux PSI, slab, iowait/steal and disk busy/queue statistics have no directly equivalent counter in this collector. Mac panels therefore show native memory pressure, wired/compressed memory, file cache, and disk IOPS/latency. JSON still identifies unsupported counters explicitly, rather than reporting them as measured zeroes.

The `proc_pidinfo` API can deny CPU/RSS/thread data for other users' processes. The monitor fills those fields with one batched call to Apple's `/bin/ps`, without asking for `sudo` or changing permissions. Process identity is checked again before merging the results. JSON marks these records with `metrics_source: "ps"`; CPU rates use differences in its cumulative CPU time, which has 10 ms resolution. If the fallback cannot read a process, that process remains explicitly unavailable. Per-process disk I/O still depends on native permissions. Temperature sensors are collected when the Mac exposes them.

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
| `k`, `x`, `z` | Linux/macOS: SIGTERM / SIGKILL / stop or resume; Windows: only `x` (forced termination) |
| `[` / `]`, `←` / `→` | Select an interface or disk |
| `p` or Space | Pause/resume sampling |
| `+` / `-` | Sample faster/slower, from 0.2 to 10 seconds |
| `?` or `h` | Show help; arrow keys scroll through dialogs on small terminals |
| `Ctrl-Z` | Linux/macOS: suspend the monitor and return the terminal to the shell |
| `q` or `Ctrl-C` | Quit |

The original `d` (overview), `y` (CPU), and `n` (network) shortcuts remain available.

Process actions require confirmation with **y** and recheck the captured process identity. Linux uses **pidfd**, requiring Linux 5.3+ on amd64/arm64; older kernels still support monitoring. Windows checks creation time using the same process handle used for termination. macOS checks the process birth time immediately before sending a signal; its check and signal are **not atomic**, unlike the Linux/Windows implementations. PID 1, the monitor itself, and Windows System (PID 4) are protected. Normal OS permissions apply; the program does not elevate privileges. Pasted text cannot confirm actions.

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

JSON includes the `os` (`linux`, `darwin`, or `windows`), counters, rates, process identities, metric availability, timestamps, measured intervals, collection duration, and warnings. The first line already contains calculated rates. Throughput fields use bytes/s; memory and capacity fields use bytes. `start_ticks` is an opaque birth token: Linux clock ticks, macOS Unix microseconds, Windows Unix milliseconds. Compare it together with the PID within one host/platform, rather than converting it with a universal clock rate.

## How metrics are calculated

- CPU usage comes from differences in OS counters (`/proc/stat` on Linux, Mach on macOS, Windows processor counters). Guest and interrupt time are not counted twice. In the process table, **100% means one core**; a multithreaded process can exceed 100%.
- Used memory is total minus the OS estimate of available memory (`MemTotal - MemAvailable` on Linux). RSS is the OS estimate of resident memory.
- On macOS, `memory.darwin` contains native VM counters and the pressure level. `cached_bytes` is the file-backed page count, including active file-backed pages; it is not a claim that every cached byte is immediately reclaimable. Compressed bytes are the physical pages occupied by the compressor. Speculative pages are already included in free memory and are not added twice.
- Network, disk, and per-process CPU rates use **actual elapsed monotonic time**. Collectors do not sleep. New interfaces and reused PIDs start with a fresh baseline; decreasing counters do not cause underflow.
- Linux `diskstats` sectors are converted using **512 bytes**, regardless of physical sector size. macOS/Windows use byte counters directly. Await and IOPS account for reads and writes. Linux busy time measures device activity; it does not represent the full parallel capacity of an NVMe device.
- PSI shows averages over 10, 60, and 300 seconds. `some` measures time when one or more tasks are stalled; `full` measures time when all non-idle tasks are stalled. Missing support is shown as unavailable.
- Aggregate network traffic sums all interfaces except loopback. Bridges, tunnels, and veth devices can represent the same traffic at multiple layers; select an individual interface to inspect its traffic. Disks are shown individually, without summing partitions or device-mapper layers.
- Filesystem usage percentage is `used / (used + available)`, accounting for reserved blocks. Remote mounts, autofs, FUSE, and internal container overlay mounts are excluded.
- On Linux, the scope is **the `/proc` filesystem visible to the monitor**. Inside containers, CPU/memory may reflect the host while processes may be restricted by the namespace. macOS/Windows report the visible host. Cgroup quota normalization, GPU metrics, and service management are not implemented.
- Linux usernames are resolved through `/etc/passwd`; other users are shown by UID. macOS uses OS account lookup with a UID fallback; Windows uses account names. Processes that exit during collection are skipped. Restrictions such as `hidepid`, macOS protected processes, or Windows access controls can limit the available data.

Kernel references: [procfs](https://docs.kernel.org/filesystems/proc.html), [block statistics](https://docs.kernel.org/block/stat.html), and [PSI](https://docs.kernel.org/accounting/psi.html).

## Efficiency and architecture

The Linux collection path reads one `stat` record per process and the kernel's aggregate counters. A reusable buffer and parsing with a fixed array avoid an extra `stat()` call and large allocations per PID. macOS/Windows use [gopsutil](https://github.com/shirou/gopsutil) for native metrics. macOS combines a bulk `sysctl` process table with one [`PROC_PIDTASKINFO`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h) call per process for CPU, memory, threads, and running/sleeping state. When needed, one `/bin/ps` batch fills denied CPU/RSS/thread fields per sample, with a one-second timeout; it is never invoked once per PID. This adds some collection overhead. Commands and ownership are cached for 5 seconds. Per-process I/O collection stays disabled until requested. Terminal handling uses [golang.org/x/term](https://pkg.go.dev/golang.org/x/term), with Windows ANSI output enabled and restored explicitly.

Filesystem, sensor, and frequency collection share a single worker with a bounded queue and a 5-second cache. A blocked filesystem call does not freeze the interface or cause workers to accumulate. Linux block device discovery is refreshed every 10 seconds. macOS APFS volumes can share storage capacity; filesystem rows should not be summed as independent physical disks.

Sampling runs separately from keyboard handling. There are no high-frequency animation ticks. The renderer outputs only changed rows in a single write per frame, and history is limited to 240 samples per series. Pausing prevents new sampling; a collection already in progress may finish in the background.

```text
cmd/nicotop/         CLI, JSON, and snapshots
internal/monitor/    OS-specific collection, caching, and process actions
internal/ui/         State, interaction, layout, and terminal handling
scripts/pty_check.py  Tests the binary in a real pseudoterminal
nicotop.sh           Linux/macOS launcher (POSIX shell)
nicotop.ps1          Windows launcher (PowerShell)
```

The nine-panel dashboard, repeated systemd/Docker/journal queries, shell/audit history collection, and external IP geolocation have been removed. The previous implementation remains in Git history.

## Verification

```bash
make test          # Counters, hotplug, PID reuse, tree, search, layouts, and CLI
make check         # go vet and the data race detector
make integration   # PTY: keyboard, resize, pause, signals, Ctrl-Z, and restoration
make bench         # Parsing, host collection, and rendering; includes allocations
```

Signal tests use only disposable processes created by the tests themselves. The PTY test runs on Linux/macOS and requires Python 3; the race detector requires the C toolchain used by Go. On Windows, run `go test ./...` and `go vet ./...` directly. The CI matrix runs native tests on all three operating systems and cross-builds amd64/arm64 binaries. Optional screenshot capture uses Pillow and fontconfig:

```bash
python3 scripts/pty_check.py --capture /tmp/nicotop.png
```

To build all six OS/architecture combinations without CGO from Linux/macOS:

```bash
make cross
# bin/nicotop-{linux,darwin,windows}-{amd64,arm64} (Windows files end in .exe)
```

Or choose a single target:

```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o bin/nicotop-darwin-arm64 ./cmd/nicotop
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o bin/nicotop-windows-amd64.exe ./cmd/nicotop
```

Benchmarks depend on process count, hardware, permissions, and sampling interval. Compare under equivalent conditions and use `collection_ms` in JSON output to track collection cost on your own host.
