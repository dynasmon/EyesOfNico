#!/usr/bin/env python3
"""Exercise the actual binary in a PTY; no third-party test dependencies.

python3 scripts/pty_check.py [bin/nicotop] [--capture /tmp/nicotop.png]
The optional PNG capture uses Pillow when available.
"""

import argparse
import codecs
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import unicodedata


def ansi_color(n):
    base = ["#000000", "#cd0000", "#00cd00", "#cdcd00", "#0000ee", "#cd00cd", "#00cdcd", "#e5e5e5",
            "#7f7f7f", "#ff0000", "#00ff00", "#ffff00", "#5c5cff", "#ff00ff", "#00ffff", "#ffffff"]
    if n < 16:
        return base[n]
    if n >= 232:
        v = 8 + (n - 232) * 10
        return f"#{v:02x}{v:02x}{v:02x}"
    n -= 16
    levels = [0, 95, 135, 175, 215, 255]
    return "#%02x%02x%02x" % (levels[n // 36], levels[n // 6 % 6], levels[n % 6])


class Screen:
    """Small VT parser for the renderer's cursor, SGR and erase operations."""
    def __init__(self, width, height):
        self.width, self.height = width, height
        self.x = self.y = 0
        self.fg, self.bg = "#d0d0d0", "#000000"
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending = ""
        self.overflows = 0
        self.clear()

    def clear(self):
        self.rows = [[(" ", self.fg, self.bg) for _ in range(self.width)] for _ in range(self.height)]

    def feed(self, data):
        self.pending += self.decoder.decode(data)
        while self.pending:
            if self.pending.startswith("\x1b"):
                match = re.match(r"\x1b\[([0-9;?]*)([@-~])", self.pending)
                if not match:
                    if len(self.pending) > 128:
                        raise AssertionError("unsupported escape sequence: " + repr(self.pending[:80]))
                    return
                params, op = match.groups()
                self.pending = self.pending[match.end():]
                if params.startswith("?"):
                    continue
                values = [int(v or 0) for v in params.split(";")]
                if op in "Hf":
                    self.y = max(0, (values[0] or 1) - 1)
                    self.x = max(0, (values[1] if len(values) > 1 else 1) - 1)
                elif op == "J" and values[0] == 2:
                    self.clear()
                elif op == "m":
                    i = 0
                    while i < len(values):
                        val = values[i]
                        if val == 0:
                            self.fg, self.bg = "#d0d0d0", "#000000"
                        elif val in (38, 48) and values[i+1:i+2] == [5]:
                            color = ansi_color(values[i+2])
                            if val == 38:
                                self.fg = color
                            else:
                                self.bg = color
                            i += 2
                        elif 30 <= val <= 37:
                            self.fg = ansi_color(val - 30)
                        elif 90 <= val <= 97:
                            self.fg = ansi_color(val - 90 + 8)
                        elif 40 <= val <= 47:
                            self.bg = ansi_color(val - 40)
                        i += 1
                continue
            char, self.pending = self.pending[0], self.pending[1:]
            if char == "\r":
                self.x = 0
                continue
            if char == "\n":
                self.y += 1
                continue
            width = 0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in "WF" else 1)
            if width == 0:
                continue
            if self.y >= self.height or self.x + width > self.width:
                self.overflows += 1
            else:
                self.rows[self.y][self.x] = (char, self.fg, self.bg)
                if width == 2:
                    self.rows[self.y][self.x+1] = ("", self.fg, self.bg)
            self.x += width

    def text(self):
        return "\n".join("".join(cell[0] for cell in row) for row in self.rows)

    def capture(self, path):
        from PIL import Image, ImageDraw, ImageFont
        font_path = subprocess.check_output(["fc-match", "-f", "%{file}", "DejaVu Sans Mono"], text=True).strip()
        font = ImageFont.truetype(font_path, 16)
        cell_width, cell_height = 10, 21
        image = Image.new("RGB", (self.width * cell_width + 32, self.height * cell_height + 32), "#000000")
        draw = ImageDraw.Draw(image)
        for y, row in enumerate(self.rows):
            for x, (char, fg, bg) in enumerate(row):
                left, top = 16 + x * cell_width, 16 + y * cell_height
                draw.rectangle((left, top, left + cell_width - 1, top + cell_height - 1), fill=bg)
                draw.text((left, top), char, fill=fg, font=font)
        image.save(path)


class Session:
    def __init__(self, binary, *args):
        self.master, self.slave = pty.openpty()
        self.original = termios.tcgetattr(self.slave)
        self.screen = Screen(120, 40)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        env = dict(os.environ, TERM="xterm-256color", LANG="C.UTF-8")
        env.pop("NO_COLOR", None)
        self.process = subprocess.Popen([binary, "--refresh", "0.2", *args], stdin=self.slave,
                                        stdout=self.slave, stderr=self.slave, env=env, start_new_session=True)
        self.raw = bytearray()

    def pump(self, duration=.3):
        end = time.monotonic() + duration
        while time.monotonic() < end:
            ready, _, _ = select.select([self.master], [], [], max(0, min(.04, end-time.monotonic())))
            if ready:
                data = os.read(self.master, 65536)
                self.raw.extend(data)
                self.screen.feed(data)

    def key(self, data, delay=.3):
        os.write(self.master, data.encode())
        self.pump(delay)

    def expect(self, text, timeout=3):
        # Native sensor setup and the first process batch can take longer on
        # a busy CI host. Wait for the observable state, not a fixed sleep.
        deadline = time.monotonic() + timeout
        while text not in self.screen.text() and time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            self.pump(.05)
        assert text in self.screen.text(), f"expected {text!r}:\n{self.screen.text()}"

    def resize(self, width, height):
        self.screen = Screen(width, height)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
        os.kill(self.process.pid, signal.SIGWINCH)
        self.pump()

    def finish(self, via_signal=False):
        if via_signal:
            os.kill(self.process.pid, signal.SIGTERM)
            self.pump()
        else:
            self.key("q")
        assert self.process.wait(timeout=3) == 0, "abnormal exit"
        assert termios.tcgetattr(self.slave) == self.original, "terminal settings were not restored"
        assert b"\x1b[?25h" in self.raw, "cursor was not restored"
        os.close(self.master)
        os.close(self.slave)

    def cleanup(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default="bin/nicotop")
    parser.add_argument("--capture")
    args = parser.parse_args()
    session = Session(os.path.abspath(args.binary))
    child = None
    try:
        session.pump(.8)
        session.expect("LIVE")
        session.expect("PROCESSES")
        session.expect("NETWORK")
        if args.capture:
            session.screen.capture(args.capture)
        assert session.screen.overflows == 0, "dashboard overflow"

        pressure_title = "MEMORY PRESSURE" if sys.platform == "darwin" else "PRESSURE / PSI"
        for key, title in [("2", pressure_title), ("3", "MEMORY"), ("4", "INTERFACES"),
                           ("5", "FILESYSTEMS"), ("6", "PROCESSES")]:
            session.key(key)
            session.expect(title)
            assert session.screen.overflows == 0, f"view {key} overflow"

        session.key("/unlikely_process_filter_9371\r")
        session.expect("No matching processes")
        session.key("\x1b")
        session.key("t")
        session.expect("tree")
        session.key("t")
        session.key("p")
        session.expect("PAUSED")
        frozen = session.screen.text()
        session.pump(.6)
        assert session.screen.text() == frozen, "paused metrics changed"
        session.key("p")
        session.expect("LIVE")
        session.key("?")
        session.expect("KEYBOARD / METRICS")
        session.key("\x1b")

        for size in [(80, 24), (40, 12), (20, 8), (120, 40)]:
            session.resize(*size)
            for view in ("1", "2", "3", "4", "5", "6"):
                session.key(view, .04)
            assert session.screen.overflows == 0, f"overflow at {size}"
        session.key("6")

        # Only act on our own disposable child, after checking the dialog PID.
        child = subprocess.Popen(["sleep", "37"])
        session.pump(.4)
        session.key(f"/{child.pid}\r")
        session.resize(20, 8)
        session.key("k")
        session.resize(120, 40)
        assert "CONFIRM PROCESS SIGNAL" not in session.screen.text(), "invisible action accepted below minimum size"
        session.key("k")
        session.expect(f"SIGTERM to PID {child.pid}")
        session.key("n")
        assert child.poll() is None, "cancelling signalled the child"
        session.key("z")
        session.expect(f"SIGSTOP to PID {child.pid}")
        session.key("y", .5)
        # waitpid works on Linux and macOS and only inspects our own child.
        stopped_pid, status = os.waitpid(child.pid, os.WUNTRACED | os.WNOHANG)
        assert stopped_pid == child.pid and os.WIFSTOPPED(status), "stop action failed"
        session.key("z")
        session.expect(f"SIGCONT to PID {child.pid}")
        session.key("y", .4)
        session.key("k")
        session.expect(f"SIGTERM to PID {child.pid}")
        session.key("y")
        child.wait(timeout=3)

        session.key("\x1b")
        session.key("\x1a", .1)
        assert termios.tcgetattr(session.slave) == session.original, "suspend did not restore terminal"
        os.kill(session.process.pid, signal.SIGCONT)
        session.pump(.4)
        session.expect("LIVE")
        session.finish()
    finally:
        session.cleanup()
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()

    for args in [("--no-alt",), ("--ascii", "--no-color")]:
        session = Session(os.path.abspath(parser.parse_args().binary), *args)
        try:
            session.pump(.4)
            session.expect("LIVE")
            session.finish(via_signal=True)
        finally:
            session.cleanup()
    print("PTY OK: 6 views, 4 sizes, search, tree, pause, safe signals, suspend/resume, terminal restoration")


if __name__ == "__main__":
    main()
