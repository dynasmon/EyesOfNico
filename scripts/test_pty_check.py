"""Regression checks for PTY output that straddles a terminal resize."""

import unittest

from pty_check import Screen


def frame(width, height):
    return b"\x1b[0m\x1b[2J" + b"".join(
        f"\x1b[{row};1H".encode() + b" " * width for row in range(1, height + 1)
    ) + b"\x1b[0m"


class ResizeTests(unittest.TestCase):
    def test_queued_old_frame_and_fragmented_sequences_survive_resize(self):
        old_row = "\x1b[40;119H界".encode()
        for split in range(len(old_row) + 1):
            with self.subTest(split=split):
                screen = Screen(120, 40)
                screen.feed(old_row[:split])
                screen.resize_on_redraw(80, 24)
                screen.feed(old_row[split:])
                self.assertTrue(screen.redraw_pending)
                self.assertEqual(screen.rows[39][118][0], "界")
                self.assertEqual(screen.overflows, 0)

                # Clear-screen and cursor sequences can also span PTY reads.
                for byte in frame(80, 24):
                    screen.feed(bytes([byte]))
                self.assertFalse(screen.redraw_pending)
                self.assertEqual(screen.text().splitlines(), [" " * 80] * 24)
                self.assertEqual(screen.overflows, 0)

    def test_resize_waits_for_last_row(self):
        screen = Screen(120, 40)
        screen.resize_on_redraw(80, 24)
        screen.feed(frame(80, 23))
        self.assertTrue(screen.redraw_pending)
        screen.feed(b"\x1b[24;1H" + b" " * 79)
        self.assertTrue(screen.redraw_pending)
        screen.feed(b" ")
        self.assertFalse(screen.redraw_pending)

    def test_real_overflows_after_resize_are_still_reported(self):
        screen = Screen(120, 40)
        screen.resize_on_redraw(80, 24)
        screen.feed(frame(80, 24))
        screen.feed(b"\x1b[24;80HXX\x1b[25;1HX")
        self.assertEqual(screen.overflows, 2)
        screen.feed(frame(80, 24))
        self.assertEqual(screen.overflows, 2)


if __name__ == "__main__":
    unittest.main()
