package ui

import (
	"strings"
	"unicode/utf8"
)

type Key struct{ Name, Text string }

// Decoder accepts fragmented escape sequences and UTF-8. Bracketed pastes are
// one text event, so pasted shortcuts can never trigger process actions.
type Decoder struct {
	pending string
	paste   bool
	pasted  strings.Builder
}

func (d *Decoder) Feed(data string) []Key {
	d.pending += data
	var keys []Key
	for len(d.pending) > 0 {
		if d.paste {
			if i := strings.Index(d.pending, "\x1b[201~"); i >= 0 {
				if d.pasted.Len() < 4096 {
					d.pasted.WriteString(clip(d.pending[:i], 4096-d.pasted.Len()))
				}
				keys = append(keys, Key{Name: "paste", Text: d.pasted.String()})
				d.pasted.Reset()
				d.paste = false
				d.pending = d.pending[i+6:]
				continue
			}
			// Keep a suffix for an end marker split across reads.
			n := max(0, len(d.pending)-5)
			if d.pasted.Len() < 4096 {
				d.pasted.WriteString(clip(d.pending[:n], 4096-d.pasted.Len()))
			}
			d.pending = d.pending[n:]
			break
		}
		if d.pending[0] == 27 {
			if len(d.pending) == 1 {
				break
			}
			if d.pending[1] == '[' || d.pending[1] == 'O' {
				end := -1
				for i := 2; i < len(d.pending); i++ {
					if d.pending[i] >= 0x40 && d.pending[i] <= 0x7e {
						end = i
						break
					}
				}
				if end < 0 {
					if len(d.pending) > 64 {
						d.pending = ""
					}
					break
				}
				seq := d.pending[:end+1]
				d.pending = d.pending[end+1:]
				if seq == "\x1b[200~" {
					d.paste = true
					continue
				}
				name := map[string]string{"\x1b[A": "up", "\x1b[B": "down", "\x1b[C": "right", "\x1b[D": "left", "\x1b[H": "home", "\x1b[F": "end", "\x1b[1~": "home", "\x1b[4~": "end", "\x1b[5~": "pgup", "\x1b[6~": "pgdown", "\x1bOH": "home", "\x1bOF": "end", "\x1bOP": "help", "\x1b[21~": "quit"}[seq]
				if name != "" {
					keys = append(keys, Key{Name: name})
				}
				continue
			}
			keys = append(keys, Key{Name: "escape"})
			d.pending = d.pending[1:]
			continue
		}
		if !utf8.FullRuneInString(d.pending) {
			break
		}
		r, n := utf8.DecodeRuneInString(d.pending)
		d.pending = d.pending[n:]
		name := "text"
		switch r {
		case 3:
			name = "quit"
		case 26:
			name = "suspend"
		case 13, 10:
			name = "enter"
		case 127, 8:
			name = "backspace"
		case 9:
			name = "tab"
		case 21:
			name = "clear"
		}
		keys = append(keys, Key{Name: name, Text: string(r)})
	}
	return keys
}

func (d *Decoder) Escape() []Key {
	if d.pending == "\x1b" {
		d.pending = ""
		return []Key{{Name: "escape"}}
	}
	return nil
}
