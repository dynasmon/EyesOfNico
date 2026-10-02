// Package ui implements a bounded, differential terminal renderer.
package ui

import (
	"fmt"
	"io"
	"math"
	"strings"
	"unicode"
)

type Style uint8

const (
	Normal Style = iota
	Muted
	Magenta
	Purple
	Blue
	Cyan
	Green
	Yellow
	Red
	White
	Selected
	Table
)

type Cell struct {
	Rune         rune
	Accent       string
	Style        Style
	Continuation bool
}
type Rect struct{ X, Y, W, H int }

func (r Rect) Inner() Rect { return Rect{r.X + 2, r.Y + 1, max(0, r.W-4), max(0, r.H-2)} }

type Screen struct {
	W, H  int
	Cells []Cell
	ASCII bool
}

func NewScreen(w, h int, ascii bool) *Screen {
	s := &Screen{W: max(0, w), H: max(0, h), ASCII: ascii}
	s.Cells = make([]Cell, s.W*s.H)
	s.Clear()
	return s
}

func (s *Screen) Clear() {
	for i := range s.Cells {
		s.Cells[i] = Cell{Rune: ' ', Style: Normal}
	}
}

// Width follows terminal columns, not UTF-8 bytes. Combining marks attach to the
// previous cell; controls/bidi escapes are never copied into terminal output.
func runeWidth(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
		return 0
	}
	if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) || (r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) || (r >= 0xfe10 && r <= 0xfe19) || (r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) || (r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff) || (r >= 0x20000 && r <= 0x3fffd)) {
		return 2
	}
	return 1
}

func safeRune(r rune) rune {
	if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
		return ' '
	}
	return r
}

func textWidth(text string) int {
	n := 0
	for _, r := range text {
		n += runeWidth(safeRune(r))
	}
	return n
}

func clip(text string, width int) string {
	if width <= 0 {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, r := range text {
		r = safeRune(r)
		w := runeWidth(r)
		if n+w > width {
			break
		}
		b.WriteRune(r)
		n += w
	}
	return b.String()
}

func pad(text string, width int) string {
	text = clip(text, width)
	return text + strings.Repeat(" ", max(0, width-textWidth(text)))
}

func (s *Screen) Put(x, y int, r rune, style Style) {
	if x < 0 || y < 0 || x >= s.W || y >= s.H {
		return
	}
	r = safeRune(r)
	width := runeWidth(r)
	if width == 0 || x+width > s.W {
		return
	}
	clear := func(col int) {
		idx := y*s.W + col
		c := s.Cells[idx]
		if c.Continuation && col > 0 {
			s.Cells[idx-1] = Cell{Rune: ' ', Style: c.Style}
		}
		if !c.Continuation && runeWidth(c.Rune) == 2 && col+1 < s.W {
			s.Cells[idx+1] = Cell{Rune: ' ', Style: c.Style}
		}
	}
	clear(x)
	if width == 2 {
		clear(x + 1)
	}
	s.Cells[y*s.W+x] = Cell{Rune: r, Style: style}
	if width == 2 {
		s.Cells[y*s.W+x+1] = Cell{Style: style, Continuation: true}
	}
}

func (s *Screen) Text(x, y, width int, text string, style Style) {
	if y < 0 || y >= s.H || width <= 0 {
		return
	}
	end := min(s.W, x+width)
	last := -1
	for _, r := range text {
		r = safeRune(r)
		w := runeWidth(r)
		if w == 0 {
			if last >= 0 && len(s.Cells[last].Accent) < 24 {
				s.Cells[last].Accent += string(r)
			}
			continue
		}
		if x+w > end {
			break
		}
		if x >= 0 {
			s.Put(x, y, r, style)
			last = y*s.W + x
		}
		x += w
	}
}

func (s *Screen) Fill(r Rect, style Style) {
	for y := max(0, r.Y); y < min(s.H, r.Y+r.H); y++ {
		for x := max(0, r.X); x < min(s.W, r.X+r.W); x++ {
			s.Put(x, y, ' ', style)
		}
	}
}

func gradient(x, w int) Style {
	if x*3 < w {
		return Magenta
	}
	if x*3 < w*2 {
		return Purple
	}
	return Blue
}

func (s *Screen) Box(r Rect, title, right string) Rect {
	if r.W < 4 || r.H < 3 {
		return Rect{}
	}
	tl, tr, bl, br, h, v := '╭', '╮', '╰', '╯', '─', '│'
	if s.ASCII {
		tl = '+'
		tr = '+'
		bl = '+'
		br = '+'
		h = '-'
		v = '|'
	}
	for x := 1; x < r.W-1; x++ {
		s.Put(r.X+x, r.Y, h, gradient(x, r.W))
		s.Put(r.X+x, r.Y+r.H-1, h, gradient(x, r.W))
	}
	for y := 1; y < r.H-1; y++ {
		s.Put(r.X, r.Y+y, v, Magenta)
		s.Put(r.X+r.W-1, r.Y+y, v, Blue)
	}
	s.Put(r.X, r.Y, tl, Magenta)
	s.Put(r.X+r.W-1, r.Y, tr, Blue)
	s.Put(r.X, r.Y+r.H-1, bl, Magenta)
	s.Put(r.X+r.W-1, r.Y+r.H-1, br, Blue)
	s.Text(r.X+2, r.Y, r.W-4, " "+title+" ", White)
	if right != "" && textWidth(title)+textWidth(right)+8 < r.W {
		s.Text(r.X+r.W-3-textWidth(right), r.Y, textWidth(right)+2, " "+right+" ", Muted)
	}
	return r.Inner()
}

func valueStyle(p float64) Style {
	if p >= 90 {
		return Red
	}
	if p >= 70 {
		return Yellow
	}
	return Green
}

func (s *Screen) Bar(x, y, w int, percent float64, style Style) {
	if w <= 0 {
		return
	}
	percent = max(0, min(100, percent))
	steps := int(math.Round(percent / 100 * float64(w*8)))
	fracs := []rune(" ▏▎▍▌▋▊▉█")
	for i := 0; i < w; i++ {
		part := max(0, min(8, steps-i*8))
		r := '─'
		st := Muted
		if s.ASCII {
			r = '-'
		}
		if part > 0 {
			r = fracs[part]
			st = style
			if s.ASCII {
				r = '#'
			}
		}
		s.Put(x+i, y, r, st)
	}
}

func (s *Screen) Graph(r Rect, values []float64, scale float64, style Style) {
	if r.W <= 0 || r.H <= 0 {
		return
	}
	scale = max(scale, 1)
	values = values[max(0, len(values)-r.W):]
	offset := r.W - len(values)
	blocks := []rune(" ▁▂▃▄▅▆▇█")
	for x, v := range values {
		steps := int(math.Round(max(0, min(v, scale)) / scale * float64(r.H*8)))
		for y := 0; y < r.H; y++ {
			part := max(0, min(8, steps-(r.H-1-y)*8))
			ch := blocks[part]
			st := style
			if part == 0 {
				st = Muted
				if y == r.H-1 {
					ch = '·'
				}
			}
			if s.ASCII {
				if part > 0 {
					ch = '#'
				} else if y == r.H-1 {
					ch = '.'
				}
			}
			s.Put(r.X+offset+x, r.Y+y, ch, st)
		}
	}
}

func (s *Screen) Plain() string {
	var b strings.Builder
	for y := 0; y < s.H; y++ {
		for x := 0; x < s.W; x++ {
			c := s.Cells[y*s.W+x]
			if !c.Continuation {
				b.WriteRune(c.Rune)
				b.WriteString(c.Accent)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

type Renderer struct {
	previous         []Cell
	w, h             int
	out              io.Writer
	color, colors256 bool
}

func NewRenderer(out io.Writer, color, colors256 bool) *Renderer {
	return &Renderer{out: out, color: color, colors256: colors256}
}
func (r *Renderer) Invalidate() { r.previous = nil }

func (r *Renderer) style(s Style) string {
	if !r.color {
		if s == Selected {
			return "\x1b[0;7m"
		}
		if s == White || s == Table {
			return "\x1b[0;1m"
		}
		return "\x1b[0m"
	}
	colors := []int{252, 245, 199, 129, 33, 51, 84, 220, 196, 15, 15, 51}
	if !r.colors256 {
		colors = []int{37, 90, 95, 35, 94, 96, 92, 93, 91, 97, 97, 96}
	}
	fg := colors[int(s)%len(colors)]
	bg := 0
	bold := ""
	if s == Selected {
		bg = 54
	}
	if s == White || s == Table {
		bold = ";1"
	}
	if r.colors256 {
		return fmt.Sprintf("\x1b[0;38;5;%d;48;5;%d%sm", fg, bg, bold)
	}
	if s == Selected {
		return "\x1b[0;97;45m"
	}
	return fmt.Sprintf("\x1b[0;%d;40%sm", fg, bold)
}

// Flush rewrites only changed rows, with a single write. Whole-row diffs also
// correctly erase the trailing half of a replaced double-width character.
func (r *Renderer) Flush(s *Screen) error {
	full := r.w != s.W || r.h != s.H || len(r.previous) != len(s.Cells)
	var b strings.Builder
	if full {
		b.WriteString("\x1b[0m\x1b[2J")
		r.previous = make([]Cell, len(s.Cells))
		r.w = s.W
		r.h = s.H
	}
	for y := 0; y < s.H; y++ {
		start, end := y*s.W, (y+1)*s.W
		changed := full
		if !changed {
			for i := start; i < end; i++ {
				if s.Cells[i] != r.previous[i] {
					changed = true
					break
				}
			}
		}
		if !changed {
			continue
		}
		fmt.Fprintf(&b, "\x1b[%d;1H", y+1)
		lastStyle := Style(255)
		for _, c := range s.Cells[start:end] {
			if c.Continuation {
				continue
			}
			if c.Style != lastStyle {
				b.WriteString(r.style(c.Style))
				lastStyle = c.Style
			}
			b.WriteRune(c.Rune)
			b.WriteString(c.Accent)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	b.WriteString("\x1b[0m")
	if _, err := io.WriteString(r.out, b.String()); err != nil {
		return err
	}
	copy(r.previous, s.Cells)
	return nil
}
