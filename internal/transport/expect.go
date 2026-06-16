// Package transport implements the SSH transport plus a small expect engine
// ("pexpect in Go"): an interactive PTY session where we send commands and
// wait for prompt patterns. Legacy network gear exposes only an interactive
// CLI over SSH, so this is the only reliable way to drive it.
package transport

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Session is an interactive expect-style session over an io.Reader/io.Writer
// pair. It is transport-agnostic: backed by real SSH in production and by
// in-memory pipes in tests.
type Session struct {
	w              io.Writer
	echo           io.Writer
	defaultTimeout time.Duration

	ch        chan readMsg
	buf       []byte
	full      strings.Builder
	closedErr error
}

type readMsg struct {
	data []byte
	err  error
}

// TimeoutError is returned by Expect when no pattern matches before the
// per-step timeout elapses. It carries the tail of unmatched output for
// debugging which prompt the device actually showed.
type TimeoutError struct {
	Tail string
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("timeout esperando respuesta; última salida: %q", e.Tail)
}

// NewSession starts a reader goroutine pumping r into an internal channel and
// returns a ready Session. w receives sent commands; echo (optional) mirrors
// all device output for verbose/live logging.
func NewSession(r io.Reader, w io.Writer, echo io.Writer, timeout time.Duration) *Session {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	s := &Session{
		w:              w,
		echo:           echo,
		defaultTimeout: timeout,
		ch:             make(chan readMsg, 32),
	}
	go s.readLoop(r)
	return s
}

func (s *Session) readLoop(r io.Reader) {
	b := make([]byte, 4096)
	for {
		n, err := r.Read(b)
		if n > 0 {
			d := make([]byte, n)
			copy(d, b[:n])
			s.ch <- readMsg{data: d}
		}
		if err != nil {
			s.ch <- readMsg{err: err}
			return
		}
	}
}

func (s *Session) absorb(data []byte) {
	s.buf = append(s.buf, data...)
	s.full.Write(data)
	if s.echo != nil {
		_, _ = s.echo.Write(data)
	}
}

// Expect reads until one of pats matches the accumulated buffer (matching the
// leftmost match across patterns, ties broken by argument order). It returns
// the matched pattern index, the text BEFORE the match (pexpect's `before`),
// and consumes the buffer up to the end of the match.
func (s *Session) Expect(ctx context.Context, pats ...*regexp.Regexp) (int, string, error) {
	timer := time.NewTimer(s.defaultTimeout)
	defer timer.Stop()

	for {
		if idx, before, end := matchAny(s.buf, pats); idx >= 0 {
			s.buf = s.buf[end:]
			return idx, before, nil
		}
		if s.closedErr != nil {
			return -1, string(s.buf), s.closedErr
		}
		select {
		case msg := <-s.ch:
			if len(msg.data) > 0 {
				s.absorb(msg.data)
			}
			if msg.err != nil {
				if idx, before, end := matchAny(s.buf, pats); idx >= 0 {
					s.buf = s.buf[end:]
					return idx, before, nil
				}
				s.closedErr = msg.err
				return -1, string(s.buf), msg.err
			}
		case <-timer.C:
			return -1, string(s.buf), &TimeoutError{Tail: tail(s.buf, 200)}
		case <-ctx.Done():
			return -1, string(s.buf), ctx.Err()
		}
	}
}

// Collect drains output until no new data arrives for `quiet`, or `max` total
// elapses. It is used for reading login banners and probe-command output where
// there is no single deterministic prompt to match.
func (s *Session) Collect(ctx context.Context, quiet, max time.Duration) string {
	out := make([]byte, len(s.buf))
	copy(out, s.buf)
	s.buf = nil

	idle := time.NewTimer(quiet)
	defer idle.Stop()
	hard := time.NewTimer(max)
	defer hard.Stop()

	for {
		select {
		case msg := <-s.ch:
			if len(msg.data) > 0 {
				out = append(out, msg.data...)
				s.full.Write(msg.data)
				if s.echo != nil {
					_, _ = s.echo.Write(msg.data)
				}
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(quiet)
			}
			if msg.err != nil {
				s.closedErr = msg.err
				return string(out)
			}
		case <-idle.C:
			return string(out)
		case <-hard.C:
			return string(out)
		case <-ctx.Done():
			return string(out)
		}
	}
}

// Send writes raw text to the device (no newline appended).
func (s *Session) Send(text string) error {
	_, err := io.WriteString(s.w, text)
	return err
}

// Sendline writes text followed by a carriage return. Network CLIs expect CR
// (0x0D) — what a real terminal's Enter key sends — to submit a command; some
// (ArubaOS-CX) ignore a bare LF entirely.
func (s *Session) Sendline(text string) error {
	return s.Send(text + "\r")
}

// Transcript returns the full session output captured so far (for reporting).
func (s *Session) Transcript() string {
	return s.full.String()
}

// matchAny finds the leftmost match among pats. Returns the pattern index, the
// text before the match, and the end offset of the match (for consuming).
func matchAny(buf []byte, pats []*regexp.Regexp) (int, string, int) {
	bestIdx, bestStart, bestEnd := -1, -1, -1
	for i, p := range pats {
		loc := p.FindIndex(buf)
		if loc == nil {
			continue
		}
		if bestStart == -1 || loc[0] < bestStart {
			bestStart, bestEnd, bestIdx = loc[0], loc[1], i
		}
	}
	if bestIdx < 0 {
		return -1, "", -1
	}
	return bestIdx, string(buf[:bestStart]), bestEnd
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}
