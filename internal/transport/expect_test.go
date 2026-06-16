package transport

import (
	"context"
	"io"
	"regexp"
	"testing"
	"time"
)

func TestMatchAnyLeftmost(t *testing.T) {
	buf := []byte("noise [sys] more <user>")
	pats := []*regexp.Regexp{
		regexp.MustCompile(`<[^>]+>`),
		regexp.MustCompile(`\[[^\]]+\]`),
	}
	idx, before, end := matchAny(buf, pats)
	if idx != 1 { // [sys] is leftmost even though it's the 2nd pattern
		t.Fatalf("want idx 1 (leftmost), got %d", idx)
	}
	if before != "noise " {
		t.Errorf("before = %q, want %q", before, "noise ")
	}
	if string(buf[end:]) != " more <user>" {
		t.Errorf("remainder = %q", string(buf[end:]))
	}
}

func TestExpectFindsPrompt(t *testing.T) {
	pr, pw := io.Pipe()
	s := NewSession(pr, io.Discard, nil, 2*time.Second)
	go func() {
		_, _ = io.WriteString(pw, "login banner\r\n")
		_, _ = io.WriteString(pw, "switch#")
	}()

	idx, before, err := s.Expect(context.Background(), regexp.MustCompile(`#\s*$`))
	if err != nil {
		t.Fatalf("expect error: %v", err)
	}
	if idx != 0 {
		t.Fatalf("idx = %d", idx)
	}
	if want := "login banner\r\nswitch"; before != want {
		t.Errorf("before = %q, want %q", before, want)
	}
}

func TestExpectTimeout(t *testing.T) {
	pr, _ := io.Pipe()
	s := NewSession(pr, io.Discard, nil, 150*time.Millisecond)
	_, _, err := s.Expect(context.Background(), regexp.MustCompile(`never`))
	if _, ok := err.(*TimeoutError); !ok {
		t.Fatalf("want TimeoutError, got %T %v", err, err)
	}
}

func TestCollectIdle(t *testing.T) {
	pr, pw := io.Pipe()
	s := NewSession(pr, io.Discard, nil, 2*time.Second)
	go func() { _, _ = io.WriteString(pw, "show version output here") }()

	out := s.Collect(context.Background(), 200*time.Millisecond, 2*time.Second)
	if out != "show version output here" {
		t.Errorf("collect = %q", out)
	}
}
