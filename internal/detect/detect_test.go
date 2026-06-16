package detect

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/Marioloez/snmpapply/internal/driver"
)

// fakeSession scripts Collect outputs and records what was sent.
type fakeSession struct {
	collects []string
	ci       int
	sent     []string
}

func (f *fakeSession) Collect(_ context.Context, _, _ time.Duration) string {
	if f.ci < len(f.collects) {
		v := f.collects[f.ci]
		f.ci++
		return v
	}
	return ""
}
func (f *fakeSession) Send(s string) error     { f.sent = append(f.sent, "send:"+s); return nil }
func (f *fakeSession) Sendline(s string) error { f.sent = append(f.sent, s); return nil }
func (f *fakeSession) Expect(_ context.Context, _ ...*regexp.Regexp) (int, string, error) {
	return 0, "", nil
}
func (f *fakeSession) Transcript() string { return "" }

func TestPrimeInBandLogin(t *testing.T) {
	// Device presents an in-band "User Name:" / "Password:" login after the SSH
	// transport already authenticated; Prime must answer with the SSH creds.
	f := &fakeSession{collects: []string{"\r\nUser Name: ", "Password: ", "\r\nICX7150 Switch#"}}
	Prime(context.Background(), f, "sit", "s3cr3t")

	var sawUser, sawPass bool
	for _, s := range f.sent {
		if s == "sit" {
			sawUser = true
		}
		if s == "s3cr3t" {
			sawPass = true
		}
	}
	if !sawUser || !sawPass {
		t.Fatalf("expected in-band login to send user and pass; sent=%v", f.sent)
	}
}

func TestIdentifyHuaweiFromBanner(t *testing.T) {
	f := &fakeSession{collects: []string{"Huawei VRP Software\r\n<MPS-Sombrero>"}}
	d, _, err := Identify(context.Background(), f, driver.All(), "sit", "pass")
	if err != nil {
		t.Fatalf("identify error: %v", err)
	}
	if d.Name() != "huawei" {
		t.Fatalf("vendor = %q, want huawei", d.Name())
	}
	for _, s := range f.sent {
		if s == "show version" {
			t.Errorf("should NOT have probed; banner was decisive")
		}
	}
}

func TestIdentifyArubaCXViaProbe(t *testing.T) {
	f := &fakeSession{collects: []string{
		"\r\nswitch login\r\nswitch# ",     // generic banner -> ambiguous
		"ArubaOS-CX Virtual.10.08.1010\r\n", // show version output -> decisive
	}}
	d, _, err := Identify(context.Background(), f, driver.All(), "sit", "pass")
	if err != nil {
		t.Fatalf("identify error: %v", err)
	}
	if d.Name() != "aruba-cx" {
		t.Fatalf("vendor = %q, want aruba-cx", d.Name())
	}
	probed := false
	for _, s := range f.sent {
		if s == "show version" {
			probed = true
		}
	}
	if !probed {
		t.Errorf("expected a `show version` probe for ambiguous banner")
	}
}
