package snmpcheck

import (
	"testing"
	"time"
)

func TestConfiguredUnreachable(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — no SNMP agent. Must report false
	// (and return promptly, bounded by the timeout).
	if Configured("192.0.2.1", "whatever", 1*time.Second) {
		t.Error("unreachable host must report not configured")
	}
}
