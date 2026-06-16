// Package snmpcheck does a fast SNMPv2c probe to tell whether a device already
// answers to a given community. The runner uses it to skip devices that are
// already configured, so a re-run only touches the ones that still need it
// (e.g. those that timed out or were rate-limited on a previous pass).
package snmpcheck

import (
	"time"

	"github.com/gosnmp/gosnmp"
)

// sysName.0 — present on every SNMP agent, so a valid response means the
// community works.
const oidSysName = "1.3.6.1.2.1.1.5.0"

// Configured reports whether host answers an SNMPv2c GET with community. In
// SNMPv2c a wrong community simply yields no response, so a successful GET
// means the community is already applied.
func Configured(host, community string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	client := &gosnmp.GoSNMP{
		Target:    host,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
		MaxOids:   1,
	}
	if err := client.Connect(); err != nil {
		return false
	}
	defer client.Conn.Close()

	resp, err := client.Get([]string{oidSysName})
	if err != nil || resp == nil || len(resp.Variables) == 0 {
		return false
	}
	// Any non-error variable type means the agent answered with this community.
	switch resp.Variables[0].Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return false
	default:
		return true
	}
}
