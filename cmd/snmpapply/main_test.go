package main

import (
	"errors"
	"testing"
)

func TestProbeReason(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"auth", errors.New("handshake ssh: ssh: unable to authenticate, attempted methods [none password]"), "credenciales SSH inválidas"},
		{"timeout", errors.New("conexión: dial tcp 192.0.2.9:22: i/o timeout"), "sin respuesta (timeout)"},
		{"deadline", errors.New("handshake ssh: context deadline exceeded"), "sin respuesta (timeout)"},
		{"refused", errors.New("conexión: dial tcp 192.0.2.9:22: connect: connection refused"), "conexión rechazada"},
		{"noroute", errors.New("conexión: dial tcp: no route to host"), "host inalcanzable"},
		{"nohost", errors.New("conexión: dial tcp: lookup foo: no such host"), "host inalcanzable"},
		{"detect", errors.New("no se pudo identificar el vendor tras show version"), "vendor no identificado"},
		{"other", errors.New("solicitud de pty: algo raro\nsegunda línea"), "solicitud de pty: algo raro"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := probeReason(c.err); got != c.want {
				t.Errorf("probeReason(%q) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}
