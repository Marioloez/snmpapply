package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// Dialer opens interactive SSH sessions tuned for legacy network gear.
type Dialer struct {
	ConnectTimeout time.Duration
	IOTimeout      time.Duration
}

// Conn is an open SSH connection with an interactive shell, embedding the
// expect Session so callers can Expect/Send/Collect directly.
type Conn struct {
	*Session
	client *ssh.Client
	sess   *ssh.Session
}

// Close tears down the shell and the underlying SSH connection.
func (c *Conn) Close() error {
	if c.sess != nil {
		_ = c.sess.Close()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Open dials host:port, authenticates with password (and keyboard-interactive,
// which Huawei VRP requires), allocates a PTY, and starts an interactive shell.
//
// The algorithm lists deliberately include 2005-era primitives
// (diffie-hellman-group1-sha1, aes128-cbc, 3des-cbc, hmac-sha1, ssh-rsa) that
// Go disables by default — these switches speak nothing newer. Modern
// algorithms stay first so healthy devices negotiate strong crypto.
func (d Dialer) Open(ctx context.Context, host string, port int, user, password string, echo io.Writer) (*Conn, error) {
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSA, // ssh-rsa (SHA-1) — legacy host keys
		},
		Timeout: d.ConnectTimeout,
	}
	cfg.KeyExchanges = []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
	}
	cfg.Ciphers = []string{
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-cbc", "3des-cbc",
	}
	cfg.MACs = []string{
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96",
	}

	nd := net.Dialer{Timeout: d.ConnectTimeout}
	tcp, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("conexión %s: %w", addr, err)
	}
	// ssh.NewClientConn has no timeout of its own, so a host that accepts TCP
	// but stalls the SSH handshake (rate-limited / overloaded gear) would hang
	// indefinitely. Bound the handshake with a socket deadline, then clear it
	// so the interactive session isn't capped by it (the expect engine has its
	// own per-step timeout).
	_ = tcp.SetDeadline(time.Now().Add(d.ConnectTimeout))
	clientConn, chans, reqs, err := ssh.NewClientConn(tcp, addr, cfg)
	if err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("handshake ssh %s: %w", addr, err)
	}
	_ = tcp.SetDeadline(time.Time{})
	client := ssh.NewClient(clientConn, chans, reqs)

	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("abrir sesión %s: %w", addr, err)
	}

	// A near-complete mode set matters: without ICRNL (CR->NL on input) some
	// CLIs (ArubaOS-CX) echo a command but never execute it — they never see a
	// line terminator. This mirrors what a normal OpenSSH client negotiates.
	// ECHO stays off so echoed commands don't pollute verification output.
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.ICRNL:         1,
		ssh.IXON:          1,
		ssh.IXANY:         1,
		ssh.IMAXBEL:       1,
		ssh.OPOST:         1,
		ssh.ONLCR:         1,
		ssh.ISIG:          1,
		ssh.ICANON:        1,
		ssh.IEXTEN:        1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}
	// Tall/wide PTY minimizes pager prompts and line wrapping.
	if err := sess.RequestPty("xterm", 1000, 300, modes); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("solicitud de pty %s: %w", addr, err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("pipe stdout %s: %w", addr, err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("pipe stdin %s: %w", addr, err)
	}
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("iniciar shell %s: %w", addr, err)
	}

	// A PTY merges stderr into the session stream, so reading stdout is enough.
	expecter := NewSession(stdout, stdin, echo, d.IOTimeout)
	return &Conn{Session: expecter, client: client, sess: sess}, nil
}
