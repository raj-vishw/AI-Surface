// Package tcpfixture provides a deterministic, fully local generic TCP
// server used by internal/discovery/network's tests — a service that
// isn't HTTP (test/fixtures/http already covers that case for network
// discovery's HTTP-candidate-port tests) but still accepts TCP
// connections, so OPEN-state detection can be tested for a non-HTTP
// service too (phase4.md §36/§37).
package tcpfixture

import (
	"net"
	"strconv"
)

// Server is the fixture TCP service. It accepts connections and, per
// configuration, optionally delays before closing them or closes them
// immediately — no application-layer protocol is spoken, matching
// phase4.md §22's "do not send arbitrary protocol payloads to unknown
// services" from the client side and giving that same guarantee nothing
// unexpected happens server-side either.
type Server struct {
	listener net.Listener
	closed   chan struct{}
}

// New starts a Server listening on an OS-assigned ephemeral port and
// returns immediately — the caller must Close it.
func New() (*Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{listener: listener, closed: make(chan struct{})}
	go s.acceptLoop()
	return s, nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			// Accept and immediately close — enough for a TCP connect
			// scanner to observe OPEN; no protocol payload is read or
			// written.
			_ = conn.Close()
		}()
	}
}

// NewOnPort starts a Server on a specific, caller-chosen port (used by the
// standalone local test environment binary — for manual testing, where
// predictable ports are needed to pass to `ai-recon network-scan`).
func NewOnPort(port int) (*Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	s := &Server{listener: listener, closed: make(chan struct{})}
	go s.acceptLoop()
	return s, nil
}

// Addr returns the fixture's listen address (e.g. "127.0.0.1:54321").
func (s *Server) Addr() string { return s.listener.Addr().String() }

// Port returns the fixture's listening TCP port.
func (s *Server) Port() int { return s.listener.Addr().(*net.TCPAddr).Port }

// Close shuts the fixture down. Safe to call once per Server.
func (s *Server) Close() error {
	close(s.closed)
	return s.listener.Close()
}

// ClosedPort returns a TCP port on 127.0.0.1 that is guaranteed to have
// nothing listening on it at the moment this function returns (a fresh
// listener is opened and immediately closed to reserve then release an
// ephemeral port) — deterministic, offline CLOSED-state test fixture
// (phase4.md §36: "leave selected ports closed").
func ClosedPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		return 0, err
	}
	return port, nil
}
