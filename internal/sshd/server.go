// Package sshd is the SSH front door of the honeypot: it speaks the
// protocol, accepts every login, and hands authenticated sessions to a
// Handler. It knows nothing about shells or models.
package sshd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config tunes the server. Zero values fall back to Defaults().
type Config struct {
	// Addr is the TCP listen address, e.g. ":2222".
	Addr string
	// ServerVersion is the banner sent to clients. It should look like a
	// real distribution's sshd.
	ServerVersion string
	// AuthDelay is how long each password attempt is held before answering,
	// so the server does not respond faster than a real one would.
	AuthDelay time.Duration
	// AcceptAfter is the password attempt number (per connection) that
	// succeeds. 1 accepts the first attempt; 3 makes the bot work a little.
	AcceptAfter int
	// MaxAuthTries mirrors OpenSSH's MaxAuthTries; after this many failures
	// the connection is dropped.
	MaxAuthTries int
	// MaxConns caps concurrent connections. Extra ones are closed at once.
	MaxConns int
	// IdleTimeout ends a connection with no channel activity for this long.
	IdleTimeout time.Duration
}

// Defaults are the values used for zero Config fields.
func Defaults() Config {
	return Config{
		Addr:          ":2222",
		ServerVersion: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11",
		AuthDelay:     400 * time.Millisecond,
		AcceptAfter:   1,
		MaxAuthTries:  6,
		MaxConns:      100,
		IdleTimeout:   5 * time.Minute,
	}
}

func (c Config) withDefaults() Config {
	d := Defaults()
	if c.Addr == "" {
		c.Addr = d.Addr
	}
	if c.ServerVersion == "" {
		c.ServerVersion = d.ServerVersion
	}
	if c.AuthDelay == 0 {
		c.AuthDelay = d.AuthDelay
	}
	if c.AcceptAfter <= 0 {
		c.AcceptAfter = d.AcceptAfter
	}
	if c.MaxAuthTries <= 0 {
		c.MaxAuthTries = d.MaxAuthTries
	}
	if c.MaxConns <= 0 {
		c.MaxConns = d.MaxConns
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = d.IdleTimeout
	}
	return c
}

// AuthMethod names how a login was attempted.
type AuthMethod string

const (
	AuthPassword    AuthMethod = "password"
	AuthPublicKey   AuthMethod = "publickey"
	AuthInteractive AuthMethod = "keyboard-interactive"
	AuthNone        AuthMethod = "none"
)

// AuthAttempt is one login attempt on a connection.
type AuthAttempt struct {
	Time     time.Time
	Method   AuthMethod
	User     string
	Password string // password or keyboard-interactive answer; empty for keys
	KeyType  string // e.g. "ssh-ed25519" for public key attempts
	KeyFP    string // SHA256 fingerprint for public key attempts
	Accepted bool
}

// Conn describes one TCP/SSH connection from an attacker.
type Conn struct {
	ID            string
	RemoteAddr    net.Addr
	LocalAddr     net.Addr
	ClientVersion string
	StartedAt     time.Time
	// User and Password are the credentials that were finally accepted.
	User     string
	Password string

	mu       sync.Mutex
	attempts []AuthAttempt
	sessions int
}

// Attempts returns a copy of every auth attempt seen so far.
func (c *Conn) Attempts() []AuthAttempt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AuthAttempt(nil), c.attempts...)
}

func (c *Conn) addAttempt(a AuthAttempt) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts = append(c.attempts, a)
	return len(c.attempts)
}

// Handler receives connection lifecycle events and authenticated sessions.
// Every method may be called concurrently for different connections.
type Handler interface {
	// Connected is called once the TCP connection is accepted, before any
	// SSH handshake. ClientVersion is not known yet.
	Connected(*Conn)
	// AuthAttempt is called for every login attempt, accepted or not.
	AuthAttempt(*Conn, AuthAttempt)
	// Session is called for each session channel the client opens after
	// authenticating. It must block until the session is over.
	Session(context.Context, *Session)
	// Disconnected is called when the connection ends, whether or not it
	// ever authenticated. err is nil for a clean close.
	Disconnected(*Conn, error)
}

// Server is the honeypot's SSH listener.
type Server struct {
	cfg     Config
	handler Handler
	log     *slog.Logger
	hostKey ssh.Signer

	listener net.Listener
	conns    atomic.Int64
	wg       sync.WaitGroup
	closing  atomic.Bool
}

// New builds a server. hostKey comes from LoadOrCreateHostKey.
func New(cfg Config, hostKey ssh.Signer, h Handler, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg.withDefaults(), handler: h, log: log, hostKey: hostKey}
}

// ListenAndServe blocks until ctx is cancelled or the listener fails.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled. It then closes
// the listener and waits for in-flight connections to finish.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.listener = ln
	s.log.Info("ssh listening", "addr", ln.Addr().String(), "banner", s.cfg.ServerVersion)

	stop := context.AfterFunc(ctx, func() {
		s.closing.Store(true)
		_ = ln.Close()
	})
	defer stop()

	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closing.Load() {
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		if s.conns.Load() >= int64(s.cfg.MaxConns) {
			s.log.Warn("connection limit reached, dropping", "remote", c.RemoteAddr())
			_ = c.Close()
			continue
		}
		s.conns.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.conns.Add(-1)
			s.handleConn(ctx, c)
		}()
	}
	s.wg.Wait()
	return nil
}

// Addr returns the bound address once Serve has been called.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) handleConn(ctx context.Context, nc net.Conn) {
	conn := &Conn{
		ID:         newID(),
		RemoteAddr: nc.RemoteAddr(),
		LocalAddr:  nc.LocalAddr(),
		StartedAt:  time.Now(),
	}
	s.handler.Connected(conn)

	// The whole connection dies with the server context.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	defer stop()

	sshConn, chans, reqs, err := ssh.NewServerConn(nc, s.serverConfig(conn))
	if err != nil {
		s.handler.Disconnected(conn, err)
		return
	}
	conn.ClientVersion = string(sshConn.ClientVersion())
	conn.User = sshConn.User()
	s.log.Info("authenticated", "conn", conn.ID, "remote", conn.RemoteAddr, "user", conn.User, "client", conn.ClientVersion)

	go ssh.DiscardRequests(reqs)

	idle := newIdleTimer(s.cfg.IdleTimeout, func() {
		s.log.Info("idle timeout", "conn", conn.ID)
		_ = sshConn.Close()
	})
	defer idle.Stop()

	var sessions sync.WaitGroup
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			continue
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			idle.Hold()
			defer idle.Release()
			s.serveSession(ctx, conn, ch, chReqs)
		}()
	}
	sessions.Wait()
	s.handler.Disconnected(conn, cleanClose(sshConn.Wait()))
}

// cleanClose maps the ways a client normally goes away to nil so that
// Disconnected only carries genuine errors.
func cleanClose(err error) error {
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		return nil
	case strings.Contains(err.Error(), "disconnect, reason 11"):
		// SSH_DISCONNECT_BY_APPLICATION: the client said goodbye.
		return nil
	}
	return err
}

func (s *Server) serverConfig(conn *Conn) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: s.cfg.ServerVersion,
		MaxAuthTries:  s.cfg.MaxAuthTries,
		PasswordCallback: func(md ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			return s.checkSecret(conn, AuthPassword, md.User(), string(pw))
		},
		KeyboardInteractiveCallback: func(md ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := ask(md.User(), "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			pw := ""
			if len(answers) > 0 {
				pw = answers[0]
			}
			return s.checkSecret(conn, AuthInteractive, md.User(), pw)
		},
		PublicKeyCallback: func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Keys are never accepted (we cannot know their private half is
			// not real) but they are worth recording: a bot presenting a
			// key is a stolen key in the wild.
			s.record(conn, AuthAttempt{
				Time:    time.Now(),
				Method:  AuthPublicKey,
				User:    md.User(),
				KeyType: key.Type(),
				KeyFP:   ssh.FingerprintSHA256(key),
			})
			return nil, errors.New("publickey rejected")
		},
	}
	cfg.AddHostKey(s.hostKey)
	return cfg
}

// checkSecret records a password-like attempt and accepts the AcceptAfter-th.
func (s *Server) checkSecret(conn *Conn, method AuthMethod, user, secret string) (*ssh.Permissions, error) {
	time.Sleep(s.cfg.AuthDelay)
	a := AuthAttempt{Time: time.Now(), Method: method, User: user, Password: secret}
	n := conn.countSecretAttempts() + 1
	a.Accepted = n >= s.cfg.AcceptAfter
	s.record(conn, a)
	if !a.Accepted {
		return nil, errors.New("password rejected")
	}
	conn.mu.Lock()
	conn.Password = secret
	conn.mu.Unlock()
	return &ssh.Permissions{}, nil
}

func (c *Conn) countSecretAttempts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, a := range c.attempts {
		if a.Method == AuthPassword || a.Method == AuthInteractive {
			n++
		}
	}
	return n
}

func (s *Server) record(conn *Conn, a AuthAttempt) {
	conn.addAttempt(a)
	s.handler.AuthAttempt(conn, a)
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b[:])
}

// idleTimer fires after d of nothing happening. Hold/Release pause it while
// a session is open, since interactive shells idle legitimately.
type idleTimer struct {
	d     time.Duration
	fire  func()
	mu    sync.Mutex
	held  int
	timer *time.Timer
}

func newIdleTimer(d time.Duration, fire func()) *idleTimer {
	t := &idleTimer{d: d, fire: fire}
	t.timer = time.AfterFunc(d, t.tick)
	return t
}

func (t *idleTimer) tick() {
	t.mu.Lock()
	held := t.held > 0
	t.mu.Unlock()
	if !held {
		t.fire()
	}
}

func (t *idleTimer) Hold() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.held++
	t.timer.Stop()
}

func (t *idleTimer) Release() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.held--
	if t.held == 0 {
		t.timer.Reset(t.d)
	}
}

func (t *idleTimer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timer.Stop()
}
