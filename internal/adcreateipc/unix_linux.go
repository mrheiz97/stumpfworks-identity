//go:build linux

package adcreateipc

import (
	"context"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func validateConfig(c Config, server bool) error {
	if !c.Enabled || c.Peer == nil || c.Owner == nil || !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket || len(c.Socket) > 100 || strings.ContainsAny(c.Socket, "\x00\r\n") {
		return adcreate.ErrDenied
	}
	if server && (c.Owner.UID != uint32(os.Geteuid()) || c.Peer.UID == c.Owner.UID) {
		return adcreate.ErrDenied
	}
	if !server && (c.Peer.UID != c.Owner.UID || c.Peer.UID == uint32(os.Geteuid())) {
		return adcreate.ErrDenied
	}
	return nil
}

// Every path component is opened without following links. Root/executor own
// all ancestors; only a root-owned sticky /tmp is exempted from write-bit denial.
func parent(c Config) (int, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, adcreate.ErrDenied
	}
	components := strings.Split(strings.TrimPrefix(filepath.Dir(c.Socket), "/"), "/")
	path := ""
	for index, part := range components {
		if part == "" {
			unix.Close(fd)
			return -1, adcreate.ErrDenied
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, adcreate.ErrDenied
		}
		fd = next
		var st unix.Stat_t
		path += "/" + part
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != c.Owner.UID) || ((st.Mode&0022) != 0 && !(path == "/tmp" && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
			unix.Close(fd)
			return -1, adcreate.ErrDenied
		}
		if index == len(components)-1 && (st.Uid != c.Owner.UID || st.Gid != c.Owner.GID || st.Mode&0027 != 0) {
			unix.Close(fd)
			return -1, adcreate.ErrDenied
		}
	}
	return fd, nil
}
func peer(conn *net.UnixConn) (Identity, error) {
	raw, e := conn.SyscallConn()
	if e != nil {
		return Identity{}, adcreate.ErrDenied
	}
	var cred *unix.Ucred
	var failure error
	if raw.Control(func(fd uintptr) { cred, failure = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || failure != nil || cred == nil || cred.Pid <= 0 {
		return Identity{}, adcreate.ErrDenied
	}
	return Identity{UID: cred.Uid, GID: cred.Gid}, nil
}
func socketStat(fd int, c Config) (unix.Stat_t, error) {
	var st unix.Stat_t
	if unix.Fstatat(fd, filepath.Base(c.Socket), &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != c.Owner.UID || st.Gid != c.Owner.GID || st.Mode&0777 != 0660 {
		return st, adcreate.ErrDenied
	}
	return st, nil
}
func dial(ctx context.Context, c Config) (net.Conn, error) {
	if validateConfig(c, false) != nil {
		return nil, adcreate.ErrDenied
	}
	fd, e := parent(c)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	before, e := socketStat(fd, c)
	if e != nil {
		return nil, e
	}
	conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", c.Socket)
	if e != nil {
		return nil, adcreate.ErrDenied
	}
	u, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, adcreate.ErrDenied
	}
	identity, e := peer(u)
	after, statErr := socketStat(fd, c)
	if e != nil || identity != *c.Peer || statErr != nil || before.Ino != after.Ino || before.Dev != after.Dev {
		conn.Close()
		return nil, adcreate.ErrDenied
	}
	return conn, nil
}

type verifiedConn struct {
	net.Conn
	identity Identity
	release  func()
	once     sync.Once
}

func (c *verifiedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }

type authenticatedListener struct {
	*net.UnixListener
	expected Identity
	slots    chan struct{}
}

func (l *authenticatedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			return nil, e
		}
		identity, e := peer(c)
		if e != nil || identity != l.expected {
			c.Close()
			continue
		}
		select {
		case l.slots <- struct{}{}:
			return &verifiedConn{Conn: c, identity: identity, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}

type Server struct {
	http     *http.Server
	listener *authenticatedListener
	lock     int
	once     sync.Once
	closeErr error
}

func Listen(c Config, backend adcreate.Operations) (*Server, error) {
	if backend == nil || !backend.IsEnabled() {
		return nil, adcreate.ErrDenied
	}
	if _, ok := backend.(ExecutorOperations); !ok {
		return nil, adcreate.ErrDenied
	}
	auth, lock, e := listenAuthenticated(c)
	if e != nil {
		return nil, e
	}
	h := &http.Server{Handler: rpcHandler(backend, *c.Peer), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0), ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		verified, ok := conn.(*verifiedConn)
		if !ok {
			return ctx
		}
		return context.WithValue(ctx, peerKey{}, verified.identity)
	}}
	h.SetKeepAlivesEnabled(false)
	return &Server{http: h, listener: auth, lock: lock}, nil
}

func listenAuthenticated(c Config) (*authenticatedListener, int, error) {
	if validateConfig(c, true) != nil {
		return nil, -1, adcreate.ErrDenied
	}
	fd, e := parent(c)
	if e != nil {
		return nil, -1, e
	}
	defer unix.Close(fd)
	lock, e := unix.Openat(fd, filepath.Base(c.Socket)+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, -1, adcreate.ErrDenied
	}
	var st unix.Stat_t
	if unix.Fstat(lock, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Uid != c.Owner.UID || unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unix.Close(lock)
		return nil, -1, adcreate.ErrDenied
	}
	var existing unix.Stat_t
	if e = unix.Fstatat(fd, filepath.Base(c.Socket), &existing, unix.AT_SYMLINK_NOFOLLOW); e != unix.ENOENT {
		unix.Close(lock)
		return nil, -1, adcreate.ErrDenied
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: c.Socket, Net: "unix"})
	if e != nil {
		unix.Close(lock)
		return nil, -1, adcreate.ErrDenied
	}
	listener.SetUnlinkOnClose(false) // Never delete a stale/replaced endpoint implicitly.
	if os.Chown(c.Socket, int(c.Owner.UID), int(c.Owner.GID)) != nil || os.Chmod(c.Socket, 0660) != nil {
		listener.Close()
		unix.Close(lock)
		return nil, -1, adcreate.ErrDenied
	}
	if _, e = socketStat(fd, c); e != nil {
		listener.Close()
		unix.Close(lock)
		return nil, -1, e
	}
	return &authenticatedListener{UnixListener: listener, expected: *c.Peer, slots: make(chan struct{}, 8)}, lock, nil
}
func (s *Server) Serve() error {
	e := s.http.Serve(s.listener)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
func (s *Server) Close() error {
	s.once.Do(func() { s.closeErr = s.http.Close(); _ = s.listener.Close(); unix.Close(s.lock) })
	return s.closeErr
}

// Shutdown stops accepting requests and waits for active handlers. The caller
// must still Close the server to release the socket fence.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
