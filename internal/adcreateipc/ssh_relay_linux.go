//go:build linux

package adcreateipc

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"golang.org/x/sys/unix"
)

const (
	relayRequestBytes  = 16 << 10
	relayResponseBytes = 72 << 10
	relayTimeout       = 35 * time.Second
)

// SSHTarget is provisioned locally. No IPC field controls the SSH command.
type SSHTarget struct {
	Host, User, IdentityFile, KnownHostsFile string
	Port                                     uint16
}

var sshUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
var sshHost = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)

func sshFile(path string, key bool) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, " \t\r\n%~") {
		return false
	}
	owner := uint32(os.Geteuid())
	for dir := filepath.Dir(path); dir != "/"; dir = filepath.Dir(dir) {
		var st unix.Stat_t
		if unix.Lstat(dir, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
			(st.Uid != 0 && (!key || st.Uid != owner)) ||
			(st.Mode&0022 != 0 && !(dir == "/tmp" && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
			return false
		}
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return false
	}
	if key {
		return st.Uid == owner && st.Mode&0777 == 0600
	}
	return st.Uid == 0 && st.Mode&0022 == 0
}

func (s SSHTarget) arguments() ([]string, error) {
	if !sshUser.MatchString(s.User) || s.User == "root" || !sshHost.MatchString(s.Host) ||
		s.Port == 0 || !sshFile(s.IdentityFile, true) || !sshFile(s.KnownHostsFile, false) {
		return nil, adcreate.ErrDenied
	}
	return []string{"-F", "/dev/null", "-T", "-p", strconv.Itoa(int(s.Port)), "-i", s.IdentityFile,
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + s.KnownHostsFile,
		"-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
		"-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no",
		"-o", "PreferredAuthentications=publickey", "-o", "ConnectTimeout=5",
		"-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=5",
		// Without the forced command, the remote process exits without reading
		// the RPC stream. In particular, it never opens an interactive shell.
		"-o", "ServerAliveCountMax=2", "-l", s.User, "--", s.Host, "false"}, nil
}

// ServeSSHRelay serves the LOGIN01 Unix endpoint. Every authenticated
// connection gets exactly one SSH process, with no retry or multiplexing.
func ServeSSHRelay(ctx context.Context, config Config, target SSHTarget) error {
	args, err := target.arguments()
	if err != nil {
		return err
	}
	listener, lock, err := listenAuthenticated(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	var requests sync.WaitGroup
	defer func() {
		cancel()
		listener.Close()
		requests.Wait()
		unix.Close(lock)
	}()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		requests.Add(1)
		go func() {
			defer requests.Done()
			defer conn.Close()
			relaySSH(ctx, conn, args)
		}()
	}
}

func relaySSH(parent context.Context, conn net.Conn, args []string) {
	ctx, cancel := context.WithTimeout(parent, relayTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	cmd.Stderr = io.Discard
	in, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	defer in.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	defer out.Close()
	if cmd.Start() != nil {
		return
	}
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		defer in.Close()
		if copyRelay(in, conn, relayRequestBytes) != nil {
			cancel()
		}
	}()
	if copyRelay(conn, out, relayResponseBytes) != nil {
		cancel()
	}
	conn.Close()
	in.Close()
	<-inputDone
	_ = cmd.Wait()
}

// ServeSSHCommand runs only as the DC01 forced command. The executor's Unix
// ownership, inode and kernel credentials are verified before any bytes flow.
func ServeSSHCommand(parent context.Context, config Config, input io.Reader, output io.Writer) error {
	ctx, cancel := context.WithTimeout(parent, relayTimeout)
	defer cancel()
	conn, err := dial(ctx, config)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	result := make(chan error, 1)
	go func() {
		if copyRelay(conn, input, relayRequestBytes) != nil {
			cancel()
		}
		_ = conn.(*net.UnixConn).CloseWrite()
	}()
	go func() { result <- copyRelay(output, conn, relayResponseBytes) }()
	select {
	case err = <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func copyRelay(dst io.Writer, src io.Reader, limit int64) error {
	_, err := io.CopyN(dst, src, limit)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return adcreate.ErrDenied
	}
	return err
}
