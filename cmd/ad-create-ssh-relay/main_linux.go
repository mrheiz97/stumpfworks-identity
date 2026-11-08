//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreateipc"
	"golang.org/x/sys/unix"
)

type config struct {
	IPC adcreateipc.Config
	SSH *adcreateipc.SSHTarget
}

func readConfig(path string) (config, error) {
	var c config
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return c, adcreate.ErrDenied
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return c, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 ||
		st.Uid != 0 || st.Mode&0022 != 0 || st.Size > 8192 {
		return c, adcreate.ErrDenied
	}
	d := json.NewDecoder(io.LimitReader(f, 8193))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, adcreate.ErrDenied
	}
	return c, nil
}

func run() error {
	mode := flag.String("mode", "", "login or dc")
	path := flag.String("config", "", "absolute root-owned JSON configuration")
	flag.Parse()
	if flag.NArg() != 0 || (*mode != "login" && *mode != "dc") || os.Geteuid() == 0 {
		return adcreate.ErrDenied
	}
	c, err := readConfig(*path)
	if err != nil {
		return err
	}
	if !c.IPC.Enabled {
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if *mode == "login" && c.SSH != nil {
		return adcreateipc.ServeSSHRelay(ctx, c.IPC, *c.SSH)
	}
	if *mode == "dc" && c.SSH == nil {
		return adcreateipc.ServeSSHCommand(ctx, c.IPC, os.Stdin, os.Stdout)
	}
	return adcreate.ErrDenied
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Create SSH relay unavailable")
		os.Exit(1)
	}
}
