package main

import (
	"github.com/TheRealHZL/stumpfworks-identity/internal/adprofile"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
)

func protectedDirectory(path string, shared bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return adprofile.ErrDenied
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return adprofile.ErrDenied
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return adprofile.ErrDenied
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	mask := uint32(0077)
	if shared {
		mask = 0027
	}
	if unix.Fstat(fd, &st) != nil || st.Mode&mask != 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return adprofile.ErrDenied
	}
	return nil
}

func lockExecutor(path string) (func(), error) {
	unix.Umask(0077)
	fd, e := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, adprofile.ErrDenied
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Nlink != 1 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		f.Close()
		return nil, adprofile.ErrDenied
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, adprofile.ErrDenied
	}
	return func() { f.Close() }, nil
}

func privateFile(path string) ([]byte, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, adprofile.ErrDenied
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Nlink != 1 || st.Size > 1<<20 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return nil, adprofile.ErrDenied
	}
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return nil, adprofile.ErrDenied
	}
	return b, nil
}
