//go:build !windows

package clientupdate

import (
	"golang.org/x/sys/unix"
	"os"
)

func tryUpdateLock(path string) (func(), bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == unix.EWOULDBLOCK {
		f.Close()
		return func() {}, false, nil
	}
	if err != nil {
		f.Close()
		return nil, false, err
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, true, nil
}
