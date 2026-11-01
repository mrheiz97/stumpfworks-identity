package clientupdate

import (
	"golang.org/x/sys/windows"
	"os"
)

func tryUpdateLock(path string) (func(), bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	o := &windows.Overlapped{}
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, o)
	if err == windows.ERROR_LOCK_VIOLATION {
		f.Close()
		return func() {}, false, nil
	}
	if err != nil {
		f.Close()
		return nil, false, err
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, o); _ = f.Close() }, true, nil
}
