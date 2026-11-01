package clientupdate

import (
	"os"
	"runtime"
)

// Linux directory fsync makes snapshot publication durable before target
// replacement. Windows is a development/test host, not an installation target.
func syncUpdateDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, e := os.Open(path)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
