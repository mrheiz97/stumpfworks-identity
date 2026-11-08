//go:build !linux

package adprofile

import "os/exec"

func setCreateChildIdentity(*exec.Cmd) {}
