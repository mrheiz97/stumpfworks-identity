//go:build linux

package adprofile

import (
	"os/exec"
	"syscall"
)

func setCreateChildIdentity(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
}
