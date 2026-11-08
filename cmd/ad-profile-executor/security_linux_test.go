package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateInputsAndExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if protectedDirectory(dir, false) != nil {
		t.Fatal("private directory rejected")
	}
	if e := os.Chmod(dir, 0750); e != nil {
		t.Fatal(e)
	}
	if protectedDirectory(dir, false) == nil || protectedDirectory(dir, true) != nil {
		t.Fatal("directory rights not enforced")
	}
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "secret")
	if e := os.WriteFile(path, []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := privateFile(path); e != nil {
		t.Fatal("private input rejected")
	}
	link := filepath.Join(dir, "symlink")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := privateFile(link); e == nil {
		t.Fatal("symlink accepted")
	}
	if e := os.Chmod(path, 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := privateFile(path); e == nil {
		t.Fatal("group-readable secret accepted")
	}
	os.Chmod(path, 0600)
	hard := filepath.Join(dir, "hardlink")
	if e := os.Link(path, hard); e != nil {
		t.Fatal(e)
	}
	if _, e := privateFile(path); e == nil {
		t.Fatal("hard-linked secret accepted")
	}
	lock := filepath.Join(dir, "executor.lock")
	unlock, e := lockExecutor(lock)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := lockExecutor(lock); e == nil {
		second()
		t.Fatal("second executor accepted")
	}
	unlock()
	unlock, e = lockExecutor(lock)
	if e != nil {
		t.Fatal("released lock unavailable")
	}
	unlock()
	if e := os.Symlink(path, filepath.Join(dir, "bad.lock")); e != nil {
		t.Fatal(e)
	}
	if unlock, e := lockExecutor(filepath.Join(dir, "bad.lock")); e == nil {
		unlock()
		t.Fatal("lock symlink accepted")
	}
}
