//go:build !linux

package main

import "errors"

func run(string, bool, string, string, bool) error { return errors.New("Linux required") }
