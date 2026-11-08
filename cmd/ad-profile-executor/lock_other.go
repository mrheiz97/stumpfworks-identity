//go:build !linux

package main

import "github.com/TheRealHZL/stumpfworks-identity/internal/adprofile"

func lockExecutor(string) (func(), error)   { return nil, adprofile.ErrDenied }
func privateFile(string) ([]byte, error)    { return nil, adprofile.ErrDenied }
func protectedDirectory(string, bool) error { return adprofile.ErrDenied }
