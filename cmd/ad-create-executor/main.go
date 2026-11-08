package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	state := flag.String("state", "", "private executor directory")
	enable := flag.Bool("enable", false, "enable native Create in the isolated lab")
	initialize := flag.Bool("initialize-journal", false, "create a new journal offline")
	backup := flag.String("backup-journal", "", "write an encrypted offline archive")
	restore := flag.String("restore-journal", "", "restore into a fresh read-only recovery journal")
	handoff := flag.Bool("handoff-journal", false, "rebind existing journal to the active laboratory DC")
	flag.Parse()
	modes := 0
	for _, selected := range []bool{*enable, *initialize, *backup != "", *restore != "", *handoff} {
		if selected {
			modes++
		}
	}
	if flag.NArg() != 0 || modes > 1 {
		fail(errors.New("invalid executor mode"))
	}
	if modes == 0 {
		fmt.Println("AD Create executor disabled")
		return
	}
	if err := run(*state, *initialize, *backup, *restore, *handoff); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "AD Create executor:", err)
	os.Exit(1)
}
