//go:build linux

package main

import (
	"os"
	"syscall"
)

func preserveOwner(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Chown(path, int(st.Uid), int(st.Gid))
}
