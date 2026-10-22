//go:build !linux

package main

import "os"

func preserveOwner(string, os.FileInfo) error {
	return nil
}
