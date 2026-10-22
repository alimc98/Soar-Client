//go:build !linux

package main

import "os"

func readPasswordLine(f *os.File) (string, error) {
	return readLine(f)
}
