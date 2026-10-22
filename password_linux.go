//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// readPasswordLine turns off terminal echo while reading a password. If stdin
// is a pipe/file (not a terminal), it falls back to a normal line read so the
// command remains scriptable.
func readPasswordLine(f *os.File) (string, error) {
	fd := int(f.Fd())
	var old syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&old)), 0, 0, 0); errno != 0 {
		return readLine(f)
	}
	noEcho := old
	noEcho.Lflag &^= syscall.ECHO
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&noEcho)), 0, 0, 0); errno != 0 {
		return readLine(f)
	}
	defer syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&old)), 0, 0, 0)
	return readLine(f)
}
