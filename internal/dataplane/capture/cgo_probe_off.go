//go:build !cgo

package capture

// cgoLinked reports the build-time cgo state. This file is compiled only when
// the binary is pure Go, so it reports false, which is the state gate P1
// requires: syscall.AllThreadsSyscall (the privilege drop of design section
// 6.6.2) is unusable in a cgo-linked binary.
func cgoLinked() bool { return false }
