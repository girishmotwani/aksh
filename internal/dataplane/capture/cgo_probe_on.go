//go:build cgo

package capture

// cgoLinked reports the build-time cgo state. This file is compiled only when
// the binary is linked with cgo, so the answer reflects the actual build rather
// than an environment variable that can disagree with it. Gate P1 relies on
// this being the ground truth (issue #66).
func cgoLinked() bool { return true }
