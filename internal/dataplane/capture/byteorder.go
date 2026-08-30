package capture

import "encoding/binary"

// The four helpers below are the only place in the codebase permitted to
// convert between network byte order and host byte order (design section
// 6.4.3). No call site may open-code an encoding/binary conversion.
//
// A __u16/__u32 holding network-order bytes is reinterpreted here as a
// native-endian word, which is exactly how cilium/ebpf marshals the kernel
// structures these values come from.

// ntohs converts a uint16 holding network-order port bytes into a host-order
// integer.
func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}

// htons is the exact inverse of ntohs.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ntohl converts a uint32 holding network-order bytes into a host-order integer.
func ntohl(v uint32) uint32 {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return binary.BigEndian.Uint32(b[:])
}

// htonl is the exact inverse of ntohl.
func htonl(v uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return binary.NativeEndian.Uint32(b[:])
}
