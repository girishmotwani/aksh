package capture

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"reflect"
	"testing"
	"unsafe"
)

// TestByteOrderHelpers covers unit test spec section 3 (#1-#14): the four
// network/host byte-order conversion helpers, which are the only permitted
// conversion site in the package (design section 6.4.3).
//
// Endianness constraint: the hard-coded expectations in #2, #3, #5, #6, #9 and
// #10 encode the behaviour on a little-endian host, which is what every target
// of this project (amd64, arm64) is. On a big-endian host these helpers are
// the identity and those cases would fail by construction; #13 and #14 are the
// endianness-neutral cross-check against encoding/binary and hold everywhere.
//
// Falsifiability note: #1, #2, #4, #5 (swap-invariant inputs) and #7, #8, #11,
// #12 (round-trip/involution properties) also pass under an identity
// implementation - that is inherent to the properties the spec names, not a
// defect in the assertions. #3, #6, #9, #10, #13, #14 and
// StructDecode_KnownByteSequence_ProducesExpectedFields are the cases that
// actually pin the swap direction, and each asserts a single expected value.
func TestByteOrderHelpers(t *testing.T) {
	t.Run("Ntohs_ZeroValue_ReturnsZero", func(t *testing.T) {
		if got := ntohs(0); got != 0 {
			t.Fatalf("ntohs(0) = %#04x, want 0x0000", got)
		}
	})

	t.Run("Ntohs_MaxValue_ReturnsByteSwapped", func(t *testing.T) {
		if got := ntohs(0xFFFF); got != 0xFFFF {
			t.Fatalf("ntohs(0xFFFF) = %#04x, want 0xffff", got)
		}
	})

	t.Run("Ntohs_KnownPattern_MatchesExpectedSwap", func(t *testing.T) {
		if got := ntohs(0x0102); got != 0x0201 {
			t.Fatalf("ntohs(0x0102) = %#04x, want 0x0201", got)
		}
	})

	t.Run("Ntohl_ZeroValue_ReturnsZero", func(t *testing.T) {
		if got := ntohl(0); got != 0 {
			t.Fatalf("ntohl(0) = %#08x, want 0x00000000", got)
		}
	})

	t.Run("Ntohl_MaxValue_ReturnsByteSwapped", func(t *testing.T) {
		if got := ntohl(0xFFFFFFFF); got != 0xFFFFFFFF {
			t.Fatalf("ntohl(0xFFFFFFFF) = %#08x, want 0xffffffff", got)
		}
	})

	t.Run("Ntohl_KnownPattern_MatchesExpectedSwap", func(t *testing.T) {
		if got := ntohl(0x01020304); got != 0x04030201 {
			t.Fatalf("ntohl(0x01020304) = %#08x, want 0x04030201", got)
		}
	})

	t.Run("Htons_RoundTrip_MatchesNtohs", func(t *testing.T) {
		for _, v := range []uint16{0, 1, 0x00FF, 0x0102, 0x1234, 15001, 65535} {
			if got := htons(ntohs(v)); got != v {
				t.Errorf("htons(ntohs(%#04x)) = %#04x, want %#04x", v, got, v)
			}
		}
	})

	t.Run("Htonl_RoundTrip_MatchesNtohl", func(t *testing.T) {
		for _, v := range []uint32{0, 1, 0x000000FF, 0x01020304, 0x7F000001, 0xC0000201, 0xFFFFFFFF} {
			if got := htonl(ntohl(v)); got != v {
				t.Errorf("htonl(ntohl(%#08x)) = %#08x, want %#08x", v, got, v)
			}
		}
	})

	t.Run("Ntohs_SingleByteBoundary_SwapsCorrectly", func(t *testing.T) {
		if got := ntohs(0x00FF); got != 0xFF00 {
			t.Fatalf("ntohs(0x00FF) = %#04x, want 0xff00", got)
		}
	})

	t.Run("Ntohl_SingleByteBoundary_SwapsCorrectly", func(t *testing.T) {
		if got := ntohl(0x000000FF); got != 0xFF000000 {
			t.Fatalf("ntohl(0x000000FF) = %#08x, want 0xff000000", got)
		}
	})

	// Spec cases #11 and #12 are named "Idempotent", but the property being
	// asserted is involution (f(f(x)) == x); a byte swap is not idempotent.
	// The spec name is the contract and is kept verbatim (Findings #16).
	t.Run("Ntohs_Idempotent_DoubleApplicationRestoresOriginal", func(t *testing.T) {
		for _, v := range []uint16{0, 1, 0x00FF, 0x0102, 0x1234, 15001, 65535} {
			if got := ntohs(ntohs(v)); got != v {
				t.Errorf("ntohs(ntohs(%#04x)) = %#04x, want %#04x", v, got, v)
			}
		}
	})

	t.Run("Ntohl_Idempotent_DoubleApplicationRestoresOriginal", func(t *testing.T) {
		for _, v := range []uint32{0, 1, 0x000000FF, 0x01020304, 0x7F000001, 0xFFFFFFFF} {
			if got := ntohl(ntohl(v)); got != v {
				t.Errorf("ntohl(ntohl(%#08x)) = %#08x, want %#08x", v, got, v)
			}
		}
	})

	t.Run("Ntohs_TableDriven_MatchesEncodingBinaryBigEndian", func(t *testing.T) {
		rng := rand.New(rand.NewSource(1))
		values := []uint16{0, 53, 443, 15001, 65535}
		for i := 0; i < 32; i++ {
			values = append(values, uint16(rng.Intn(65536)))
		}
		for _, v := range values {
			var b [2]byte
			binary.NativeEndian.PutUint16(b[:], v)
			want := binary.BigEndian.Uint16(b[:])
			if got := ntohs(v); got != want {
				t.Errorf("ntohs(%#04x) = %#04x, want %#04x (encoding/binary BigEndian)", v, got, want)
			}
		}
	})

	t.Run("Ntohl_TableDriven_MatchesEncodingBinaryBigEndian", func(t *testing.T) {
		rng := rand.New(rand.NewSource(2))
		values := []uint32{0, 0x7F000001, 0xC0000201, 0xFFFFFFFF}
		for i := 0; i < 32; i++ {
			values = append(values, rng.Uint32())
		}
		for _, v := range values {
			var b [4]byte
			binary.NativeEndian.PutUint32(b[:], v)
			want := binary.BigEndian.Uint32(b[:])
			if got := ntohl(v); got != want {
				t.Errorf("ntohl(%#08x) = %#08x, want %#08x (encoding/binary BigEndian)", v, got, want)
			}
		}
	})
}

// TestKernelStructLayout covers unit test spec section 4 (#15-#22): the Go
// mirrors of the kernel-facing C structures must match the ABI in design
// section 6.4.1 byte for byte, since a layout disagreement is silent.
func TestKernelStructLayout(t *testing.T) {
	t.Run("BpfSockTupleLayout_SizeOf_MatchesKernelABI", func(t *testing.T) {
		if got := unsafe.Sizeof(bpfSockTuple{}); got != 12 {
			t.Fatalf("unsafe.Sizeof(bpfSockTuple{}) = %d, want 12", got)
		}
	})

	t.Run("AkshPairValueLayout_SizeOf_MatchesKernelABI", func(t *testing.T) {
		if got := unsafe.Sizeof(akshPairValue{}); got != 24 {
			t.Fatalf("unsafe.Sizeof(akshPairValue{}) = %d, want 24", got)
		}
	})

	t.Run("AkshConfigLayout_SizeOf_MatchesKernelABI", func(t *testing.T) {
		if got := unsafe.Sizeof(akshConfig{}); got != 32 {
			t.Fatalf("unsafe.Sizeof(akshConfig{}) = %d, want 32", got)
		}
	})

	t.Run("BpfSockTupleLayout_FieldOffsets_MatchKernelABI", func(t *testing.T) {
		want := map[string]uintptr{"SAddr": 0, "DAddr": 4, "SPort": 8, "DPort": 10}
		assertFieldOffsets(t, reflect.TypeOf(bpfSockTuple{}), want)
	})

	t.Run("AkshPairValueLayout_FieldOffsets_MatchKernelABI", func(t *testing.T) {
		want := map[string]uintptr{"IP": 0, "Port": 4, "Flags": 6, "UID": 8, "Pad": 12, "StampNS": 16}
		assertFieldOffsets(t, reflect.TypeOf(akshPairValue{}), want)
	})

	t.Run("StructDecode_KnownByteSequence_ProducesExpectedFields", func(t *testing.T) {
		raw := []byte{
			0x01, 0x02, 0x03, 0x04, // saddr
			0x05, 0x06, 0x07, 0x08, // daddr
			0x09, 0x0A, // sport
			0x0B, 0x0C, // dport
		}
		var got bpfSockTuple
		if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &got); err != nil {
			t.Fatalf("binary.Read(bpfSockTuple) error = %v, want nil", err)
		}
		want := bpfSockTuple{
			SAddr: binary.NativeEndian.Uint32(raw[0:4]),
			DAddr: binary.NativeEndian.Uint32(raw[4:8]),
			SPort: binary.NativeEndian.Uint16(raw[8:10]),
			DPort: binary.NativeEndian.Uint16(raw[10:12]),
		}
		if got != want {
			t.Fatalf("decoded bpfSockTuple = %+v, want %+v", got, want)
		}
		// The raw bytes are network order, so the host-order port is exactly
		// the big-endian reading of them. Asserting a single value is what
		// makes this case fail if ntohs ever stops swapping.
		wantPort := binary.BigEndian.Uint16(raw[10:12])
		if gotPort := ntohs(got.DPort); gotPort != wantPort {
			t.Fatalf("ntohs(DPort) = %#04x, want %#04x", gotPort, wantPort)
		}
	})

	t.Run("StructLayout_NoImplicitPadding_MatchesPackedSize", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			typ  reflect.Type
		}{
			{"bpfSockTuple", reflect.TypeOf(bpfSockTuple{})},
			{"akshPairValue", reflect.TypeOf(akshPairValue{})},
			{"akshConfig", reflect.TypeOf(akshConfig{})},
		} {
			var sum uintptr
			for i := 0; i < tc.typ.NumField(); i++ {
				sum += tc.typ.Field(i).Type.Size()
			}
			if sum != tc.typ.Size() {
				t.Errorf("%s: sum of field sizes = %d, struct size = %d (implicit padding present)", tc.name, sum, tc.typ.Size())
			}
		}
	})

	t.Run("StructLayout_Alignment_SatisfiesUnsafeAlignOf", func(t *testing.T) {
		if got := unsafe.Alignof(bpfSockTuple{}); got != 4 {
			t.Errorf("unsafe.Alignof(bpfSockTuple{}) = %d, want 4", got)
		}
		if got := unsafe.Alignof(akshPairValue{}); got != 8 {
			t.Errorf("unsafe.Alignof(akshPairValue{}) = %d, want 8", got)
		}
		if got := unsafe.Alignof(akshConfig{}); got != 8 {
			t.Errorf("unsafe.Alignof(akshConfig{}) = %d, want 8", got)
		}
	})
}

// assertFieldOffsets fails the test when any named field is missing from the
// struct type or sits at an offset other than the kernel ABI requires.
func assertFieldOffsets(t *testing.T, typ reflect.Type, want map[string]uintptr) {
	t.Helper()
	for name, offset := range want {
		field, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("%s: field %q is missing", typ.Name(), name)
			continue
		}
		if field.Offset != offset {
			t.Errorf("%s.%s offset = %d, want %d", typ.Name(), name, field.Offset, offset)
		}
	}
}
