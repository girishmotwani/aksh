//go:build linux

package bpf

import (
	"sort"
	"testing"
	"unsafe"
)

func TestGeneratedOrigDstStruct_SizeIs24Bytes_FieldsAtDesignOffsets(t *testing.T) {
	var got AkshbpfOrigDst

	if size := unsafe.Sizeof(got); size != 24 {
		t.Fatalf("unsafe.Sizeof(AkshbpfOrigDst{}) = %d, want 24", size)
	}

	offsets := map[string]uintptr{
		"Ip":      unsafe.Offsetof(got.Ip),
		"Port":    unsafe.Offsetof(got.Port),
		"Flags":   unsafe.Offsetof(got.Flags),
		"Uid":     unsafe.Offsetof(got.Uid),
		"Pad":     unsafe.Offsetof(got.Pad),
		"StampNs": unsafe.Offsetof(got.StampNs),
	}
	want := map[string]uintptr{
		"Ip":      0,
		"Port":    4,
		"Flags":   6,
		"Uid":     8,
		"Pad":     12,
		"StampNs": 16,
	}

	for field, wantOffset := range want {
		if gotOffset := offsets[field]; gotOffset != wantOffset {
			t.Fatalf("Offsetof(%s) = %d, want %d", field, gotOffset, wantOffset)
		}
	}
}

func TestGeneratedPairKeyStruct_SizeIs8Bytes_PortAtOffset4(t *testing.T) {
	var got AkshbpfPairKey

	if size := unsafe.Sizeof(got); size != 8 {
		t.Fatalf("unsafe.Sizeof(AkshbpfPairKey{}) = %d, want 8", size)
	}

	if offset := unsafe.Offsetof(got.Port); offset != 4 {
		t.Fatalf("Offsetof(Port) = %d, want 4", offset)
	}
}

func TestGeneratedAkshCfgStruct_SizeIs32Bytes_ReservedFieldAtOffset24(t *testing.T) {
	var got AkshbpfAkshCfg

	if size := unsafe.Sizeof(got); size != 32 {
		t.Fatalf("unsafe.Sizeof(AkshbpfAkshCfg{}) = %d, want 32", size)
	}

	if offset := unsafe.Offsetof(got.Reserved); offset != 24 {
		t.Fatalf("Offsetof(Reserved) = %d, want 24", offset)
	}
}

func TestGeneratedMapNames_MatchDesignTable_AkshConfigBypassCidr4CookieOrigDstPairOrigDst(t *testing.T) {
	spec, err := LoadAkshbpf()
	if err != nil {
		t.Fatalf("LoadAkshbpf() error = %v", err)
	}

	var names []string
	for name := range spec.Maps {
		names = append(names, name)
	}
	sort.Strings(names)

	want := []string{"aksh_config", "bypass_cidr4", "cookie_orig_dst", "pair_orig_dst"}
	if len(names) != len(want) {
		t.Fatalf("map name count = %d (%v), want %d (%v)", len(names), names, len(want), want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("map names = %v, want %v", names, want)
		}
	}
}

func TestGeneratedProgramNames_MatchDesignTable_AllSixFunctionNamesPresent(t *testing.T) {
	spec, err := LoadAkshbpf()
	if err != nil {
		t.Fatalf("LoadAkshbpf() error = %v", err)
	}

	var names []string
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)

	want := []string{
		"aksh_connect4",
		"aksh_connect6_deny",
		"aksh_sendmsg4",
		"aksh_sendmsg6",
		"aksh_sock_create",
		"aksh_sockops",
	}
	if len(names) != len(want) {
		t.Fatalf("program name count = %d (%v), want %d (%v)", len(names), names, len(want), want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("program names = %v, want %v", names, want)
		}
	}
}
