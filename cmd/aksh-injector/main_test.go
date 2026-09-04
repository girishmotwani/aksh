package main

import "testing"

func TestEnvOrDefault(t *testing.T) {
	const key = "AKSH_INJECTOR_TEST_ENVORDEFAULT"
	t.Setenv(key, "")
	if got := envOrDefault(key, "fallback"); got != "fallback" {
		t.Fatalf("empty env: got %q want fallback", got)
	}
	t.Setenv(key, "explicit")
	if got := envOrDefault(key, "fallback"); got != "explicit" {
		t.Fatalf("set env: got %q want explicit", got)
	}
}

func TestEnvBoolOrDefault(t *testing.T) {
	const key = "AKSH_INJECTOR_TEST_ENVBOOL"
	cases := []struct {
		name     string
		value    string
		set      bool
		fallback bool
		want     bool
	}{
		{"unset returns fallback true", "", false, true, true},
		{"unset returns fallback false", "", false, false, false},
		{"true", "true", true, false, true},
		{"false", "false", true, true, false},
		{"1", "1", true, false, true},
		{"0", "0", true, true, false},
		{"unparseable returns fallback", "notabool", true, true, true},
		{"empty string returns fallback", "", true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(key, tc.value)
			} else {
				t.Setenv(key, "")
			}
			if got := envBoolOrDefault(key, tc.fallback); got != tc.want {
				t.Fatalf("envBoolOrDefault(%q, %v) = %v, want %v", tc.value, tc.fallback, got, tc.want)
			}
		})
	}
}
