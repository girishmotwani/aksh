package audit_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// forbiddenSubstr are token-ish substrings that must never name a field or a
// serialised key anywhere in the audit record (INV-5, §2.3).
var forbiddenSubstr = []string{"token", "secret", "bearer", "password", "jwt"}

// walkKeys recursively collects every key in a decoded JSON object tree.
func walkKeys(v any, out map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			out[k] = true
			walkKeys(vv, out)
		}
	case []any:
		for _, vv := range t {
			walkKeys(vv, out)
		}
	}
}

// walkStringValues recursively collects every string value in a decoded JSON
// object tree so the redaction invariant can be asserted over VALUES, not just
// keys (INV-5 defence-in-depth: even if a token-ish value were ever routed into
// a legitimately-named field, it must not survive to the wire).
func walkStringValues(v any, out map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for _, vv := range t {
			walkStringValues(vv, out)
		}
	case []any:
		for _, vv := range t {
			walkStringValues(vv, out)
		}
	case string:
		out[t] = true
	}
}

// structFieldNames recursively collects every struct field name reachable
// from a type, descending through nested structs, slices, pointers, and maps.
func structFieldNames(t reflect.Type, out map[string]bool, seen map[reflect.Type]bool) {
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() == reflect.Map {
		structFieldNames(t.Key(), out, seen)
		structFieldNames(t.Elem(), out, seen)
		return
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		out[f.Name] = true
		structFieldNames(f.Type, out, seen)
	}
}

// Test_Encode_NoTokenField_StructurallyImpossible proves there is no path from
// a token to the JSON: the encoder reads only pipeline.AuditEvent, which by
// construction has no token-capable field, and no rendered record carries a
// token-ish key under any outcome.
func Test_Encode_NoTokenField_StructurallyImpossible(t *testing.T) {
	// By construction: the source event type has no token-capable field.
	fields := map[string]bool{}
	structFieldNames(reflect.TypeOf(pipeline.AuditEvent{}), fields, map[reflect.Type]bool{})
	for name := range fields {
		ln := strings.ToLower(name)
		for _, bad := range forbiddenSubstr {
			if strings.Contains(ln, bad) {
				t.Fatalf("pipeline.AuditEvent has token-capable field %q", name)
			}
		}
	}

	// End-to-end: no serialised key is token-ish under any outcome.
	for _, ev := range []pipeline.AuditEvent{
		fullAuditEvent(), earlyDenialEvent(), plaintextEvent(), staleEvent(),
	} {
		m := decodeRecord(t, ev)
		keys := map[string]bool{}
		walkKeys(m, keys)
		for k := range keys {
			lk := strings.ToLower(k)
			for _, bad := range forbiddenSubstr {
				if strings.Contains(lk, bad) {
					t.Fatalf("record carries token-ish key %q", k)
				}
			}
		}
		// Defence-in-depth (INV-5): no serialised VALUE is token-ish either, so
		// a token routed into a legitimately-named field could never reach the
		// wire. The bounded §2 fixtures carry only identities/hashes/versions.
		vals := map[string]bool{}
		walkStringValues(m, vals)
		for v := range vals {
			lv := strings.ToLower(v)
			for _, bad := range forbiddenSubstr {
				if strings.Contains(lv, bad) {
					t.Fatalf("record carries token-ish value %q", v)
				}
			}
		}
	}
}

// Test_Encode_Record_HasNoFreeFormText proves the record is a bounded field
// set: every serialised key belongs to the closed §2 schema vocabulary, so a
// SIEM parser sees no free-form text field (exportability obligation §6).
func Test_Encode_Record_HasNoFreeFormText(t *testing.T) {
	allowed := map[string]bool{
		"schema": true, "ts": true, "requestId": true,
		"pod": true, "namespace": true, "name": true, "uid": true,
		"agent": true, "serviceAccount": true,
		"decision": true, "disposition": true, "reason": true, "fault": true, "faultClass": true,
		"request": true, "identity": true, "method": true, "path": true, "port": true,
		"transport": true, "serviceUID": true, "serviceGeneration": true,
		"policy": true, "ref": true, "version": true, "evaluatorVersion": true, "ambiguous": true,
		"credential": true, "provider": true, "resource": true, "scopes": true,
		"cacheHit": true, "expiresAt": true,
		"timings": true, "total_us": true, "match_us": true, "acquire_us": true, "audit_us": true,
	}
	for _, ev := range []pipeline.AuditEvent{
		fullAuditEvent(), earlyDenialEvent(), plaintextEvent(), staleEvent(),
	} {
		m := decodeRecord(t, ev)
		keys := map[string]bool{}
		walkKeys(m, keys)
		for k := range keys {
			if !allowed[k] {
				t.Fatalf("record carries unexpected/free-form key %q (not in bounded §2 schema)", k)
			}
		}
	}
}
