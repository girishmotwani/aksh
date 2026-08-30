package token_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

// tokenInExportedField holds a Token in an EXPORTED field. fmt can reach the
// value through an exported path, so Token.Format is invoked and redaction
// holds. This is the safe, common composition (S3 §6).
type tokenInExportedField struct {
	Tok token.Token
}

// tokenInUnexportedField holds a Token in an UNEXPORTED field of another
// struct. This is the residue S3 §6 rule 3 forbids: fmt reflects into the
// outer struct's unexported field, descends into Token, and reads its
// unexported secret WITHOUT invoking Token.Format — so the secret leaks. The
// mitigation is the rule (never embed a Token in another struct's unexported
// field), not the type.
type tokenInUnexportedField struct {
	tok token.Token
}

// redactionVerbs covers the fmt verbs a stray log/debug statement is most
// likely to reach for, including %#v which bypasses String() and would print
// raw struct internals absent a Formatter.
var redactionVerbs = []string{"%v", "%+v", "%#v", "%s", "%q"}

// TestToken_NestedInExportedField_Redacted proves the positive guarantee: a
// Token composed into another struct via an exported field never leaks its
// secret under any common fmt verb. This is the case production code is
// expected to use, and it must stay safe.
func TestToken_NestedInExportedField_Redacted(t *testing.T) {
	outer := tokenInExportedField{Tok: token.NewToken(testSecret, time.Now().Add(time.Hour))}
	for _, verb := range redactionVerbs {
		out := fmt.Sprintf(verb, outer)
		if strings.Contains(out, testSecret) {
			t.Errorf("Token in exported field leaked under %s: %s", verb, out)
		}
	}
	// A pointer to the outer struct must be equally safe.
	for _, verb := range redactionVerbs {
		out := fmt.Sprintf(verb, &outer)
		if strings.Contains(out, testSecret) {
			t.Errorf("Token in exported field (via pointer) leaked under %s: %s", verb, out)
		}
	}
}

// TestToken_NestedInUnexportedField_KnownResidue pins the accepted residue of
// S3 §6 rule 3: a Token held in another struct's UNEXPORTED field IS reachable
// by fmt's reflective printer and DOES leak. The test does not assert this is
// desirable — it makes the rule's rationale executable. If a future Go release
// (or a redaction change) ever stops leaking here, this test fails and forces a
// deliberate re-evaluation of whether rule 3 is still required.
func TestToken_NestedInUnexportedField_KnownResidue(t *testing.T) {
	outer := tokenInUnexportedField{tok: token.NewToken(testSecret, time.Now().Add(time.Hour))}
	leaked := false
	for _, verb := range redactionVerbs {
		if strings.Contains(fmt.Sprintf(verb, outer), testSecret) {
			leaked = true
			break
		}
	}
	if !leaked {
		t.Fatal("unexported-field residue no longer leaks under any verb — " +
			"re-evaluate S3 §6 rule 3: the type may now redact where only a rule did before")
	}
}
