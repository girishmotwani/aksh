package collector

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// makeJWT builds a JWT-shaped token (three base64url segments) from the given
// header and payload maps and an arbitrary signature. It never signs anything;
// the demo only ever decodes for display.
func makeJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	enc := func(v map[string]any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(payload) + "." + base64.RawURLEncoding.EncodeToString([]byte("signature-not-verified"))
}

// A representative Microsoft Entra access token payload (non-secret claims only)
// plus a fixed exp so its RFC3339 rendering is deterministic.
func sampleEntraJWT(t *testing.T) string {
	t.Helper()
	return makeJWT(t,
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": "abc123"},
		map[string]any{
			"iss":   "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
			"aud":   "https://management.azure.com/",
			"exp":   1700000000, // 2023-11-14T22:13:20Z
			"tid":   "72f988bf-86f1-41af-91ab-2d7cd011db47",
			"appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
		},
	)
}

func TestIngestStoresStolenCredential(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	token := sampleEntraJWT(t)
	body, _ := json.Marshal(map[string]any{
		"cluster_id": "prod-tokyo-1", "namespace": "kagent", "pod": "agent-0",
		"stolen_credential": token,
	})
	rr := postDiagnostics(h, string(body), nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
	if store.Count() != 1 {
		t.Fatalf("count = %d, want 1", store.Count())
	}
	e := store.Snapshot()[0]
	if e.StolenCredential != token {
		t.Fatalf("stored credential = %q, want raw token", e.StolenCredential)
	}
	if e.CredentialClaims == nil {
		t.Fatal("credential_claims is nil for a valid JWT")
	}
	c := e.CredentialClaims
	if c.Iss != "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/" {
		t.Fatalf("iss = %q", c.Iss)
	}
	if c.Aud != "https://management.azure.com/" {
		t.Fatalf("aud = %q", c.Aud)
	}
	if c.Exp != "2023-11-14T22:13:20Z" {
		t.Fatalf("exp = %q, want RFC3339 2023-11-14T22:13:20Z", c.Exp)
	}
	if c.Tid != "72f988bf-86f1-41af-91ab-2d7cd011db47" {
		t.Fatalf("tid = %q", c.Tid)
	}
	if c.AppID != "04b07795-8ddb-461a-bbee-02f9e1bf7b46" {
		t.Fatalf("appid = %q", c.AppID)
	}
}

func TestIngestWithoutStolenCredential(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	// The existing valid body carries no stolen_credential; ingest must succeed
	// and store empty credential fields, never crashing on absence.
	rr := postDiagnostics(h, validBody, nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	e := store.Snapshot()[0]
	if e.StolenCredential != "" || e.CredentialClaims != nil {
		t.Fatalf("expected no credential, got %q / %+v", e.StolenCredential, e.CredentialClaims)
	}
}

func TestDecodeJWTClaimsPanicSafeOnGarbage(t *testing.T) {
	garbage := []string{
		"",
		"not-a-jwt",
		"only.two",
		"a.b.c.d",
		"...",
		"!!!.@@@.###",           // not base64url
		"e30.e30",               // only two segments
		"e30.!!!invalid!!!.sig", // payload not base64url
		base64.RawURLEncoding.EncodeToString([]byte("{bad json")) + ".e30.sig",
	}
	for _, g := range garbage {
		if got := decodeJWTClaims(g); got != nil {
			t.Fatalf("decodeJWTClaims(%q) = %+v, want nil", g, got)
		}
	}
	// A payload that is valid base64url JSON but not an object must not panic.
	arr := base64.RawURLEncoding.EncodeToString([]byte("[1,2,3]"))
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	if got := decodeJWTClaims(hdr + "." + arr + ".sig"); got != nil {
		t.Fatalf("non-object payload = %+v, want nil", got)
	}
}

func TestIngestNonJWTCredentialStoredRaw(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	const opaque = "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	body, _ := json.Marshal(map[string]any{
		"cluster_id": "c1", "namespace": "ns", "pod": "p",
		"stolen_credential": opaque,
	})
	rr := postDiagnostics(h, string(body), nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	e := store.Snapshot()[0]
	if e.StolenCredential != opaque {
		t.Fatalf("raw credential = %q, want %q", e.StolenCredential, opaque)
	}
	if e.CredentialClaims != nil {
		t.Fatalf("non-JWT credential decoded claims = %+v, want nil (display raw)", e.CredentialClaims)
	}
}

func TestStolenCredentialBounded(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	// Large body limit so the credential itself, not the body cap, is exercised.
	ingest = NewIngest(store, 1<<20, nil)
	h := ingest.Handler()

	huge := make([]byte, maxStolenCredentialLen+5000)
	for i := range huge {
		huge[i] = 'A'
	}
	body, _ := json.Marshal(map[string]any{
		"cluster_id": "c1", "namespace": "ns", "pod": "p",
		"stolen_credential": string(huge),
	})
	rr := postDiagnostics(h, string(body), nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if got := len(store.Snapshot()[0].StolenCredential); got > maxStolenCredentialLen {
		t.Fatalf("stored credential len = %d, want <= %d", got, maxStolenCredentialLen)
	}
}

func TestInternalEventsExposesCredential(t *testing.T) {
	store := NewStore(10)
	ingest := NewIngest(store, MaxBodyBytes, nil)
	token := sampleEntraJWT(t)
	body, _ := json.Marshal(map[string]any{
		"cluster_id": "c1", "namespace": "ns", "pod": "p",
		"stolen_credential": token,
	})
	if rr := postDiagnostics(ingest.Handler(), string(body), nil); rr.Code != http.StatusAccepted {
		t.Fatalf("ingest status = %d", rr.Code)
	}

	obs := NewObserver(store).Handler()
	rr := httptest.NewRecorder()
	obs.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/internal/events", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("events status = %d", rr.Code)
	}
	var events []struct {
		StolenCredential string            `json:"stolen_credential"`
		CredentialClaims *CredentialClaims `json:"credential_claims"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if events[0].StolenCredential != token {
		t.Fatalf("internal/events stolen_credential = %q", events[0].StolenCredential)
	}
	if events[0].CredentialClaims == nil || events[0].CredentialClaims.AppID == "" {
		t.Fatalf("internal/events missing decoded claims: %+v", events[0].CredentialClaims)
	}

	// A leak still counts as exactly one event.
	rr = httptest.NewRecorder()
	obs.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/internal/count", nil))
	var c struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &c)
	if c.Count != 1 {
		t.Fatalf("count = %d, want 1", c.Count)
	}
}

func TestCredentialJSONEscapesMaliciousValue(t *testing.T) {
	store := NewStore(10)
	ingest := NewIngest(store, MaxBodyBytes, nil)
	const xss = `<script>alert('pwned')</script>`
	body, _ := json.Marshal(map[string]any{
		"cluster_id": "c1", "namespace": "ns", "pod": "p",
		"stolen_credential": xss,
	})
	if rr := postDiagnostics(ingest.Handler(), string(body), nil); rr.Code != http.StatusAccepted {
		t.Fatalf("ingest status = %d", rr.Code)
	}

	obs := NewObserver(store).Handler()
	rr := httptest.NewRecorder()
	obs.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/internal/events", nil))
	// Go's JSON encoder escapes < and > so the raw tag can never appear literally
	// in the served bytes.
	if bytes.Contains(rr.Body.Bytes(), []byte("<script>")) {
		t.Fatalf("served JSON contains an unescaped <script> tag: %s", rr.Body.String())
	}
	// The value must still round-trip as data.
	var events []Event
	if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if events[0].StolenCredential != xss {
		t.Fatalf("credential did not round-trip: %q", events[0].StolenCredential)
	}
}

// TestDashboardRendersCredentialsWithoutInnerHTML is a static guard on the
// client-side dashboard: it must never assign untrusted event data via
// innerHTML. All rendering goes through textContent, which is the XSS-safe path.
func TestDashboardRendersCredentialsWithoutInnerHTML(t *testing.T) {
	if bytes.Contains(dashboardHTML, []byte("innerHTML")) {
		t.Fatal("dashboard uses innerHTML; credential values must be rendered via textContent only")
	}
	for _, want := range []string{"renderLeak", "LEAKED CREDENTIAL", "credential_claims", "stolen_credential"} {
		if !bytes.Contains(dashboardHTML, []byte(want)) {
			t.Fatalf("dashboard HTML missing expected leak-rendering token %q", want)
		}
	}
}
