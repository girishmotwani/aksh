package pipeline

import (
	"errors"
	"net/http"
	"testing"

	"github.com/girishmotwani/aksh/internal/policy"
)

func TestIdentityStage_SNIHostMatchPopulatesFacts(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://Example.COM/a/../b?x=1", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "API.Example.com",
			AuthorityHost:   "api.example.COM",
			DestinationPort: 8443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	if got := rc.Facts.Identity; got != "api.example.com" {
		t.Fatalf("Facts.Identity = %q, want api.example.com", got)
	}
	if got := rc.Facts.Method; got != http.MethodPost {
		t.Fatalf("Facts.Method = %q, want %q", got, http.MethodPost)
	}
	if got := rc.Facts.Path; got != "/b" {
		t.Fatalf("Facts.Path = %q, want /b", got)
	}
	if got := rc.Facts.Port; got != 8443 {
		t.Fatalf("Facts.Port = %d, want 8443", got)
	}
	if got := rc.Facts.Transport; got != policy.TransportTLS {
		t.Fatalf("Facts.Transport = %q, want %q", got, policy.TransportTLS)
	}
	if got := req.Host; got != "api.example.com" {
		t.Fatalf("Request.Host = %q, want api.example.com", got)
	}
}

func TestSNIHostMismatchDenied(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:           "api.example.com",
			AuthorityHost: "other.example.com",
		},
	}

	decision := (&IdentityStage{}).Execute(rc)

	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if decision.Reason != ReasonIdentityMismatch {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonIdentityMismatch)
	}
}

func TestIdentityStage_MalformedPathDenies(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.URL.Path = "/bad\\path"
	req.URL.RawPath = "/bad\\path"

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:           "example.com",
			AuthorityHost: "example.com",
		},
	}

	decision := (&IdentityStage{}).Execute(rc)

	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if decision.Reason != ReasonMalformedTarget {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonMalformedTarget)
	}
}

func TestIdentityStage_EmptySNIAndHostDenies(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/path", nil)
	rc := &RequestContext{
		Request:  req,
		Identity: IdentityInput{},
	}
	decision := (&IdentityStage{}).Execute(rc)
	if decision.Disposition() != DispositionDeny {
		t.Fatalf("got %v, want deny for empty SNI+Host", decision.Disposition())
	}
}

func TestIdentityStage_SNIOnlyUsesIdentity(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			DestinationPort: 443,
		},
	}
	decision := (&IdentityStage{}).Execute(rc)
	if !decision.IsAllow() {
		t.Fatalf("got %v, want allow", decision.Disposition())
	}
	if rc.Facts.Identity != "api.example.com" {
		t.Fatalf("Identity = %q, want api.example.com", rc.Facts.Identity)
	}
}

func TestIdentityStage_HostOnlyUsesIdentity(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://api.example.com/path", nil)
	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			AuthorityHost:   "api.example.com",
			DestinationPort: 80,
		},
	}
	decision := (&IdentityStage{}).Execute(rc)
	if !decision.IsAllow() {
		t.Fatalf("got %v, want allow", decision.Disposition())
	}
	if rc.Facts.Identity != "api.example.com" {
		t.Fatalf("Identity = %q, want api.example.com", rc.Facts.Identity)
	}
	if rc.Facts.Transport != policy.TransportPlaintext {
		t.Fatalf("Transport = %q, want plaintext", rc.Facts.Transport)
	}
}

func TestIdentityStage_CanonicalPathForwarded(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/a/../b", nil)
	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:           "example.com",
			AuthorityHost: "example.com",
		},
	}
	(&IdentityStage{}).Execute(rc)
	if req.URL.Path != "/b" {
		t.Fatalf("URL.Path = %q, want /b", req.URL.Path)
	}
}

func TestIdentityStage_EncodedPathRoundTrips(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/a/%2F/b", nil)
	req.URL.RawPath = "/a/%2F/b"
	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:           "example.com",
			AuthorityHost: "example.com",
		},
	}
	(&IdentityStage{}).Execute(rc)
	if req.URL.RawPath != "/a/%2F/b" {
		t.Fatalf("URL.RawPath = %q, want /a/%%2F/b", req.URL.RawPath)
	}
	if got := req.URL.EscapedPath(); got != "/a/%2F/b" {
		t.Fatalf("EscapedPath() = %q, want /a/%%2F/b", got)
	}
}

func TestAuthorityPortAbsentAllowed(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			AuthorityPort:   0,
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
}

func TestAuthorityPortEqualAllowed(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			AuthorityPort:   443,
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
}

func TestIdentityStage_ZeroPaddedHostPortDenied(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	req.Host = "api.example.com:00"
	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if decision.Reason != ReasonMalformedTarget {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonMalformedTarget)
	}
}

func TestIdentityStage_EmptyHostZeroPortDenied(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	req.Host = ":0"
	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if decision.Reason != ReasonMalformedTarget {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonMalformedTarget)
	}
}

func TestAuthorityPortMismatchDenied(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			AuthorityPort:   8080,
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if decision.Reason != ReasonIdentityMismatch {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonIdentityMismatch)
	}
}

func TestAuthorityPortFromAbsoluteForm(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com:8443/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			AuthorityPort:   8443,
			DestinationPort: 8443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
}

func TestAuthorityPortZeroLiteralRejected(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Host = "api.example.com:0"

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			AuthorityPort:   0,
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if decision.Reason != ReasonMalformedTarget {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonMalformedTarget)
	}
}

func TestAuthorityPortParsedFromHostHeaderMustMatchDestination(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Host = "api.example.com:8443"

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			AuthorityPort:   0,
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if decision.Reason != ReasonIdentityMismatch {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonIdentityMismatch)
	}
}

func TestAuthorityPortParsedFromHostHeaderMatchingDestinationAllowed(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Host = "api.example.com:8443"

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			AuthorityPort:   8443,
			DestinationPort: 8443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	if got := rc.Facts.Port; got != 8443 {
		t.Fatalf("Facts.Port = %d, want 8443", got)
	}
}

func TestAuthorityPortFromRequestHost(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		wantPort    uint16
		wantPresent bool
		wantErr     bool
	}{
		{name: "empty", host: "", wantPresent: false},
		{name: "host only", host: "api.example.com", wantPresent: false},
		{name: "host port", host: "api.example.com:8443", wantPort: 8443, wantPresent: true},
		{name: "bracketed ipv6 no port", host: "[2001:db8::1]", wantPresent: false},
		{name: "malformed host port syntax", host: "api.example.com:8443:extra", wantPresent: true, wantErr: true},
		{name: "zero port", host: "api.example.com:0", wantPresent: true, wantErr: true},
		{name: "unclosed ipv6 bracket", host: "[::1", wantPresent: false},
		{name: "bare ipv6 no brackets", host: "2001:db8::1", wantPresent: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPort, gotPresent, err := authorityPortFromRequestHost(tt.host)
			if tt.wantErr {
				if err == nil {
					t.Fatal("authorityPortFromRequestHost() error = nil, want error")
				}
			} else if err != nil {
				t.Fatalf("authorityPortFromRequestHost() error = %v, want nil", err)
			}
			if gotPort != tt.wantPort {
				t.Fatalf("authorityPortFromRequestHost() port = %d, want %d", gotPort, tt.wantPort)
			}
			if gotPresent != tt.wantPresent {
				t.Fatalf("authorityPortFromRequestHost() present = %v, want %v", gotPresent, tt.wantPresent)
			}
			if tt.wantErr && !errors.Is(err, errMalformedHostPort) {
				t.Fatalf("authorityPortFromRequestHost() error = %v, want %v", err, errMalformedHostPort)
			}
		})
	}
}

func TestIdentityStage_NegativeHostPortRejected(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Host = "api.example.com:-1"

	rc := &RequestContext{
		Request: req,
		Identity: IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}

	decision := (&IdentityStage{}).Execute(rc)
	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if decision.Reason != ReasonMalformedTarget {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonMalformedTarget)
	}
}
