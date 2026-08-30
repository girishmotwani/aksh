package requestpath_test

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

func TestValidate_RawHeadScanFailsFirst_ShortCircuitsBeforeLaterChecks(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.example.com\r\nHost: api.example.com:0\r\n\r\n"
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.Host = "api.example.com:0"

	rejection := requestpath.Validate(req, []byte(raw), requestpath.Handover{}, requestpath.DefaultOptions())
	if rejection == nil {
		t.Fatal("Validate() = nil, want rejection")
	}
	if rejection.Reason != pipeline.ReasonUnsupportedProtocol {
		t.Fatalf("Reason = %v, want %v", rejection.Reason, pipeline.ReasonUnsupportedProtocol)
	}
}

func TestValidate_HTTP10_Rejected400(t *testing.T) {
	raw := "GET / HTTP/1.0\r\nHost: api.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
}

func TestValidate_HTTP20_Rejected400(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Host = "api.example.com"
	raw := "GET /path HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
}

func TestValidate_HTTP11_Accepted(t *testing.T) {
	raw := "GET /path HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

func TestValidate_NilRequest_Rejected400WithoutPanic(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Validate() panicked: %v", r)
		}
	}()

	rejection := requestpath.Validate(nil, []byte(raw), requestpath.Handover{}, requestpath.DefaultOptions())
	if rejection == nil {
		t.Fatal("Validate() = nil, want rejection")
	}
	if rejection.Reason != pipeline.ReasonMalformedTarget {
		t.Fatalf("Reason = %v, want %v", rejection.Reason, pipeline.ReasonMalformedTarget)
	}
}

func TestValidate_ConnectMethod_Rejected400WithAuditedMethod(t *testing.T) {
	raw := "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n"
	req := mustReadRequest(t, raw)

	rejection := requestpath.Validate(req, []byte(raw), requestpath.Handover{}, requestpath.DefaultOptions())
	if rejection == nil {
		t.Fatal("Validate() = nil, want rejection")
	}
	if rejection.Reason != pipeline.ReasonUnsupportedProtocol {
		t.Fatalf("Reason = %v, want %v", rejection.Reason, pipeline.ReasonUnsupportedProtocol)
	}
	if rejection.Method != http.MethodConnect {
		t.Fatalf("Method = %q, want %q", rejection.Method, http.MethodConnect)
	}
}

func TestValidate_UpgradeHeaderOrConnectionUpgrade_RejectedBeforeSanitiseStage(t *testing.T) {
	tests := []string{
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: keep-alive, Upgrade\r\n\r\n",
	}
	for _, raw := range tests {
		t.Run(strings.ReplaceAll(raw, "\r\n", "|"), func(t *testing.T) {
			req := mustReadRequest(t, raw)
			assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
		})
	}
}

func TestValidate_UpgradeAbsent_PassesUpgradeCheck(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: keep-alive\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

func TestValidate_OriginFormTarget_Accepted(t *testing.T) {
	raw := "GET /path HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

func TestValidate_AbsoluteFormTarget_Accepted(t *testing.T) {
	raw := "GET https://api.example.com/path HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

// Parsed with the real http.ReadRequest, which for absolute-form overwrites
// req.Host with the request-target authority and deletes the Host header. The
// wire Host must therefore be recovered from the raw head; comparing req.Host
// against req.URL.Host compares the authority with itself and accepts this.
func TestValidate_AbsoluteFormAuthorityConflictsWithHost_Rejected400(t *testing.T) {
	raw := "GET https://api.example.com/path HTTP/1.1\r\nHost: other.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func TestValidate_AbsoluteFormPortConflictsWithHost_Rejected400(t *testing.T) {
	raw := "GET https://api.example.com:8443/path HTTP/1.1\r\nHost: api.example.com:9443\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func TestValidate_AbsoluteFormHostCarriesSchemeDefaultPort_Accepted(t *testing.T) {
	raw := "GET https://api.example.com/path HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

func TestValidate_AbsoluteFormHostDiffersOnlyByCase_Accepted(t *testing.T) {
	raw := "GET https://api.example.com/path HTTP/1.1\r\nHost: API.Example.COM\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

func TestValidate_AsteriskFormOnOptions_AcceptedPathRewrittenToRoot(t *testing.T) {
	raw := "OPTIONS * HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	if rejection := requestpath.Validate(req, []byte(raw), requestpath.Handover{}, requestpath.DefaultOptions()); rejection != nil {
		t.Fatalf("Validate() = %+v, want nil", rejection)
	}
	if req.URL.Path != "/" {
		t.Fatalf("URL.Path = %q, want /", req.URL.Path)
	}
}

func TestValidate_AsteriskFormOnNonOptions_Rejected400(t *testing.T) {
	raw := "GET * HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func TestValidate_SingleValidHost_Accepted(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

func TestValidate_HostBadPort_Rejected400MalformedTarget(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.example.com:notaport\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func TestValidate_HostPortZeroLiteral_Rejected400(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.example.com:0\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func TestValidate_HostPortOutOfRange_Rejected400(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.example.com:70000\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func TestValidate_BracketedIPv6HostWithoutPort_Accepted(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

func TestValidate_BracketedIPv6HostWithPort_Accepted(t *testing.T) {
	tests := []string{
		"GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: [2001:DB8::1]:8443\r\n\r\n",
	}

	for _, raw := range tests {
		t.Run(strings.ReplaceAll(raw, "\r\n", "|"), func(t *testing.T) {
			req := mustReadRequest(t, raw)
			assertValidateAccepted(t, req, raw)
		})
	}
}

func TestValidate_BracketedNonIPLiteralHost_Rejected400(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: [api.example.com]\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func TestValidate_NonBracketedHostWithBracketCharacter_Rejected400(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: exa[mple].com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func TestValidate_ContentLengthAndTransferEncodingTogether_Rejected400(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
	req := mustReadRequest(t, raw)
	req.TransferEncoding = []string{"chunked"}
	assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
}

func TestValidate_NegativeContentLength_Rejected400(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/path", nil)
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.Host = "api.example.com"
	req.ContentLength = -1
	raw := "POST /path HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: -1\r\n\r\n"
	assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
}

func TestValidate_UnknownTransferEncodingValue_Rejected400(t *testing.T) {
	req := mustReadRequest(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	req.TransferEncoding = []string{"identity"}
	raw := "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: identity\r\n\r\n"
	assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
}

func TestValidate_NoFramingHeaders_NoBodyExpected(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateAccepted(t, req, raw)
}

func TestValidate_Expect100ContinueHonoured_PassesCheck(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: api.example.com\r\nExpect: 100-continue\r\n\r\n"
	req := mustReadRequest(t, raw)
	if rejection := requestpath.Validate(req, []byte(raw), requestpath.Handover{}, requestpath.DefaultOptions()); rejection != nil {
		t.Fatalf("Validate() = %+v, want nil", rejection)
	}
	if got := req.Header.Values("Expect"); len(got) != 0 {
		t.Fatalf("Expect header values = %v, want empty", got)
	}
}

func TestValidate_ExpectOtherValue_Rejected400(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: api.example.com\r\nExpect: 200-ok\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
}

func TestValidate_DuplicateExpectHeaders_Rejected400(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: api.example.com\r\nExpect: 100-continue\r\nExpect: 100-continue\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
}

func TestValidate_TrailerDeclaresCredentialOrHopByHopName_Rejected400(t *testing.T) {
	tests := []string{
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\nTrailer: Connection\r\n\r\n",
	}
	for _, raw := range tests {
		t.Run(strings.ReplaceAll(raw, "\r\n", "|"), func(t *testing.T) {
			req := mustReadRequest(t, raw)
			assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
		})
	}
}

func TestValidate_TrailerDeclaresConnectionNominatedName_Rejected400(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: api.example.com\r\nConnection: x-secret\r\nTransfer-Encoding: chunked\r\nTrailer: x-secret\r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonUnsupportedProtocol)
}

func TestValidate_HostEmptyString_Rejected400(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: \r\n\r\n"
	req := mustReadRequest(t, raw)
	assertValidateRejected(t, req, raw, pipeline.ReasonMalformedTarget)
}

func mustReadRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("http.ReadRequest(%q) error = %v", raw, err)
	}
	return req
}

func assertValidateAccepted(t *testing.T, req *http.Request, raw string) {
	t.Helper()
	if rejection := requestpath.Validate(req, []byte(raw), requestpath.Handover{}, requestpath.DefaultOptions()); rejection != nil {
		t.Fatalf("Validate() = %+v, want nil", rejection)
	}
}

func assertValidateRejected(t *testing.T, req *http.Request, raw string, reason pipeline.DenyReason) {
	t.Helper()
	rejection := requestpath.Validate(req, []byte(raw), requestpath.Handover{}, requestpath.DefaultOptions())
	if rejection == nil {
		t.Fatal("Validate() = nil, want rejection")
	}
	if rejection.Class != requestpath.ClassT5 {
		t.Fatalf("Class = %q, want %q", rejection.Class, requestpath.ClassT5)
	}
	if rejection.Reason != reason {
		t.Fatalf("Reason = %v, want %v", rejection.Reason, reason)
	}
	if rejection.Wire != requestpath.WireWrite400Close {
		t.Fatalf("Wire = %d, want %d", rejection.Wire, requestpath.WireWrite400Close)
	}
	if rejection.Status != 400 {
		t.Fatalf("Status = %d, want 400", rejection.Status)
	}
}
