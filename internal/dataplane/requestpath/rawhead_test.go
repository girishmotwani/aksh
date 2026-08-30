package requestpath_test

import (
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

func TestScanRawHead_ValidHead_ReturnsNil(t *testing.T) {
	head := "GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n"
	if got := requestpath.ScanRawHead([]byte(head)); got != nil {
		t.Fatalf("ScanRawHead() = %+v, want nil", got)
	}
}

func TestScanRawHead_DuplicateHost_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_AbsentHost_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_BareCRInHeaderValue_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Test: abc\rdef\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_BareLFLineTerminator_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\nX-Test: value\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_ObsFoldContinuationLine_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Test: value\r\n folded\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_WhitespaceBeforeColon_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding : chunked\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_ControlByteInFieldName_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nBad\x00Name: value\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_ControlByteInFieldValue_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Test: value\x00x\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_NonTokenCharacterInFieldName_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nBad(Name): value\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_DuplicateContentLengthSameValue_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_DuplicateContentLengthDifferentValues_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_MultipleTransferEncodingLines_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_ContentLengthEmptyOrNonNumeric_ReturnsT5Rejection(t *testing.T) {
	tests := []string{
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length:\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: abc\r\n\r\n",
	}

	for _, head := range tests {
		t.Run(strings.ReplaceAll(head, "\r\n", "|"), func(t *testing.T) {
			assertRawHeadRejection(t, head, requestpath.ClassT5, pipeline.ReasonUnsupportedProtocol)
		})
	}
}

func TestScanRawHead_ContentLengthLeadingZerosOrPlusOrPadding_ReturnsT5Rejection(t *testing.T) {
	tests := []string{
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0100\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: +5\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length:  5\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5 \r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length:5 \r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length:5  \r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length:  5  \r\n\r\n",
	}

	for _, head := range tests {
		t.Run(strings.ReplaceAll(head, "\r\n", "|"), func(t *testing.T) {
			assertRawHeadRejection(t, head, requestpath.ClassT5, pipeline.ReasonUnsupportedProtocol)
		})
	}
}

func TestScanRawHead_ContentLengthSingleSpaceAccepted(t *testing.T) {
	head := "GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\n\r\n"
	if got := requestpath.ScanRawHead([]byte(head)); got != nil {
		t.Fatalf("ScanRawHead() = %+v, want nil", got)
	}
}

func TestScanRawHead_ContentLengthWithoutPadding_Accepted(t *testing.T) {
	head := "GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length:5\r\n\r\n"
	if got := requestpath.ScanRawHead([]byte(head)); got != nil {
		t.Fatalf("ScanRawHead() = %+v, want nil", got)
	}
}

func TestScanRawHead_RequestLineOver8192Bytes_ReturnsMalformedTargetRejection(t *testing.T) {
	head := "GET /" + strings.Repeat("a", 8200) + " HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	assertRawHeadRejection(t, head, requestpath.ClassT5, pipeline.ReasonMalformedTarget)
}

func TestScanRawHead_ContentLengthAndTransferEncodingTogether_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_UnterminatedHead_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"GET / HTTP/1.1\r\nHost: api.example.com\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func TestScanRawHead_RequestLineWithoutMethodTargetAndVersion_ReturnsT5Rejection(t *testing.T) {
	assertRawHeadRejection(t,
		"Host:  \r\nHost:\r\n\r\n",
		requestpath.ClassT5,
		pipeline.ReasonUnsupportedProtocol,
	)
}

func assertRawHeadRejection(t *testing.T, head string, class requestpath.RejectClass, reason pipeline.DenyReason) {
	t.Helper()

	rejection := requestpath.ScanRawHead([]byte(head))
	if rejection == nil {
		t.Fatal("ScanRawHead() = nil, want rejection")
	}
	if rejection.Class != class {
		t.Fatalf("Class = %q, want %q", rejection.Class, class)
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
