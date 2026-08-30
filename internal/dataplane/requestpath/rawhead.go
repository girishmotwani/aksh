package requestpath

import (
	"bytes"
	"strings"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// ScanRawHead inspects a raw HTTP/1.1 request head for structural faults.
func ScanRawHead(head []byte) *Rejection {
	if rejection := validateHeadLineEndings(head); rejection != nil {
		return rejection
	}
	if len(head) < 4 || !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
		return unsupportedProtocolRejection()
	}

	requestLineEnd := bytes.Index(head, []byte("\r\n"))
	if requestLineEnd <= 0 {
		return unsupportedProtocolRejection()
	}
	if requestLineEnd > 8192 {
		return malformedTargetRejection()
	}
	if len(bytes.Fields(head[:requestLineEnd])) != 3 {
		return unsupportedProtocolRejection()
	}

	lines := bytes.Split(head[:len(head)-2], []byte("\r\n"))
	hostCount := 0
	contentLengthCount := 0
	transferEncodingCount := 0

	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			return unsupportedProtocolRejection()
		}

		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return unsupportedProtocolRejection()
		}
		if line[colon-1] == ' ' || line[colon-1] == '\t' {
			return unsupportedProtocolRejection()
		}

		name := line[:colon]
		value := line[colon+1:]
		if !validHeaderName(name) || !validHeaderValue(value) {
			return unsupportedProtocolRejection()
		}

		switch lower := strings.ToLower(string(name)); lower {
		case "host":
			hostCount++
		case "content-length":
			contentLengthCount++
			if invalidContentLengthValue(trimContentLengthFieldValue(string(value))) {
				return unsupportedProtocolRejection()
			}
		case "transfer-encoding":
			transferEncodingCount++
			if transferEncodingCount > 1 {
				return unsupportedProtocolRejection()
			}
			if strings.ToLower(strings.TrimSpace(string(value))) != "chunked" {
				return unsupportedProtocolRejection()
			}
		}
	}

	if hostCount == 0 || hostCount > 1 {
		return unsupportedProtocolRejection()
	}
	if contentLengthCount > 1 {
		return unsupportedProtocolRejection()
	}
	if contentLengthCount > 0 && transferEncodingCount > 0 {
		return unsupportedProtocolRejection()
	}
	if transferEncodingCount > 1 {
		return unsupportedProtocolRejection()
	}

	return nil
}

func validateHeadLineEndings(head []byte) *Rejection {
	for i := 0; i < len(head); i++ {
		switch head[i] {
		case '\r':
			if i+1 >= len(head) || head[i+1] != '\n' {
				return unsupportedProtocolRejection()
			}
			i++
		case '\n':
			if i == 0 || head[i-1] != '\r' {
				return unsupportedProtocolRejection()
			}
		}
	}
	return nil
}

func validHeaderName(name []byte) bool {
	for _, b := range name {
		if !isTChar(b) {
			return false
		}
	}
	return true
}

func validHeaderValue(value []byte) bool {
	for _, b := range value {
		if b == '\t' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func invalidContentLengthValue(raw string) bool {
	trimmed := strings.Trim(raw, " \t")
	if raw != trimmed {
		return true
	}
	if trimmed == "" {
		return true
	}
	if strings.HasPrefix(trimmed, "+") {
		return true
	}
	if !allDigits(trimmed) {
		return true
	}
	return len(trimmed) > 1 && trimmed[0] == '0'
}

func trimContentLengthFieldValue(raw string) string {
	if raw == "" {
		return raw
	}
	if raw[0] == ' ' || raw[0] == '\t' {
		return raw[1:]
	}
	return raw
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isTChar(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	}

	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func unsupportedProtocolRejection() *Rejection {
	return &Rejection{
		Class:  ClassT5,
		Reason: pipeline.ReasonUnsupportedProtocol,
		Wire:   WireWrite400Close,
		Status: 400,
	}
}

func malformedTargetRejection() *Rejection {
	return &Rejection{
		Class:  ClassT5,
		Reason: pipeline.ReasonMalformedTarget,
		Wire:   WireWrite400Close,
		Status: 400,
	}
}
