package requestpath

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// Validate applies request-level checks after parsing and before pipeline use.
func Validate(req *http.Request, rawHead []byte, _ Handover, _ Options) *Rejection {
	if rejection := ScanRawHead(rawHead); rejection != nil {
		return rejection
	}
	if req == nil || req.URL == nil {
		return malformedRequestRejection(req, "")
	}
	if req.ProtoMajor != 1 || req.ProtoMinor != 1 {
		return unsupportedRequestRejection(req, "")
	}
	if req.Method == http.MethodConnect {
		return unsupportedRequestRejection(req, "")
	}
	if hasUpgradeHeaders(req) {
		return unsupportedRequestRejection(req, "")
	}
	if rejection := validateTarget(req, rawHead); rejection != nil {
		return rejection
	}
	if _, _, err := splitAuthority(req.Host); err != nil {
		return malformedRequestRejection(req, "")
	}
	if rejection := validateFraming(req, rawHead); rejection != nil {
		return rejection
	}
	if rejection := validateExpect(req); rejection != nil {
		return rejection
	}
	if rejection := validateTrailers(req); rejection != nil {
		return rejection
	}
	return nil
}

func validateTarget(req *http.Request, rawHead []byte) *Rejection {
	if req.RequestURI == "*" {
		if req.Method != http.MethodOptions {
			return malformedRequestRejection(req, "")
		}
		req.URL.Path = "/"
		req.URL.RawPath = ""
		return nil
	}

	if req.URL.IsAbs() {
		scheme := strings.ToLower(req.URL.Scheme)
		if scheme != "http" && scheme != "https" {
			return malformedRequestRejection(req, "")
		}

		absoluteHost, absolutePort, err := splitAuthority(req.URL.Host)
		if err != nil {
			return malformedRequestRejection(req, "")
		}
		// http.ReadRequest overwrites req.Host with the absolute-form authority
		// and deletes the Host header, so the wire value has to be recovered from
		// the raw head to detect a request that carries two different authorities.
		rawHost, ok := rawHeadHeaderValue(rawHead, "host")
		if !ok {
			return malformedRequestRejection(req, "")
		}
		headerHost, headerPort, err := splitAuthority(rawHost)
		if err != nil {
			return malformedRequestRejection(req, "")
		}
		if !strings.EqualFold(absoluteHost, headerHost) ||
			effectiveAuthorityPort(scheme, absolutePort) != effectiveAuthorityPort(scheme, headerPort) {
			return malformedRequestRejection(req, "")
		}
		return nil
	}

	if !strings.HasPrefix(req.RequestURI, "/") {
		return malformedRequestRejection(req, "")
	}
	return nil
}

func validateFraming(req *http.Request, rawHead []byte) *Rejection {
	hasContentLength := rawHeadHasHeader(rawHead, "content-length")
	if (hasContentLength || len(req.TransferEncoding) > 0) && bodylessMethod(req.Method) {
		return unsupportedRequestRejection(req, "framing")
	}
	if len(req.TransferEncoding) > 0 {
		if len(req.TransferEncoding) != 1 || strings.ToLower(req.TransferEncoding[0]) != "chunked" {
			return unsupportedRequestRejection(req, "framing")
		}
		if hasContentLength {
			return unsupportedRequestRejection(req, "framing")
		}
		return nil
	}

	if req.ContentLength < 0 {
		return unsupportedRequestRejection(req, "framing")
	}

	return nil
}

func bodylessMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

func validateExpect(req *http.Request) *Rejection {
	values := req.Header.Values("Expect")
	if len(values) == 0 {
		return nil
	}
	if len(values) > 1 {
		return unsupportedRequestRejection(req, "expect")
	}
	if strings.EqualFold(strings.TrimSpace(values[0]), "100-continue") {
		req.Header.Del("Expect")
		return nil
	}
	return unsupportedRequestRejection(req, "expect")
}

func validateTrailers(req *http.Request) *Rejection {
	nominated := connectionNominatedNames(req.Header)
	for _, name := range declaredTrailerNames(req) {
		lower := strings.ToLower(name)
		if deniedTrailerName(lower) || nominated[lower] {
			return unsupportedRequestRejection(req, "trailer")
		}
	}
	return nil
}

func hasUpgradeHeaders(req *http.Request) bool {
	if req.Header.Get("Upgrade") != "" {
		return true
	}
	for _, value := range req.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func splitAuthority(authority string) (string, uint16, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", 0, errBadAuthority
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		host := authority[1 : len(authority)-1]
		if !validAuthorityIPv6Literal(host) {
			return "", 0, errBadAuthority
		}
		return strings.ToLower(host), 0, nil
	}
	if !strings.Contains(authority, ":") {
		if !validAuthorityHost(authority) {
			return "", 0, errBadAuthority
		}
		return strings.ToLower(authority), 0, nil
	}

	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, errBadAuthority
	}
	if host == "" {
		return "", 0, errBadAuthority
	}
	if strings.Contains(host, ":") {
		if !validAuthorityIPv6Literal(host) {
			return "", 0, errBadAuthority
		}
	} else if !validAuthorityHost(host) {
		return "", 0, errBadAuthority
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, errBadAuthority
	}
	return strings.ToLower(host), uint16(port), nil
}

func validAuthorityHost(host string) bool {
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune(".-", r):
		default:
			return false
		}
	}
	return true
}

func validAuthorityIPv6Literal(host string) bool {
	if host == "" {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is6() && addr.Zone() == ""
}

func rawHeadHasHeader(rawHead []byte, name string) bool {
	lower := strings.ToLower(name)
	lines := strings.Split(string(rawHead), "\r\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if strings.EqualFold(line[:colon], lower) {
			return true
		}
	}
	return false
}

func rawHeadHeaderValue(rawHead []byte, name string) (string, bool) {
	lines := strings.Split(string(rawHead), "\r\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if strings.EqualFold(line[:colon], name) {
			return strings.TrimSpace(line[colon+1:]), true
		}
	}
	return "", false
}

// effectiveAuthorityPort resolves an absent port (0) to the scheme default so a
// bare authority and one carrying the default port are not treated as a conflict.
func effectiveAuthorityPort(scheme string, port uint16) uint16 {
	if port != 0 {
		return port
	}
	if scheme == "https" {
		return 443
	}
	return 80
}

func declaredTrailerNames(req *http.Request) []string {
	names := make([]string, 0, len(req.Trailer))
	seen := make(map[string]struct{}, len(req.Trailer))

	for name := range req.Trailer {
		names = append(names, name)
		seen[strings.ToLower(name)] = struct{}{}
	}
	for _, value := range req.Header.Values("Trailer") {
		for _, name := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(name)
			if trimmed == "" {
				continue
			}
			lower := strings.ToLower(trimmed)
			if _, ok := seen[lower]; ok {
				continue
			}
			names = append(names, trimmed)
			seen[lower] = struct{}{}
		}
	}
	return names
}

func connectionNominatedNames(header http.Header) map[string]bool {
	nominated := make(map[string]bool)
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(token)
			if trimmed != "" {
				nominated[strings.ToLower(trimmed)] = true
			}
		}
	}
	return nominated
}

func deniedTrailerName(lower string) bool {
	switch lower {
	case "authorization", "proxy-authorization", "forwarded", "via", "x-real-ip",
		"connection", "keep-alive", "proxy-authenticate", "proxy-connection", "te",
		"transfer-encoding", "upgrade":
		return true
	}
	return strings.HasPrefix(lower, "x-forwarded-") ||
		strings.HasPrefix(lower, "x-envoy-") ||
		strings.HasPrefix(lower, "x-aksh-")
}

func unsupportedRequestRejection(req *http.Request, bound string) *Rejection {
	return &Rejection{
		Class:  ClassT5,
		Reason: pipeline.ReasonUnsupportedProtocol,
		Bound:  bound,
		Wire:   WireWrite400Close,
		Status: 400,
		Method: req.Method,
		Path:   requestPath(req),
	}
}

func malformedRequestRejection(req *http.Request, bound string) *Rejection {
	method := ""
	if req != nil {
		method = req.Method
	}
	return &Rejection{
		Class:  ClassT5,
		Reason: pipeline.ReasonMalformedTarget,
		Bound:  bound,
		Wire:   WireWrite400Close,
		Status: 400,
		Method: method,
		Path:   requestPath(req),
	}
}

func requestPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	if req.URL.RawPath != "" {
		return req.URL.RawPath
	}
	if req.URL.Path != "" {
		return req.URL.Path
	}
	return req.RequestURI
}

var errBadAuthority = strconv.ErrSyntax
