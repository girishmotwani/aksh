package pipeline

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/girishmotwani/aksh/internal/policy"
)

type IdentityStage struct{}

func (s *IdentityStage) Name() string { return "identity" }

var errMalformedHostPort = errors.New("host port must be between 1 and 65535")

func (s *IdentityStage) Execute(rc *RequestContext) Decision {
	if rc == nil || rc.Request == nil || rc.Request.URL == nil {
		return DenyFault(ReasonInternal, fmt.Errorf("request context missing request"))
	}

	sni := strings.ToLower(rc.Identity.SNI)
	host := strings.ToLower(rc.Identity.AuthorityHost)

	// Policy must never infer an identity solely from the dialled IP: the
	// hostname is the authenticated and operator-configured policy key.
	if sni == "" && host == "" {
		return Deny(ReasonIdentityMismatch, fmt.Errorf("no SNI or Host identity"))
	}

	// Requiring both agent-controlled protocol identities to agree prevents
	// policy from authorising one host while the request names another.
	if sni != "" && host != "" && sni != host {
		return Deny(ReasonIdentityMismatch, nil)
	}

	parsedAuthorityPort, hasParsedAuthorityPort, err := authorityPortFromRequestHost(rc.Request.Host)
	if err != nil {
		return Deny(ReasonMalformedTarget, err)
	}

	authorityPort := rc.Identity.AuthorityPort
	if hasParsedAuthorityPort {
		if authorityPort != 0 && authorityPort != parsedAuthorityPort {
			return Deny(ReasonIdentityMismatch, nil)
		}
		authorityPort = parsedAuthorityPort
	}
	if authorityPort != 0 && authorityPort != rc.Identity.DestinationPort {
		return Deny(ReasonIdentityMismatch, nil)
	}

	// Use whichever is available; prefer SNI.
	identity := sni
	if identity == "" {
		identity = host
	}

	// Match the encoded path when available so encoded separators cannot be
	// decoded differently by policy and the upstream.
	rawPath := rc.Request.URL.RawPath
	if rawPath == "" {
		rawPath = rc.Request.URL.Path
	}
	if rawPath == "" {
		rawPath = "/"
	}

	path, err := policy.CanonicalizePath(rawPath)
	if err != nil {
		return Deny(ReasonMalformedTarget, err)
	}

	// Keep the canonical form in RawPath for policy/transport agreement while
	// satisfying net/url's requirement that Path contain the decoded form.
	rc.Request.URL.RawPath = path
	decoded, decErr := url.PathUnescape(path)
	if decErr != nil {
		decoded = path
	}
	rc.Request.URL.Path = decoded

	transport := rc.Transport
	if transport == "" {
		// SNI is available only for intercepted TLS. Host-only requests are
		// treated as plaintext unless the trusted transport layer said otherwise.
		if sni != "" {
			transport = policy.TransportTLS
		} else {
			transport = policy.TransportPlaintext
		}
	}

	// Replace the untrusted authority with the identity policy actually matched.
	rc.Request.Host = identity
	rc.Facts = policy.RequestFacts{
		Identity:  identity,
		Method:    rc.Request.Method,
		Path:      path,
		Port:      rc.Identity.DestinationPort,
		Transport: transport,
	}
	rc.Transport = transport

	return Allow()
}

func authorityPortFromRequestHost(host string) (uint16, bool, error) {
	if !authorityHasPortSyntax(host) {
		return 0, false, nil
	}

	parsedHost, parsedPort, err := net.SplitHostPort(host)
	if err != nil {
		return 0, true, errMalformedHostPort
	}

	portNum, pErr := strconv.Atoi(parsedPort)
	if parsedHost == "" || pErr != nil || portNum <= 0 || portNum > 65535 {
		return 0, true, errMalformedHostPort
	}
	return uint16(portNum), true, nil
}

func authorityHasPortSyntax(host string) bool {
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "[") {
		closing := strings.LastIndex(host, "]")
		if closing < 0 {
			return false
		}
		return closing+1 < len(host) && host[closing+1] == ':'
	}
	if !strings.Contains(host, ":") {
		return false
	}
	// A bare (non-bracketed) IPv6 literal contains colons but is not
	// host:port syntax; RFC 3986 requires brackets for that case.
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	return true
}
