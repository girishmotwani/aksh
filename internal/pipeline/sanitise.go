package pipeline

import (
	"fmt"
	"net/http"
	"strings"
)

// hopByHop lists standard hop-by-hop headers per RFC 2616 §13.5.1
// that must not be forwarded by a proxy.
var hopByHop = map[string]bool{
	"connection":         true,
	"keep-alive":         true,
	"proxy-authenticate": true,
	"proxy-connection":   true,
	"te":                 true,
	"transfer-encoding":  true,
	"upgrade":            true,
}

type SanitiseStage struct{}

func (s *SanitiseStage) Name() string { return "sanitise" }

func (s *SanitiseStage) Execute(rc *RequestContext) Decision {
	if rc == nil || rc.Request == nil {
		return DenyFault(ReasonInternal, fmt.Errorf("request context missing request"))
	}

	// Read nominations before deleting Connection itself; otherwise an agent
	// could hide a hop-by-hop header from the removal pass.
	nominated := connectionNominated(rc.Request.Header)

	for key := range rc.Request.Header {
		lower := strings.ToLower(key)
		if shouldStrip(lower) || hopByHop[lower] || nominated[lower] {
			delete(rc.Request.Header, key)
		}
	}

	// Apply the same credential boundary to trailers already declared or
	// materialised on the request; headers and trailers are equivalent upstream.
	for key := range rc.Request.Trailer {
		lower := strings.ToLower(key)
		if shouldStrip(lower) {
			delete(rc.Request.Trailer, key)
		}
	}

	return Allow()
}

func shouldStrip(lower string) bool {
	// Remove both credentials and forgeable proxy provenance. The upstream
	// must see only identity established by Aksh, never claims from the agent.
	switch lower {
	case "authorization", "proxy-authorization",
		"forwarded", "via", "x-real-ip":
		return true
	}
	return strings.HasPrefix(lower, "x-forwarded-") ||
		strings.HasPrefix(lower, "x-envoy-") ||
		strings.HasPrefix(lower, "x-aksh-")
}

// connectionNominated parses the Connection header and returns the
// lowercased set of header names nominated for hop-by-hop removal.
func connectionNominated(h http.Header) map[string]bool {
	vals := h.Values("Connection")
	if len(vals) == 0 {
		return nil
	}
	nominated := make(map[string]bool, len(vals))
	for _, v := range vals {
		for _, name := range strings.Split(v, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				nominated[strings.ToLower(name)] = true
			}
		}
	}
	return nominated
}
