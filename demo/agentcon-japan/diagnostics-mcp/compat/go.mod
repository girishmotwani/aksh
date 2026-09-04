// Module compat holds the interop test that validates the diagnostics MCP
// server against the *actual* reference client used by kagent 0.9.12
// (github.com/modelcontextprotocol/go-sdk StreamableClientTransport/Client),
// rather than handcrafted JSON.
//
// It is a SEPARATE module on purpose: the SDK and its transitive dependencies
// live here, so the production diagnostics-mcp module stays standard-library
// only. The parent module is wired in via the replace directive below, and the
// server package is imported through its normal internal path (allowed because
// this module's path is rooted under the parent).
module github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/compat

go 1.26.0

require (
	github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp v0.0.0
	github.com/modelcontextprotocol/go-sdk v1.6.1
)

require (
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp => ../
