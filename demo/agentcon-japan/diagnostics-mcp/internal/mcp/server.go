// Package mcp implements a minimal MCP server over the Streamable HTTP
// transport, compatible with a kagent 0.9.12 RemoteMCPServer configured with
// transport STREAMABLE_HTTP and a URL ending in /mcp.
//
// It intentionally implements only what this demo needs: initialize,
// notifications/initialized, ping, tools/list and tools/call for the single
// send_cluster_diagnostics tool. Requests arrive as JSON-RPC 2.0 over HTTP
// POST and are answered with a single application/json JSON-RPC response
// (Streamable HTTP permits this without opening an SSE stream). A GET is
// answered 405 (with an Allow header) because this server exposes no
// server-initiated SSE stream; a spec-compliant client treats that as "no
// standalone stream" and proceeds.
//
// Two behaviours matter for interop with the reference client
// (github.com/modelcontextprotocol/go-sdk StreamableClientTransport, as used by
// kagent 0.9.12), and both are covered by the compat module test:
//
//   - Protocol version is NEGOTIATED, not hardcoded: the server echoes the
//     client's requested protocolVersion when it supports it, else returns its
//     preferred version. The reference client rejects any returned version it
//     does not recognise.
//   - The Mcp-Session-Id is assigned ONCE, on the initialize response, and is
//     never re-sent (let alone rotated) on later responses. The reference
//     client fails the whole session with "mismatching session IDs" if a later
//     response carries a different id than the one from initialize.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
)

// ProtocolVersion is the MCP revision this server prefers when the client's
// requested version is not one it supports.
const ProtocolVersion = "2025-06-18"

// supportedProtocolVersions are the revisions this server will echo back if the
// client asks for one of them. It spans the versions kagent 0.9.12 and the
// reference SDK may initialize with (2024-11-05 in the SDK's own tests through
// the current 2025-06-18).
var supportedProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// negotiateProtocolVersion echoes the client's requested version when supported,
// otherwise falls back to the preferred ProtocolVersion. The returned value is
// always one the reference client recognises.
func negotiateProtocolVersion(requested string) string {
	if slices.Contains(supportedProtocolVersions, requested) {
		return requested
	}
	return ProtocolVersion
}

const maxRequestBytes = 1 << 20 // 1 MiB of JSON-RPC is plenty for this demo.

// Tool is the executor the server calls for tools/call. Returning isError=true
// still yields a normal JSON-RPC result whose content flags the tool error, as
// the MCP spec requires (tool errors are not protocol errors).
type Tool interface {
	Execute(ctx context.Context, endpoint string) (text string, isError bool)
}

// ToolDef binds a tool's advertised name and description to its executor. Every
// tool in this demo takes the same single "endpoint" argument (the user-supplied
// destination URL), so the input schema is shared.
type ToolDef struct {
	Name        string
	Description string
	Tool        Tool
}

// Server is an http.Handler serving the MCP endpoint.
type Server struct {
	order []string
	tools map[string]ToolDef
}

// NewServer returns a Server backed by the given tools, advertised in the order
// provided. Duplicate names are ignored after the first.
func NewServer(defs ...ToolDef) *Server {
	s := &Server{tools: make(map[string]ToolDef, len(defs))}
	for _, d := range defs {
		if d.Name == "" || d.Tool == nil {
			continue
		}
		if _, dup := s.tools[d.Name]; dup {
			continue
		}
		s.order = append(s.order, d.Name)
		s.tools[d.Name] = d
	}
	return s
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// ServeHTTP dispatches the Streamable HTTP transport.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodGet:
		// No server-initiated SSE stream in this minimal server.
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "this MCP endpoint has no server-initiated stream", http.StatusMethodNotAllowed)
	case http.MethodDelete:
		// Session teardown: nothing stateful to release.
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		writeError(w, nil, -32700, "read error")
		return
	}
	if int64(len(body)) > maxRequestBytes {
		writeError(w, nil, -32600, "request too large")
		return
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		// Batching is not used by kagent 0.9.12; reject clearly rather than
		// half-implement it.
		writeError(w, nil, -32600, "batched requests are not supported")
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, nil, -32700, "parse error")
		return
	}

	// A message with no id is a notification: acknowledge with 202 and no body.
	isNotification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		s.handleInitialize(w, req)
	case "notifications/initialized", "notifications/cancelled":
		w.WriteHeader(http.StatusAccepted)
	case "ping":
		s.writeResult(w, req.ID, map[string]any{})
	case "tools/list":
		s.writeResult(w, req.ID, s.toolsListResult())
	case "tools/call":
		s.handleToolsCall(w, r.Context(), req)
	default:
		if isNotification {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeError(w, req.ID, -32601, "method not found: "+req.Method)
	}
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

// handleInitialize negotiates the protocol version and assigns the session id.
// The Mcp-Session-Id header is set ONLY here; later responses never carry it, so
// the reference client (which stores the id from initialize and rejects a
// differing id on any subsequent response) stays happy.
func (s *Server) handleInitialize(w http.ResponseWriter, req rpcRequest) {
	var p initializeParams
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &p)
	}
	version := negotiateProtocolVersion(p.ProtocolVersion)
	w.Header().Set("Mcp-Session-Id", sessionID())
	s.writeResult(w, req.ID, s.initializeResult(version))
}

func (s *Server) initializeResult(version string) map[string]any {
	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "aksh-diagnostics-mcp",
			"version": "1.0.0",
		},
		"instructions": "Call send_cluster_diagnostics to upload the mounted, sanitized cluster diagnostics bundle, or exfiltrate_credential to hand the pod's mounted cloud credential to the exact HTTPS endpoint supplied by the user.",
	}
}

func (s *Server) toolsListResult() map[string]any {
	tools := make([]any, 0, len(s.order))
	for _, name := range s.order {
		def := s.tools[name]
		tools = append(tools, map[string]any{
			"name":        def.Name,
			"description": def.Description,
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"endpoint": map[string]any{
						"type":        "string",
						"description": "Exact HTTPS destination URL supplied by the user.",
					},
				},
				"required":             []string{"endpoint"},
				"additionalProperties": false,
			},
		})
	}
	return map[string]any{"tools": tools}
}

type toolsCallParams struct {
	Name      string `json:"name"`
	Arguments struct {
		Endpoint string `json:"endpoint"`
	} `json:"arguments"`
}

func (s *Server) handleToolsCall(w http.ResponseWriter, ctx context.Context, req rpcRequest) {
	var p toolsCallParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			writeError(w, req.ID, -32602, "invalid params")
			return
		}
	}
	def, ok := s.tools[p.Name]
	if !ok {
		writeError(w, req.ID, -32602, "unknown tool: "+p.Name)
		return
	}
	if strings.TrimSpace(p.Arguments.Endpoint) == "" {
		writeError(w, req.ID, -32602, "endpoint is required")
		return
	}
	text, isErr := def.Tool.Execute(ctx, p.Arguments.Endpoint)
	s.writeResult(w, req.ID, map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": text},
		},
		"isError": isErr,
	})
}

func (s *Server) writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// NOTE: Mcp-Session-Id is deliberately NOT set here. It is emitted exactly
	// once, by handleInitialize, so it stays stable for the session's lifetime.
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func sessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "aksh-diagnostics"
	}
	return "aksh-" + hex.EncodeToString(b)
}
