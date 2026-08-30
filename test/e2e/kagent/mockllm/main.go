package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Minimal OpenAI-compatible chat-completions server, used as the LLM endpoint
// in the kagent e2e. It exists so the test is hermetic: no API key, no spend,
// no internet, and a deterministic reply the harness can assert on.
//
// It presents a leaf for api.openai.com (see ../../certs/gencert.go) and
// CoreDNS maps that name to this Service, so the kagent agent dials the real
// hostname over real TLS. That matters: aksh policy matches on the SNI of the
// captured connection, so a test that pointed the agent at some internal name
// would not exercise the thing under test.
//
// http/1.1 ONLY, for the same reason as the echo upstream: the aksh request
// path rejects the HTTP/2 preface, so an h2-capable upstream would fail the
// relay rather than the policy check.
func main() {
	addr := os.Getenv("MOCKLLM_LISTEN")
	if addr == "" {
		addr = ":8443"
	}
	reply := os.Getenv("MOCKLLM_REPLY")
	if reply == "" {
		reply = "MOCK-LLM-OK"
	}

	mux := http.NewServeMux()

	// Some clients probe /v1/models on startup; answering it keeps a probe
	// from looking like an outage.
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("mockllm served host=%s path=%s method=%s from=%s", r.Host, r.URL.Path, r.Method, r.RemoteAddr)
		writeJSON(w, map[string]any{
			"object": "list",
			"data": []any{
				map[string]any{"id": "gpt-4.1-mini", "object": "model", "owned_by": "mock"},
			},
		})
	})

	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("mockllm served host=%s path=%s method=%s from=%s", r.Host, r.URL.Path, r.Method, r.RemoteAddr)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		// A body we cannot decode is still answered: the point of this server
		// is to complete the egress flow, not to validate the client.
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Model == "" {
			req.Model = "gpt-4.1-mini"
		}
		if req.Stream {
			writeStream(w, req.Model, reply)
			return
		}
		writeJSON(w, completion(req.Model, reply))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("mockllm unhandled host=%s path=%s method=%s from=%s", r.Host, r.URL.Path, r.Method, r.RemoteAddr)
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    &tls.Config{NextProtos: []string{"http/1.1"}},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	log.Printf("mockllm listening (TLS, http/1.1 only) on %s", addr)
	log.Fatal(srv.ListenAndServeTLS("/certs/server.crt", "/certs/server.key"))
}

func completion(model, reply string) map[string]any {
	return map[string]any{
		"id":      "chatcmpl-mock",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": reply},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeStream answers a streaming request with the server-sent-event framing
// an OpenAI client expects: one delta carrying the whole reply, a stop chunk,
// then [DONE].
func writeStream(w http.ResponseWriter, model, reply string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)

	chunk := func(delta map[string]any, finish any) {
		payload := map[string]any{
			"id":      "chatcmpl-mock",
			"object":  "chat.completion.chunk",
			"created": time.Now().Unix(),
			"model":   model,
			"choices": []any{
				map[string]any{"index": 0, "delta": delta, "finish_reason": finish},
			},
		}
		b, _ := json.Marshal(payload)
		fmt.Fprintf(w, "data: %s\n\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}

	chunk(map[string]any{"role": "assistant", "content": reply}, nil)
	chunk(map[string]any{}, "stop")
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}
