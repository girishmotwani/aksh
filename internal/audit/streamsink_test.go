package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

var (
	_ audit.AuditSink    = (*audit.StreamSink)(nil)
	_ pipeline.AuditSink = (*audit.StreamSink)(nil)
)

func testAuditEvent() pipeline.AuditEvent {
	return pipeline.AuditEvent{
		Timestamp:     time.Unix(1700000000, 0).UTC(),
		RequestID:     "req-1",
		Identity:      "api.example.com",
		Method:        "GET",
		Path:          "/v1/models",
		Port:          443,
		Disposition:   pipeline.DispositionDeny,
		DenyReason:    pipeline.ReasonIdentityMismatch,
		Fault:         true,
		FaultClass:    pipeline.FaultClassLocal,
		PolicyVersion: "policy-1",
		RuleName:      "rule-1",
		CredentialID:  "cred-1",
		CacheHit:      true,
		Ambiguous:     false,
	}
}

func TestNewStreamSink_ValidWriter_ReturnsUsableSink(t *testing.T) {
	var buf bytes.Buffer
	sink := audit.NewStreamSink(&buf)
	if sink == nil {
		t.Fatal("NewStreamSink() = nil, want non-nil")
	}
}

func TestRecord_ValidEvent_WritesOneWholeJSONLine(t *testing.T) {
	var buf bytes.Buffer
	sink := audit.NewStreamSink(&buf)

	if err := sink.Record(context.Background(), testAuditEvent()); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	output := buf.String()
	if strings.Count(output, "\n") != 1 {
		t.Fatalf("newline count = %d, want 1 in %q", strings.Count(output, "\n"), output)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got["requestId"] != "req-1" {
		t.Fatalf("requestId = %v, want req-1", got["requestId"])
	}
	if schema, _ := got["schema"].(string); schema != "aksh.dev/audit/v1" {
		t.Fatalf("schema = %q, want aksh.dev/audit/v1", schema)
	}
}

func TestRecord_ContextAlreadyCancelled_ReturnsErrorWithoutWriting(t *testing.T) {
	var buf bytes.Buffer
	sink := audit.NewStreamSink(&buf)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sink.Record(ctx, testAuditEvent())
	if err == nil {
		t.Fatal("Record() error = nil, want non-nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Record() error = %v, want context.Canceled or wrapped equivalent", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("buffer length = %d, want 0", buf.Len())
	}
}

func TestRecord_ContextCancelledConcurrentlyDuringWrite_StillCompletesOrFailsCleanly(t *testing.T) {
	writer := &gatedWriter{started: make(chan struct{}), release: make(chan struct{})}
	sink := audit.NewStreamSink(writer)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- sink.Record(ctx, testAuditEvent())
	}()

	writer.waitStarted(t)
	cancel()
	close(writer.release)

	err := <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Record() error = %v, want nil or context.Canceled", err)
	}
	if len(writer.writes) > 1 {
		t.Fatalf("writes = %d, want <= 1", len(writer.writes))
	}
	for _, write := range writer.writes {
		if !strings.HasSuffix(write, "\n") {
			t.Fatalf("write %q missing trailing newline", write)
		}
	}
}

func TestRecord_ConcurrentCallsFromManyGoroutines_ProduceWholeParseableJSONLines(t *testing.T) {
	var buf bytes.Buffer
	sink := audit.NewStreamSink(&buf)

	const goroutines = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ev := testAuditEvent()
			ev.RequestID = "req-" + strconv.Itoa(i)
			if err := sink.Record(context.Background(), ev); err != nil {
				t.Errorf("Record() error = %v", err)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != goroutines {
		t.Fatalf("line count = %d, want %d", len(lines), goroutines)
	}
	for _, line := range lines {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("json.Unmarshal(%q) error = %v", line, err)
		}
	}
}

func TestStreamSink_SatisfiesBothAuditSinkAndPipelineAuditSink_CompileTimeAssertion(t *testing.T) {
	var buf bytes.Buffer
	sink := audit.NewStreamSink(&buf)
	if sink == nil {
		t.Fatal("NewStreamSink() = nil, want non-nil")
	}
}

func TestRecord_EncodedEventContainsNoCredentialLikeField_NoTokenLeakage(t *testing.T) {
	var buf bytes.Buffer
	sink := audit.NewStreamSink(&buf)

	if err := sink.Record(context.Background(), testAuditEvent()); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for key, value := range decoded {
		lowerKey := strings.ToLower(key)
		if lowerKey == "token" || lowerKey == "secret" {
			t.Fatalf("unexpected sensitive field %q present", key)
		}
		if s, ok := value.(string); ok {
			lowerValue := strings.ToLower(s)
			if strings.Contains(lowerValue, "bearer ") || strings.Contains(lowerValue, "access_token") {
				t.Fatalf("unexpected credential-like value %q for key %q", s, key)
			}
		}
	}
}

type gatedWriter struct {
	mu      sync.Mutex
	started chan struct{}
	release chan struct{}
	writes  []string
	once    sync.Once
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.started)
	})
	<-w.release

	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

func (w *gatedWriter) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-w.started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for writer to start")
	}
}
