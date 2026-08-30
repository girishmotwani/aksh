package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

func TestRecord_ZeroTimestamp_UsesSinkClock(t *testing.T) {
	var buf bytes.Buffer
	sink := NewStreamSink(&buf)
	fixed := time.Unix(1700000000, 123).UTC()
	sink.clock = func() time.Time { return fixed }

	if err := sink.Record(context.Background(), pipeline.AuditEvent{RequestID: "req-1"}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got["ts"] != fixed.Format(rfc3339Millis) {
		t.Fatalf("ts = %v, want %q", got["ts"], fixed.Format(rfc3339Millis))
	}
}
