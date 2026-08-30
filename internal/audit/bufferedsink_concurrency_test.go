package audit

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// parseLines splits NDJSON output into records, asserting each line is a whole,
// non-interleaved JSON object.
func parseLines(t *testing.T, out []byte) []map[string]any {
	t.Helper()
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("interleaved/partial JSON line %q: %v", line, err)
		}
		recs = append(recs, m)
	}
	return recs
}

// #26
func TestRecord_ConcurrentCallers_NoInterleavedRecords(t *testing.T) {
	const n = 64
	w := &bsWriter{}
	s := newTestSink(t, w, n, 5*time.Millisecond, nil)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.Record(context.Background(), sampleEvent("req-26")); err != nil {
				t.Errorf("Record[%d] error = %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	recs := parseLines(t, w.bytesWritten())
	if len(recs) != n {
		t.Fatalf("wrote %d whole records, want %d", len(recs), n)
	}
}

// #27
func TestRecord_ConcurrentWithFlush_NoDataRace(t *testing.T) {
	const n = 64
	w := &bsWriter{}
	s := newTestSink(t, w, n, 2*time.Millisecond, nil)

	stop := make(chan struct{})
	var fwg sync.WaitGroup
	for i := 0; i < 4; i++ {
		fwg.Add(1)
		go func() {
			defer fwg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.Flush()
				}
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.Record(context.Background(), sampleEvent("req-27")); err != nil {
				t.Errorf("Record[%d] error = %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	fwg.Wait()
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	recs := parseLines(t, w.bytesWritten())
	if len(recs) != n {
		t.Fatalf("wrote %d whole records, want %d", len(recs), n)
	}
}

// E2E-2: decision Record -> completed flush -> bytes observed on a fake writer,
// proving the durable-before-return contract end-to-end with the Slice-3
// encoder.
func TestE2E2_DecisionRecord_DurableBytesObservedWithEncoder(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	if err := s.Record(context.Background(), sampleEvent("e2e-2")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	recs := parseLines(t, w.bytesWritten())
	if len(recs) != 1 {
		t.Fatalf("observed %d records, want 1", len(recs))
	}
	if recs[0]["schema"] != auditRecordSchema {
		t.Fatalf("schema = %v, want %s", recs[0]["schema"], auditRecordSchema)
	}
	if recs[0]["requestId"] != "e2e-2" {
		t.Fatalf("requestId = %v, want e2e-2", recs[0]["requestId"])
	}
}
