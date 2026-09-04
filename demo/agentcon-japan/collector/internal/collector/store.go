package collector

import (
	"sync"
	"time"
)

// Store is a bounded, concurrency-safe, in-memory ring of the most recent
// events plus a change-notification fan-out for live observers. It is the whole
// persistence layer of the demo: there is deliberately no disk, no external
// store, and a hard cap on retained events so the collector's footprint stays
// flat no matter how much traffic the demo throws at it.
//
// Live delivery uses a signal-and-pull model rather than pushing event copies
// through per-subscriber channels. Each subscriber holds only a coalescing
// "something changed" signal; when woken it pulls every event newer than its
// own watermark straight from the authoritative buffer via EventsAfter. This
// makes delivery ordered and gap-free within the retained window regardless of
// concurrency: a subscriber can never observe an event twice, observe events
// out of sequence, or lose a delivered event because a bounded push-channel
// filled. All mutation and signalling happen under a single mutex, so seq
// assignment, retention, and notification are one atomic step.
type Store struct {
	mu  sync.Mutex
	cap int
	buf []Event // retains at most cap events, oldest-first, ascending seq
	seq int64   // monotonically increasing sequence assigned to each event
	now func() time.Time

	subs    map[int]chan struct{} // coalescing change signals, buffer 1
	nextSub int
}

// NewStore returns a Store retaining at most capacity events. A non-positive
// capacity is coerced to 1 so the store always holds something and Add cannot
// panic on an empty ring.
func NewStore(capacity int) *Store {
	if capacity < 1 {
		capacity = 1
	}
	return &Store{
		cap:  capacity,
		buf:  make([]Event, 0, capacity),
		now:  time.Now,
		subs: make(map[int]chan struct{}),
	}
}

// Add stamps the event with the next sequence number and the current time,
// appends it, evicts the oldest event once the cap is exceeded, and signals live
// subscribers. Sequence assignment, retention, and signalling all happen under
// the same lock, so seq is strictly monotonic in append order and no subscriber
// can be woken for an event that is not yet visible in the buffer. It returns
// the stored event so the caller can report the assigned seq/request_id without
// re-reading the store.
func (s *Store) Add(e Event) Event {
	s.mu.Lock()
	s.seq++
	e.Seq = s.seq
	e.Timestamp = s.now().UTC().Format(time.RFC3339Nano)
	if len(s.buf) == s.cap {
		// Drop the oldest event. Copy forward rather than reslice so the
		// backing array does not grow without bound over the demo's life.
		copy(s.buf, s.buf[1:])
		s.buf[len(s.buf)-1] = e
	} else {
		s.buf = append(s.buf, e)
	}
	s.signalLocked()
	s.mu.Unlock()
	return e
}

// Snapshot returns a copy of the retained events, oldest-first. The copy means
// callers (UI, harness) can read without holding the lock or racing writers.
func (s *Store) Snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.buf))
	copy(out, s.buf)
	return out
}

// EventsAfter returns a copy of the retained events whose seq is strictly
// greater than afterSeq, oldest-first. It is the pull half of live delivery: a
// subscriber calls it with its current watermark to obtain exactly the events it
// has not yet seen, in order and without duplicates. Because the buffer is
// bounded, events older than the retained window are simply absent — a
// subscriber that falls far behind resumes from the oldest retained event,
// which is the inherent contract of a fixed-size store.
func (s *Store) EventsAfter(afterSeq int64) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	// buf is ascending by seq; find the first index past the watermark.
	i := 0
	for i < len(s.buf) && s.buf[i].Seq <= afterSeq {
		i++
	}
	if i >= len(s.buf) {
		return nil
	}
	out := make([]Event, len(s.buf)-i)
	copy(out, s.buf[i:])
	return out
}

// Count returns the number of retained events.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf)
}

// LatestSeq returns the highest sequence number assigned so far, or 0 if no
// event has ever been added. It is preserved across Reset so it is a stable
// upper bound a fresh subscriber can use as its initial watermark.
func (s *Store) LatestSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// Reset clears retained events. The sequence counter is intentionally preserved
// so seq stays globally monotonic across resets, which keeps live and
// reconnecting subscribers from ever seeing a seq go backwards.
func (s *Store) Reset() {
	s.mu.Lock()
	s.buf = s.buf[:0]
	s.mu.Unlock()
}

// Subscribe registers a live listener and returns its id plus a receive-only
// signal channel. A value on the channel means "there is new data"; the
// subscriber responds by pulling with EventsAfter. The channel is coalescing
// (buffer 1): bursts collapse into a single wake-up, and a slow subscriber can
// never apply backpressure to the ingest path because signalling never blocks.
func (s *Store) Subscribe() (int, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextSub
	s.nextSub++
	ch := make(chan struct{}, 1)
	s.subs[id] = ch
	return id, ch
}

// Unsubscribe removes a listener's signal channel. It is safe to call once per
// subscriber; a second call is a no-op.
func (s *Store) Unsubscribe(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, id)
}

// signalLocked wakes every subscriber without blocking. Must be called with
// s.mu held. A full (already-signalled) channel is left as-is: the pending
// wake-up will make the subscriber pull all new events anyway, so coalescing
// loses no data.
func (s *Store) signalLocked() {
	for _, ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
