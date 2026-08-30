package requestpath

import (
	"errors"
	"io"
	"sync"
)

// ErrResponseBodyTooLarge is returned by responseBodyLimitReader once the
// cumulative number of bytes read from the wrapped body exceeds the
// configured limit. Callers match it with errors.Is.
var ErrResponseBodyTooLarge = errors.New("requestpath: response body exceeds configured limit")

// responseBodyLimitReader wraps an io.ReadCloser and enforces a cumulative
// byte cap with O(1) memory: it holds only fixed-size counters, never a
// buffer proportional to the stream size. The boundary is inclusive -- a
// cumulative count of exactly limit bytes is permitted; the read that pushes
// the count strictly above limit fails with ErrResponseBodyTooLarge.
type responseBodyLimitReader struct {
	inner io.ReadCloser
	limit int64

	mu       sync.Mutex
	count    int64
	exceeded bool

	closeOnce sync.Once
	closeErr  error
}

// newResponseBodyLimitReader wraps inner with a cumulative byte cap of limit.
func newResponseBodyLimitReader(inner io.ReadCloser, limit int64) *responseBodyLimitReader {
	return &responseBodyLimitReader{inner: inner, limit: limit}
}

// Read reads from the wrapped body, tracking the cumulative byte count. Once
// the limit has been exceeded every subsequent call returns
// ErrResponseBodyTooLarge without touching the wrapped body.
func (r *responseBodyLimitReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.exceeded {
		r.mu.Unlock()
		return 0, ErrResponseBodyTooLarge
	}
	r.mu.Unlock()

	n, err := r.inner.Read(p)

	r.mu.Lock()
	r.count += int64(n)
	if r.count > r.limit {
		r.exceeded = true
		r.mu.Unlock()
		return n, ErrResponseBodyTooLarge
	}
	r.mu.Unlock()
	return n, err
}

// Close closes the wrapped body exactly once, regardless of how many times
// Close is invoked.
func (r *responseBodyLimitReader) Close() error {
	r.closeOnce.Do(func() {
		r.closeErr = r.inner.Close()
	})
	return r.closeErr
}

// Exceeded reports whether a read has pushed the cumulative count strictly
// above the configured limit.
func (r *responseBodyLimitReader) Exceeded() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exceeded
}
