package requestpath

import "io"

// HeadGuard enforces a per-request head byte limit beneath the parser.
type HeadGuard struct {
	r         io.Reader
	limit     int
	remaining int
	armed     bool
	tee       []byte
}

// NewHeadGuard constructs a head guard over r with the provided limit.
func NewHeadGuard(r io.Reader, limit int) *HeadGuard {
	if limit < 0 {
		limit = 0
	}
	return &HeadGuard{
		r:     r,
		limit: limit,
		tee:   make([]byte, 0, limit),
	}
}

// Arm resets the budget and capture buffer for the next request head.
func (g *HeadGuard) Arm() {
	g.remaining = g.limit
	g.armed = true
	g.tee = g.tee[:0]
}

// Disarm stops counting and capturing bytes.
func (g *HeadGuard) Disarm() {
	g.armed = false
}

// Read enforces the current head budget when armed.
func (g *HeadGuard) Read(p []byte) (int, error) {
	if !g.armed {
		return g.r.Read(p)
	}
	if g.remaining <= 0 {
		return 0, ErrHeadTooLarge
	}

	limit := len(p)
	if limit > g.remaining {
		limit = g.remaining
	}

	n, err := g.r.Read(p[:limit])
	if n > 0 {
		g.tee = append(g.tee, p[:n]...)
		g.remaining -= n
	}
	if err != nil {
		return n, err
	}
	if len(p) > limit && g.remaining == 0 {
		return n, ErrHeadTooLarge
	}
	return n, nil
}

// Head returns the bytes captured since the most recent Arm call.
func (g *HeadGuard) Head() []byte {
	return g.tee
}
