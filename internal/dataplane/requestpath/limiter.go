package requestpath

// Limiter is a non-blocking admission cap for in-flight requests.
type Limiter struct {
	ch chan struct{}
}

// NewLimiter constructs a limiter with capacity n.
func NewLimiter(n int) *Limiter {
	if n <= 0 {
		n = 1
	}
	return &Limiter{ch: make(chan struct{}, n)}
}

// TryAcquire returns false immediately when the limiter is saturated.
func (l *Limiter) TryAcquire() bool {
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns one acquired slot and panics on over-release.
func (l *Limiter) Release() {
	select {
	case <-l.ch:
	default:
		panic("requestpath: limiter release without acquire")
	}
}

// InFlight returns the current number of held slots.
func (l *Limiter) InFlight() int {
	return len(l.ch)
}
