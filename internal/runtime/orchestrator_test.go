package runtime

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
)

// fakeListener records Bind/Serve/Shutdown calls for orchestrator lifecycle
// assertions. Serve blocks until ctx is cancelled so a shutdown path is
// exercised deterministically when a valid config drives it.
type fakeListener struct {
	mu            sync.Mutex
	bindCalls     int
	shutdownCalls int
}

func (f *fakeListener) Bind() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bindCalls++
	return nil
}

func (f *fakeListener) Serve(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeListener) Shutdown(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdownCalls++
	return nil
}

func (f *fakeListener) binds() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bindCalls
}

func fakeFactory(fl *fakeListener) ListenerFactory {
	return func(cfg config.Config, h listener.ConnHandler, log *slog.Logger) (Listener, error) {
		return fl, nil
	}
}

// 116
func TestRun_InvalidConfig_ReturnsErrorBeforeBind(t *testing.T) {
	fl := &fakeListener{}
	o, err := New(Options{
		Config:          config.Config{}, // invalid: missing required fields
		ListenerFactory: fakeFactory(fl),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := o.Run(context.Background()); err == nil {
		t.Fatal("Run() = nil, want config validation error")
	}
	if got := fl.binds(); got != 0 {
		t.Fatalf("Bind calls = %d, want 0 before validation passes", got)
	}
}
