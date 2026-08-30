package main

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/runtime"
)

// fakeListener records Bind/Shutdown and blocks in Serve until ctx cancel so
// the SIGTERM-driven shutdown path is exercised deterministically.
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

func (f *fakeListener) shutdowns() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.shutdownCalls
}

func fakeFactory(fl *fakeListener) runtime.ListenerFactory {
	return func(cfg config.Config, h listener.ConnHandler, log *slog.Logger) (runtime.Listener, error) {
		return fl, nil
	}
}

func invalidConfig() config.Config { return config.Config{} }

func validConfig() config.Config {
	return config.Config{
		Listener: config.ListenerConfig{Address: "127.0.0.1:0"},
		CA:       config.CAConfig{PrivDir: "/priv", PubDir: "/pub"},
		Policy:   config.PolicyConfig{Namespace: "ns", MaxStaleness: 45 * time.Second},
		Capture: config.CaptureConfig{
			PodPath:     "/proc/1/root/sys/fs/cgroup",
			ProxyUID:    1774,
			ProxyGID:    1774,
			BlockNonTCP: true,
			RunProbe:    true,
		},
		Token: config.TokenConfig{
			SATokenPath: "/token",
			Entra: config.EntraConfig{
				TenantID:  "tenant",
				ClientID:  "client",
				Authority: "https://login.microsoftonline.com",
			},
		},
		Audit: config.AuditConfig{Sink: "stdout"},
	}
}

// 118
func TestMain_ConfigValidationFailure_ExitsNonZeroWithoutBind(t *testing.T) {
	fl := &fakeListener{}
	code := run(context.Background(), deps{
		loadConfig: func() (config.Config, error) { return invalidConfig(), nil },
		factory:    fakeFactory(fl),
	})
	if code == 0 {
		t.Fatalf("run() exit code = 0, want non-zero on config validation failure")
	}
	if got := fl.binds(); got != 0 {
		t.Fatalf("Bind calls = %d, want 0 on validation failure", got)
	}
}

// 134
func TestRun_SIGTERM_CallsShutdownAndExitsZero(t *testing.T) {
	fl := &fakeListener{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	go func() {
		done <- run(ctx, deps{
			loadConfig: func() (config.Config, error) { return validConfig(), nil },
			factory:    fakeFactory(fl),
		})
	}()

	// Wait for Bind then deliver the (simulated) SIGTERM via ctx cancel.
	deadline := time.After(2 * time.Second)
	for fl.binds() == 0 {
		select {
		case <-deadline:
			t.Fatal("listener never bound")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("run() exit code = %d, want 0 after clean drain", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not return after SIGTERM")
	}
	if got := fl.shutdowns(); got != 1 {
		t.Fatalf("Shutdown calls = %d, want 1", got)
	}
}
