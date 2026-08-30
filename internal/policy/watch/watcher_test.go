package watch

import (
	"context"
	"errors"
	"testing"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwatch "k8s.io/apimachinery/pkg/watch"
)

// stubClient is a no-op AkshPolicyClient used by validation tests that never
// reach list/watch.
type stubClient struct{}

func (stubClient) List(ctx context.Context, opts metav1.ListOptions) (*v1alpha1.AkshPolicyList, error) {
	return &v1alpha1.AkshPolicyList{}, nil
}

func (stubClient) Watch(ctx context.Context, opts metav1.ListOptions) (kwatch.Interface, error) {
	return kwatch.NewFake(), nil
}

func validOptions() Options {
	return Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}
}

func TestNewWatcher_EmptyNamespace_ReturnsError(t *testing.T) {
	opts := validOptions()
	opts.Namespace = ""
	store := &Store{}
	w, err := NewWatcher(opts, stubClient{}, store)
	if err == nil || w != nil {
		t.Fatalf("NewWatcher(empty namespace) = (%v, %v), want (nil, error)", w, err)
	}
	if _, _, ok := store.Current(); ok {
		t.Fatalf("store mutated on invalid NewWatcher")
	}
}

func TestNewWatcher_NilClient_ReturnsError(t *testing.T) {
	store := &Store{}
	w, err := NewWatcher(validOptions(), nil, store)
	if err == nil || w != nil {
		t.Fatalf("NewWatcher(nil client) = (%v, %v), want (nil, error)", w, err)
	}
	if _, _, ok := store.Current(); ok {
		t.Fatalf("store mutated on invalid NewWatcher")
	}
}

func TestNewWatcher_NilStore_ReturnsError(t *testing.T) {
	w, err := NewWatcher(validOptions(), stubClient{}, nil)
	if err == nil || w != nil {
		t.Fatalf("NewWatcher(nil store) = (%v, %v), want (nil, error)", w, err)
	}
}

func TestNewWatcher_ZeroMaxStaleness_ReturnsError(t *testing.T) {
	store := &Store{}
	for _, ms := range []time.Duration{0, -1 * time.Second} {
		opts := validOptions()
		opts.MaxStaleness = ms
		w, err := NewWatcher(opts, stubClient{}, store)
		if err == nil || w != nil {
			t.Fatalf("NewWatcher(MaxStaleness=%v) = (%v, %v), want (nil, error)", ms, w, err)
		}
	}
	if _, _, ok := store.Current(); ok {
		t.Fatalf("store mutated on invalid NewWatcher")
	}
}

// Ensure sentinel errors are distinguishable for callers/logging.
func TestNewWatcher_ValidationErrors_AreSentinels(t *testing.T) {
	store := &Store{}
	if _, err := NewWatcher(Options{MaxStaleness: time.Second}, stubClient{}, store); !errors.Is(err, ErrEmptyNamespace) {
		t.Fatalf("empty namespace err = %v, want ErrEmptyNamespace", err)
	}
	if _, err := NewWatcher(validOptions(), nil, store); !errors.Is(err, ErrNilClient) {
		t.Fatalf("nil client err = %v, want ErrNilClient", err)
	}
	if _, err := NewWatcher(validOptions(), stubClient{}, nil); !errors.Is(err, ErrNilStore) {
		t.Fatalf("nil store err = %v, want ErrNilStore", err)
	}
	opts := validOptions()
	opts.MaxStaleness = 0
	if _, err := NewWatcher(opts, stubClient{}, store); !errors.Is(err, ErrInvalidMaxStaleness) {
		t.Fatalf("zero staleness err = %v, want ErrInvalidMaxStaleness", err)
	}
}
