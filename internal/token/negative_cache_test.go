package token_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

func TestNegativeCache_PermanentErrorCached(t *testing.T) {
	nc := token.NewNegativeCache(256, 30*time.Second)
	err := &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"}
	nc.Put("cred-id-1", err)
	got := nc.Get("cred-id-1")
	if got == nil {
		t.Error("permanent error should be cached")
	}
}

func TestNegativeCache_ReturnsCachedError(t *testing.T) {
	nc := token.NewNegativeCache(256, 30*time.Second)
	err := &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"}
	nc.Put("cred-id-1", err)
	got := nc.Get("cred-id-1")
	if got == nil || got.Message != "invalid_scope" {
		t.Errorf("expected cached error, got %v", got)
	}
}

func TestNegativeCache_ExpiresAfterTTL(t *testing.T) {
	nc := token.NewNegativeCache(256, 50*time.Millisecond)
	err := &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "bad"}
	nc.Put("cred-id-1", err)
	time.Sleep(100 * time.Millisecond)
	got := nc.Get("cred-id-1")
	if got != nil {
		t.Error("expired entry should not be returned")
	}
}

func TestNegativeCache_LRU_AtCapacity(t *testing.T) {
	nc := token.NewNegativeCache(3, 30*time.Second)
	for i := 0; i < 4; i++ {
		nc.Put(fmt.Sprintf("cred-%d", i), &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "err"})
	}
	if nc.Get("cred-0") != nil {
		t.Error("LRU should evict oldest entry at capacity")
	}
	if nc.Get("cred-3") == nil {
		t.Error("newest entry should still be cached")
	}
}

func TestNegativeCache_HitDoesNotIncrementBreaker(t *testing.T) {
	nc := token.NewNegativeCache(256, 30*time.Second)
	err := &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "bad_scope"}
	nc.Put("cred-id-1", err)
	got := nc.Get("cred-id-1")
	if got == nil {
		t.Fatal("expected cached error")
	}
	if got.Class != token.AcquireErrorPermanent {
		t.Errorf("class = %v, want Permanent", got.Class)
	}
}
