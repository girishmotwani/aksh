package token_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/token"
)

func TestBreaker_StartsClosed(t *testing.T) {
	b := token.NewBreaker(5, 30)
	if b.IsOpen() {
		t.Error("breaker should start closed")
	}
}

func TestBreaker_OpensAfter5TransientFailures(t *testing.T) {
	b := token.NewBreaker(5, 30)
	for i := 0; i < 5; i++ {
		b.RecordFailure(token.AcquireErrorTransient)
	}
	if !b.IsOpen() {
		t.Error("breaker should be open after 5 transient failures")
	}
}

func TestBreaker_OpenRejectsImmediately(t *testing.T) {
	b := token.NewBreaker(5, 30)
	for i := 0; i < 5; i++ {
		b.RecordFailure(token.AcquireErrorTransient)
	}
	if b.AllowRequest() {
		t.Error("open breaker should not allow requests")
	}
}

func TestBreaker_ProbeAfterInterval(t *testing.T) {
	b := token.NewBreaker(5, 0)
	for i := 0; i < 5; i++ {
		b.RecordFailure(token.AcquireErrorTransient)
	}
	if !b.AllowRequest() {
		t.Error("should allow probe after interval")
	}
}

func TestBreaker_SuccessfulProbeCloses(t *testing.T) {
	b := token.NewBreaker(5, 0)
	for i := 0; i < 5; i++ {
		b.RecordFailure(token.AcquireErrorTransient)
	}
	b.AllowRequest()
	b.RecordSuccess()
	if b.IsOpen() {
		t.Error("breaker should close after successful probe")
	}
}

func TestBreaker_PermanentError_DoesNotIncrement(t *testing.T) {
	b := token.NewBreaker(5, 30)
	for i := 0; i < 10; i++ {
		b.RecordFailure(token.AcquireErrorPermanent)
	}
	if b.IsOpen() {
		t.Error("permanent errors should not open the breaker")
	}
}

func TestBreaker_LocalError_DoesNotIncrement(t *testing.T) {
	b := token.NewBreaker(5, 30)
	for i := 0; i < 10; i++ {
		b.RecordFailure(token.AcquireErrorLocal)
	}
	if b.IsOpen() {
		t.Error("local errors should not open the breaker")
	}
}

func TestBreaker_SuccessResetsCount(t *testing.T) {
	b := token.NewBreaker(5, 30)
	for i := 0; i < 4; i++ {
		b.RecordFailure(token.AcquireErrorTransient)
	}
	b.RecordSuccess()
	for i := 0; i < 4; i++ {
		b.RecordFailure(token.AcquireErrorTransient)
	}
	if b.IsOpen() {
		t.Error("breaker should not be open after reset + 4 failures")
	}
}
