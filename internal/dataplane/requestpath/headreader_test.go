package requestpath_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
)

func TestNewHeadGuard_ValidReaderAndLimit_ReturnsNonNilGuard(t *testing.T) {
	guard := requestpath.NewHeadGuard(bytes.NewBufferString("GET / HTTP/1.1\r\n\r\n"), 16)
	if guard == nil {
		t.Fatal("NewHeadGuard() = nil, want non-nil")
	}
}

func TestNewHeadGuard_NegativeLimit_DoesNotPanicAndFailsClosed(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewHeadGuard() panicked: %v", r)
		}
	}()

	guard := requestpath.NewHeadGuard(bytes.NewBufferString("abc"), -1)
	guard.Arm()

	buf := make([]byte, 1)
	if _, err := guard.Read(buf); !errors.Is(err, requestpath.ErrHeadTooLarge) {
		t.Fatalf("Read() error = %v, want ErrHeadTooLarge", err)
	}
}

func TestArm_ResetsBudgetToLimit_ReadsUpToLimitSucceed(t *testing.T) {
	guard := requestpath.NewHeadGuard(bytes.NewBufferString("abcdef"), 6)
	guard.Arm()

	buf := make([]byte, 6)
	n, err := guard.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v, want nil", err)
	}
	if n != 6 {
		t.Fatalf("Read() bytes = %d, want 6", n)
	}
}

func TestArm_CalledTwiceOnSameConnection_EachRequestGetsFullBudget(t *testing.T) {
	guard := requestpath.NewHeadGuard(bytes.NewBufferString("abcdef"), 3)

	guard.Arm()
	buf := make([]byte, 3)
	if n, err := guard.Read(buf); err != nil || n != 3 {
		t.Fatalf("first Read() = (%d, %v), want (3, nil)", n, err)
	}
	guard.Disarm()

	guard.Arm()
	if n, err := guard.Read(buf); err != nil || n != 3 {
		t.Fatalf("second Read() = (%d, %v), want (3, nil)", n, err)
	}
}

func TestDisarm_CalledBeforeBody_BodyBytesNotCountedAgainstBudget(t *testing.T) {
	guard := requestpath.NewHeadGuard(bytes.NewBufferString("headbody"), 4)
	guard.Arm()

	head := make([]byte, 4)
	if _, err := guard.Read(head); err != nil {
		t.Fatalf("Read(head) error = %v, want nil", err)
	}
	guard.Disarm()

	body := make([]byte, 4)
	n, err := guard.Read(body)
	if err != nil {
		t.Fatalf("Read(body) error = %v, want nil", err)
	}
	if n != 4 {
		t.Fatalf("Read(body) bytes = %d, want 4", n)
	}
}

func TestRead_ArmedWithinBudget_ReturnsRequestedBytes(t *testing.T) {
	guard := requestpath.NewHeadGuard(bytes.NewBufferString("abcdef"), 6)
	guard.Arm()

	buf := make([]byte, 2)
	n, err := guard.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v, want nil", err)
	}
	if got := string(buf[:n]); got != "ab" {
		t.Fatalf("Read() bytes = %q, want %q", got, "ab")
	}
}

func TestRead_ArmedOverBudget_TruncatesAndReturnsErrHeadTooLarge(t *testing.T) {
	reader := &countingReader{data: []byte("abcdef")}
	guard := requestpath.NewHeadGuard(reader, 3)
	guard.Arm()

	buf := make([]byte, 6)
	n, err := guard.Read(buf)
	if !errors.Is(err, requestpath.ErrHeadTooLarge) {
		t.Fatalf("Read() error = %v, want ErrHeadTooLarge", err)
	}
	if n != 3 {
		t.Fatalf("Read() bytes = %d, want 3", n)
	}
	if reader.read != 3 {
		t.Fatalf("underlying bytes read = %d, want 3", reader.read)
	}
}

func TestRead_ArmedOverBudgetShortRead_DelaysErrHeadTooLargeUntilBudgetExhausted(t *testing.T) {
	reader := &shortReader{data: []byte("abcdef"), step: 2}
	guard := requestpath.NewHeadGuard(reader, 3)
	guard.Arm()

	buf := make([]byte, 6)
	n, err := guard.Read(buf)
	if err != nil {
		t.Fatalf("first Read() error = %v, want nil", err)
	}
	if n != 2 {
		t.Fatalf("first Read() bytes = %d, want 2", n)
	}

	n, err = guard.Read(buf)
	if !errors.Is(err, requestpath.ErrHeadTooLarge) {
		t.Fatalf("second Read() error = %v, want ErrHeadTooLarge", err)
	}
	if n != 1 {
		t.Fatalf("second Read() bytes = %d, want 1", n)
	}
}

func TestRead_ExactlyAtBudgetBoundary_LastByteSucceedsNextReadFails(t *testing.T) {
	guard := requestpath.NewHeadGuard(bytes.NewBufferString("abc"), 3)
	guard.Arm()

	buf := make([]byte, 3)
	if n, err := guard.Read(buf); err != nil || n != 3 {
		t.Fatalf("first Read() = (%d, %v), want (3, nil)", n, err)
	}

	next := make([]byte, 1)
	if _, err := guard.Read(next); err == nil {
		t.Fatal("second Read() error = nil, want non-nil")
	} else if !errors.Is(err, requestpath.ErrHeadTooLarge) && !errors.Is(err, io.EOF) {
		t.Fatalf("second Read() error = %v, want ErrHeadTooLarge or io.EOF", err)
	}
}

func TestHead_AfterReadingSomeBytes_ReturnsExactlyTheBytesConsumed(t *testing.T) {
	guard := requestpath.NewHeadGuard(bytes.NewBufferString("abcdef"), 6)
	guard.Arm()

	buf := make([]byte, 4)
	if _, err := guard.Read(buf); err != nil {
		t.Fatalf("Read() error = %v, want nil", err)
	}

	if got := string(guard.Head()); got != "abcd" {
		t.Fatalf("Head() = %q, want %q", got, "abcd")
	}
}

type countingReader struct {
	data []byte
	read int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.read += n
	return n, nil
}

type shortReader struct {
	data []byte
	step int
}

func (r *shortReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if r.step > 0 && len(p) > r.step {
		p = p[:r.step]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
