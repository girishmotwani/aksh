package requestpath_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
)

func TestDefaultOptions_Called_ReturnsAllNonZeroFields(t *testing.T) {
	opts := requestpath.DefaultOptions()

	if opts.MaxHeaderBytes <= 0 {
		t.Fatalf("MaxHeaderBytes = %d, want > 0", opts.MaxHeaderBytes)
	}
	if opts.MaxInflightRequests <= 0 {
		t.Fatalf("MaxInflightRequests = %d, want > 0", opts.MaxInflightRequests)
	}
	if opts.CopyBufferBytes <= 0 {
		t.Fatalf("CopyBufferBytes = %d, want > 0", opts.CopyBufferBytes)
	}
	if opts.HeaderReadTimeout <= 0 {
		t.Fatalf("HeaderReadTimeout = %v, want > 0", opts.HeaderReadTimeout)
	}
	if opts.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout = %v, want > 0", opts.IdleTimeout)
	}
	if opts.ProgressDeadline <= 0 {
		t.Fatalf("ProgressDeadline = %v, want > 0", opts.ProgressDeadline)
	}
	if opts.UpstreamDialTimeout <= 0 {
		t.Fatalf("UpstreamDialTimeout = %v, want > 0", opts.UpstreamDialTimeout)
	}
	if opts.UpstreamResponseTimeout <= 0 {
		t.Fatalf("UpstreamResponseTimeout = %v, want > 0", opts.UpstreamResponseTimeout)
	}
	if opts.MaxRejectionAudits <= 0 {
		t.Fatalf("MaxRejectionAudits = %d, want > 0", opts.MaxRejectionAudits)
	}
	if opts.RejectionAuditTimeout <= 0 {
		t.Fatalf("RejectionAuditTimeout = %v, want > 0", opts.RejectionAuditTimeout)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidate_ZeroValueOptions_ReturnsError(t *testing.T) {
	if err := (requestpath.Options{}).Validate(); err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}
}

func TestValidate_MaxHeaderBytesZeroOrNegative_ReturnsError(t *testing.T) {
	for _, maxHeaderBytes := range []int{0, -1} {
		opts := requestpath.DefaultOptions()
		opts.MaxHeaderBytes = maxHeaderBytes
		if err := opts.Validate(); err == nil {
			t.Fatalf("Validate() error = nil for MaxHeaderBytes=%d, want non-nil", maxHeaderBytes)
		}
	}
}

func TestValidate_EachOtherBoundFieldZeroOrNegativeIndependently_ReturnsError(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*requestpath.Options)
	}{
		{
			name: "MaxInflightRequests",
			mut: func(opts *requestpath.Options) {
				opts.MaxInflightRequests = 0
			},
		},
		{
			name: "CopyBufferBytes",
			mut: func(opts *requestpath.Options) {
				opts.CopyBufferBytes = -1
			},
		},
		{
			name: "HeaderReadTimeout",
			mut: func(opts *requestpath.Options) {
				opts.HeaderReadTimeout = 0
			},
		},
		{
			name: "IdleTimeout",
			mut: func(opts *requestpath.Options) {
				opts.IdleTimeout = -1
			},
		},
		{
			name: "ProgressDeadline",
			mut: func(opts *requestpath.Options) {
				opts.ProgressDeadline = 0
			},
		},
		{
			name: "UpstreamDialTimeout",
			mut: func(opts *requestpath.Options) {
				opts.UpstreamDialTimeout = -1
			},
		},
		{
			name: "UpstreamResponseTimeout",
			mut: func(opts *requestpath.Options) {
				opts.UpstreamResponseTimeout = 0
			},
		},
		{
			name: "MaxRejectionAudits",
			mut: func(opts *requestpath.Options) {
				opts.MaxRejectionAudits = 0
			},
		},
		{
			name: "RejectionAuditTimeout",
			mut: func(opts *requestpath.Options) {
				opts.RejectionAuditTimeout = -1
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := requestpath.DefaultOptions()
			tc.mut(&opts)
			if err := opts.Validate(); err == nil {
				t.Fatalf("Validate() error = nil for %s, want non-nil", tc.name)
			}
		})
	}
}

func TestValidate_AllFieldsFromDefaultOptions_ReturnsNil(t *testing.T) {
	if err := requestpath.DefaultOptions().Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestDefaultOptions_MaxResponseBodyBytes_Is128MiB(t *testing.T) {
	opts := requestpath.DefaultOptions()
	if want := int64(128 * 1024 * 1024); opts.MaxResponseBodyBytes != want {
		t.Fatalf("MaxResponseBodyBytes = %d, want %d", opts.MaxResponseBodyBytes, want)
	}
}

func TestValidate_MaxResponseBodyBytesNegative_ReturnsError(t *testing.T) {
	opts := requestpath.DefaultOptions()
	opts.MaxResponseBodyBytes = -1
	if err := opts.Validate(); err == nil {
		t.Fatal("Validate() error = nil for MaxResponseBodyBytes=-1, want non-nil")
	}
}

func TestValidate_MaxResponseBodyBytesZero_ReturnsError(t *testing.T) {
	opts := requestpath.DefaultOptions()
	opts.MaxResponseBodyBytes = 0
	if err := opts.Validate(); err == nil {
		t.Fatal("Validate() error = nil for MaxResponseBodyBytes=0, want non-nil")
	}
}

func TestValidate_MaxResponseBodyBytesCustomPositive_ReturnsNil(t *testing.T) {
	opts := requestpath.DefaultOptions()
	opts.MaxResponseBodyBytes = 64 * 1024 * 1024
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}
