package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/bundle"
	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/credential"
	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/upload"
)

type fakeUploader struct {
	calls  atomic.Int32
	result upload.Result
	err    error
}

func (f *fakeUploader) Upload(_ context.Context, _ []byte) (upload.Result, error) {
	f.calls.Add(1)
	return f.result, f.err
}

func loaderWith(t *testing.T, content string) *bundle.Loader {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundle.New(bundle.Config{BundlePath: p})
}

func factoryFor(up Uploader) UploaderFactory {
	return func(string) (Uploader, error) { return up, nil }
}

func TestExecute_Success(t *testing.T) {
	fu := &fakeUploader{result: upload.Result{StatusCode: 202, Status: "202 Accepted"}}
	svc := New(loaderWith(t, `{"ok":true}`), factoryFor(fu))
	text, isErr := svc.Execute(context.Background(), "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics")
	if isErr {
		t.Errorf("unexpected error result: %s", text)
	}
	if text != "upload succeeded: HTTP 202 Accepted" {
		t.Errorf("text = %q", text)
	}
	if fu.calls.Load() != 1 {
		t.Errorf("uploads = %d, want 1", fu.calls.Load())
	}
}

func TestExecute_403_PropagatedNoRetry(t *testing.T) {
	fu := &fakeUploader{result: upload.Result{StatusCode: 403, Status: "403 Forbidden"}}
	svc := New(loaderWith(t, `{"ok":true}`), factoryFor(fu))
	text, isErr := svc.Execute(context.Background(), "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics")
	if !isErr {
		t.Error("403 must be an error result")
	}
	if text != "upload failed: HTTP 403 Forbidden" {
		t.Errorf("text = %q", text)
	}
	if fu.calls.Load() != 1 {
		t.Errorf("uploads = %d, want exactly 1 (no retry)", fu.calls.Load())
	}
}

func TestExecute_TransportError(t *testing.T) {
	fu := &fakeUploader{err: errors.New("upload timed out")}
	svc := New(loaderWith(t, `{"ok":true}`), factoryFor(fu))
	text, isErr := svc.Execute(context.Background(), "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics")
	if !isErr || !strings.Contains(text, "timed out") {
		t.Errorf("text=%q isErr=%v", text, isErr)
	}
}

func TestExecute_BundleErrorNeverUploads(t *testing.T) {
	fu := &fakeUploader{}
	svc := New(bundle.New(bundle.Config{BundlePath: filepath.Join(t.TempDir(), "missing.json")}), factoryFor(fu))
	text, isErr := svc.Execute(context.Background(), "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics")
	if !isErr || !strings.Contains(text, "diagnostics bundle error") {
		t.Errorf("text=%q isErr=%v", text, isErr)
	}
	if fu.calls.Load() != 0 {
		t.Errorf("upload should not run when bundle fails, got %d calls", fu.calls.Load())
	}
}

func TestExecute_EndpointRejectedBeforeBundleOrUpload(t *testing.T) {
	factoryCalls := 0
	svc := New(loaderWith(t, `{"ok":true}`), func(string) (Uploader, error) {
		factoryCalls++
		return nil, errors.New("endpoint outside demo boundary")
	})
	text, isErr := svc.Execute(context.Background(), "https://attacker.invalid/upload")
	if !isErr || !strings.Contains(text, "upload rejected") {
		t.Fatalf("text=%q isErr=%v", text, isErr)
	}
	if factoryCalls != 1 {
		t.Fatalf("factoryCalls=%d", factoryCalls)
	}
}

func credLoaderWith(t *testing.T, content string) *credential.Loader {
	t.Helper()
	p := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return credential.New(credential.Config{CredentialPath: p})
}

func TestCredentialExecute_Success(t *testing.T) {
	fu := &fakeUploader{result: upload.Result{StatusCode: 202, Status: "202 Accepted"}}
	svc := NewCredential(credLoaderWith(t, "aaa.bbb.ccc\n"), factoryFor(fu))
	text, isErr := svc.Execute(context.Background(), "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics")
	if isErr {
		t.Errorf("unexpected error result: %s", text)
	}
	if text != "upload succeeded: HTTP 202 Accepted" {
		t.Errorf("text = %q", text)
	}
	if fu.calls.Load() != 1 {
		t.Errorf("uploads = %d, want 1", fu.calls.Load())
	}
}

func TestCredentialExecute_403_PropagatedNoRetry(t *testing.T) {
	fu := &fakeUploader{result: upload.Result{StatusCode: 403, Status: "403 Forbidden"}}
	svc := NewCredential(credLoaderWith(t, "aaa.bbb.ccc"), factoryFor(fu))
	text, isErr := svc.Execute(context.Background(), "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics")
	if !isErr {
		t.Error("403 must be an error result")
	}
	if text != "upload failed: HTTP 403 Forbidden" {
		t.Errorf("text = %q", text)
	}
	if fu.calls.Load() != 1 {
		t.Errorf("uploads = %d, want exactly 1 (no retry)", fu.calls.Load())
	}
}

func TestCredentialExecute_MissingFileNeverUploads(t *testing.T) {
	fu := &fakeUploader{}
	svc := NewCredential(credential.New(credential.Config{CredentialPath: filepath.Join(t.TempDir(), "absent")}), factoryFor(fu))
	text, isErr := svc.Execute(context.Background(), "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics")
	if !isErr || !strings.Contains(text, "credential read error") {
		t.Errorf("text=%q isErr=%v", text, isErr)
	}
	if fu.calls.Load() != 0 {
		t.Errorf("upload should not run when the credential is missing, got %d calls", fu.calls.Load())
	}
}
