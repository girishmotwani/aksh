package main

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/injector"
)

// TestStaticTokenSecretKeyDefault confirms the static-token secret key flag
// defaults to "token" (the fixed on-disk filename the proxy reads), matching
// the Helm chart default.
func TestStaticTokenSecretKeyDefault(t *testing.T) {
	t.Setenv("AKSH_INJECTOR_STATIC_TOKEN_SECRET_KEY", "")
	if got := envOrDefault("AKSH_INJECTOR_STATIC_TOKEN_SECRET_KEY", "token"); got != "token" {
		t.Fatalf("static token key default = %q, want token", got)
	}
}

// TestStaticTokenProfile_ConstructorAcceptance ties the CLI/env wiring to the
// injector contract: a configured static-token Secret with the default key is
// accepted, and a secret name without a key is rejected fail-closed.
func TestStaticTokenProfile_ConstructorAcceptance(t *testing.T) {
	base := injector.InjectorOptions{
		ProxyImage:       "aksh-proxy:test",
		ReservedUID:      1774,
		ReservedGID:      1774,
		OptInLabelKey:    "aksh.dev/inject",
		OptInLabelValue:  "enabled",
		InjectionVersion: "v1",
	}

	valid := base
	valid.RuntimeProfile = injector.RuntimeProfile{
		StaticTokenSecretName: "aksh-model-credentials",
		StaticTokenSecretKey:  envOrDefault("AKSH_INJECTOR_STATIC_TOKEN_SECRET_KEY", "token"),
	}
	if _, err := injector.NewSidecarInjector(valid); err != nil {
		t.Fatalf("valid static token profile rejected: %v", err)
	}

	missingKey := base
	missingKey.RuntimeProfile = injector.RuntimeProfile{StaticTokenSecretName: "aksh-model-credentials"}
	if _, err := injector.NewSidecarInjector(missingKey); err == nil {
		t.Fatal("static token secret name without a key must be rejected")
	}
}
