// Self-contained module for the AgentCon Japan demo telemetry collector.
//
// It is intentionally its own module (separate from the repository root) so the
// demo builds with only the Go standard library, changes no root dependencies,
// and produces a tiny statically linked image. A nested go.mod is excluded from
// the root module's ./... so it cannot perturb the main build or CI.
module github.com/girishmotwani/aksh/demo/agentcon-japan/collector

go 1.26.0
