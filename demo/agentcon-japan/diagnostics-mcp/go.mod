// Self-contained module for the AgentCon Japan diagnostics MCP demo.
//
// It is deliberately a *separate* module from the repository root so the demo
// can be built and pinned independently and never perturbs the aksh-proxy
// module. It has no third-party dependencies: everything is the Go standard
// library, which is the strongest possible form of "pinned dependencies" — the
// only version that can move is the toolchain, pinned below.
module github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp

go 1.26.0
