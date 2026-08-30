# Phase 4 Follow-ups from Phase 3 Code Review

These items were identified during Phase 3's multi-model code review and deferred
because they are integration-level concerns that become relevant when the cache is
wired into the enforcement pipeline.

## Must address in Phase 4

1. **Cache must integrate breaker + negative cache in its Get path**
   - S3 §4 state machine: valid-token-serves-first, then gates apply in order:
     negative cache → breaker → capacity/timeout → single-flight
   - Commit failure state BEFORE releasing waiters

2. **Background refresh needs acquisition timeout (10s) and shutdown context**
   - Without it, a stuck provider permanently leaks a goroutine
   - Use cache lifecycle context + 10s timeout per S3 §8

3. **Consolidate credential identity implementations**
   - `CredentialSelector.Identity()` uses old delimiter-based formula
   - `Resolve()` → `resolvedIdentity()` uses the correct S2 §2.3 LP formula
   - Remove or delegate the legacy method

4. **Add refresh jitter (±10%)**
   - S3 §4 requires it to prevent thundering herd across replicas
   - Sample once per acquisition, against usable lifetime

5. **Prevent stale background refresh overwriting newer foreground acquisition**
   - Store conditionally: only replace if new token has later `usableUntil`
