## Description

Briefly describe what this PR changes and why it is necessary.

## Related tasks

- Closes issue: # (issue number)
- Audit roadmap task ID: (e.g. T-09)

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring (no functional change)
- [ ] Documentation update
- [ ] CI / build / tooling change
- [ ] Security fix

## Enterprise Readiness checklist

Complete every applicable item before requesting review.

**Build & tests**
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes with no new warnings
- [ ] `cargo test` passes in full
- [ ] New or updated tests cover the changed behaviour
- [ ] Overall test coverage is not reduced by this PR

**Security-critical paths**
- [ ] Changes to `src/crypto.rs`, `src/chain.rs`, `src/auth.rs`, or `src/engine.rs` have been flagged to @AuraIDToken prior to submission (CODEOWNERS will auto-request review)
- [ ] No secrets, keys, or credentials are introduced into source or configuration files
- [ ] Any new dependency has been checked with `cargo audit` and `cargo deny`

**Documentation**
- [ ] Inline documentation updated for any public API or complex algorithm change
- [ ] `docs/` updated if behaviour, configuration, or exit codes changed
- [ ] `openapi.yaml` updated if HTTP API surface changed

**Compliance & audit**
- [ ] Audit log format is unchanged, or the change is documented in an ADR
- [ ] Policy signing workflow is unaffected, or changes are covered by a new signed policy

## Notes for reviewers

(Optional — highlight anything that deserves particular attention during review.)
