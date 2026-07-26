# Contributing

Thank you for considering a contribution. By participating you agree to abide
by our [Code of Conduct](https://www.contributor-covenant.org/).

## Development environment

* Rust 1.86+ (stable).
* `jq` for `./scripts/test.sh`.
* Docker (optional) for the distroless image.

## Toolchain quick-start

```bash
rustup update stable
cargo install --locked cargo-deny cargo-audit cargo-cyclonedx
./scripts/setup.sh
```

`cargo-deny`, `cargo-audit`, and `cargo-cyclonedx` are only needed if you want
to reproduce the full CI supply-chain checks locally.

## Style

* `cargo fmt --all`.
* `cargo clippy --all-targets --all-features -- -D warnings`.
* No `unsafe` code (the crate forbids it).
* No `unwrap` / `expect` / `panic` outside of tests, code-generated wrappers,
  or genuinely unreachable paths.
* Documentation comments on all public items.

## Test discipline

* Add a `golden` test in `tests/golden.rs` for every new policy rule.
* Add a chain regression test in `tests/integration.rs` for any change that
  touches `chain.rs`, `log_writer.rs`, or the entry schema.
* Update `docs/openapi.yaml` for any API change.

### Local validation

For production-code changes, match the current CI workflow as closely as
practical:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --locked --release --all-targets
cargo test --locked --all-targets
```

For documentation-only changes, skip Rust validation unless your edits depend
on behavior you also changed in code.

## Pull requests

1. Open a draft PR early if the scope is still moving.
2. Run the relevant validation for your change type before requesting review.
3. Update `CHANGELOG.md` when user-facing behavior, security posture, CLI
   flags, or operator workflows change.
4. Keep commits logical; reviewers rely on history when auditing policy and
   security changes.

## Security

Do not file security issues publicly — see [SECURITY.md](SECURITY.md).

## Documentation sync checklist

When behavior, CLI flags, exit codes, or security posture changes, update docs
in the same PR:

* `README.md` (operator-facing defaults, endpoints, CLI examples)
* `CONTRIBUTING.md` (developer workflow and validation commands)
* `SECURITY.md` (supported versions, disclosure/SBOM posture)
* `docs/adrs/*.md` (status/wording updates; do not rewrite accepted decisions)
* `docs/exit-codes.md`, `docs/deployment.md`, and `docs/ROADMAP.md` when the
  change affects operator runbooks or release status
* `docs/ARCHITECTURE.md` or `docs/THREAT_MODEL.md` when the trust boundary or
  evidence model changes
