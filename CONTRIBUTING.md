# Contributing

Thank you for considering a contribution. By participating you agree to abide
by our [Code of Conduct](https://www.contributor-covenant.org/).

## Development environment

* Rust 1.86+ (stable).
* `pre-commit` (optional) for local hook runs.
* Docker (optional) for the distroless image.

## Toolchain quick-start

```bash
rustup update stable
cargo install --locked cargo-deny cargo-audit cargo-cyclonedx
./scripts/setup.sh
```

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

## Pull requests

1. Open a draft PR for early review.
2. Run `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all-targets` locally.
3. Update `CHANGELOG.md` under the relevant version heading.
4. Squash to logical commits before requesting review.

## Security

Do not file security issues publicly — see [SECURITY.md](SECURITY.md).
