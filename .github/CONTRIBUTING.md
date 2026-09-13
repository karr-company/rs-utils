# Contributing to rs-utils

Thanks for contributing to `rs-utils`!

This document describes the development workflow, dependency updates, testing expectations, and pull request process.

## Prerequisites

Install a current stable Rust toolchain using [rustup](<https://rustup.rs/>).

Verify that Rust and Cargo are available:

```
rustc --version
cargo --version
```

Clone the repository and create a branch for your change:

```
git clone https://github.com/karr-company/rs-utils.git
cd rs-utils
git checkout -b feature/my-change
```

## Development workflow

Before making changes, make sure the existing project builds and tests successfully:

```
cargo check
cargo test
```

Format Rust code with:

```
cargo fmt
```

Check formatting without modifying files:

```
cargo fmt -- --check
```

Run Clippy:

```
cargo clippy --all-targets --all-features -- -D warnings
```

For a normal code change, please run at least:

```
cargo fmt -- --check
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Fix any failures before opening a pull request.

## Making changes

Keep changes focused and easy to review.

When changing behaviour:

- Add or update tests where appropriate.
- Keep public APIs backwards-compatible unless a breaking change is intentional.
- Update documentation when user-facing behaviour changes.
- Avoid unrelated formatting or refactoring changes in the same pull request.

For larger changes, open an issue or discuss the proposed approach before investing significant implementation effort.

## Dependency updates

Dependency versions are specified in `Cargo.toml`. Cargo resolves those requirements and records the selected versions in `Cargo.lock`.

For quick dependency requirement updates, use [`cargo-edit`](<https://crates.io/crates/cargo-edit>).

### Install cargo-edit

Install the latest `cargo-edit` from crates.io:

```
cargo install cargo-edit
```

Verify the installation:

```
cargo upgrade --help
```

`cargo-edit` provides the `cargo upgrade` command for updating dependency version requirements in `Cargo.toml`.

> **Note:** Modern Cargo already provides `cargo add` and `cargo rm`, so `cargo-edit` is primarily useful here for its `cargo upgrade` functionality.

### Check available dependency upgrades

From the repository root, run:

```
cargo upgrade --dry-run
```

This shows the changes that would be made without modifying `Cargo.toml`.

Review the proposed changes carefully before applying them.

### Upgrade dependencies

To update compatible dependency requirements:

```
cargo upgrade
```

You can also upgrade a specific dependency:

```
cargo upgrade -p serde
```

Or specify an explicit version requirement:

```
cargo upgrade -p serde@1.0
```

### Upgrade incompatible versions deliberately

By default, `cargo upgrade` prefers compatible updates. Incompatible updates should be considered separately because they may require source changes.

To allow incompatible upgrades:

```
cargo upgrade --incompatible
```

Do not use this blindly for all dependencies. Review each major-version change and consult the dependency's release notes when necessary.

### Update the lockfile

`cargo upgrade` changes dependency requirements in `Cargo.toml`.

This is different from:

```
cargo update
```

`cargo update` updates the versions selected in `Cargo.lock` without necessarily changing the version requirements in `Cargo.toml`.

After changing dependency requirements, run:

```
cargo check
cargo test
```

If necessary, update the lockfile explicitly:

```
cargo update
```

Review both `Cargo.toml` and `Cargo.lock` before committing.

### Recommended dependency-update workflow

For a routine dependency update:

```
# Check the current state
cargo check
cargo test

# Preview dependency requirement changes
cargo upgrade --dry-run

# Apply compatible dependency upgrades
cargo upgrade

# Resolve and verify dependencies
cargo check
cargo test

# Check formatting and lints
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Review the resulting diff:

```
git diff -- Cargo.toml Cargo.lock
```

Keep dependency-update pull requests focused. If an upgrade requires source changes, include those changes and explain the reason in the pull request description.

## Tests

Run the complete test suite before submitting a pull request:

```
cargo test
```

When working on a particular area, you can run a narrower set of tests during development, but run the complete suite before submitting.

New functionality should normally include tests covering the new behaviour.

## Formatting and linting

Use `rustfmt` to format Rust code:

```
cargo fmt
```

Check formatting in CI-compatible mode:

```
cargo fmt -- --check
```

Run Clippy with warnings treated as errors:

```
cargo clippy --all-targets --all-features -- -D warnings
```

Please do not submit code that introduces new compiler or Clippy warnings.

## Commit messages

Use concise commit messages that describe the intent of the change.

Examples:

```
fix: handle empty input
feat: add vehicle validation
docs: improve validation examples
refactor: simplify rule matching
test: cover invalid vehicle identifiers
chore: update dependencies
```

Keep commits focused where practical.

## Pull requests

Before opening a pull request:

1. Rebase or update your branch against the current `main` branch.
2. Review your changes with `git diff`.
3. Run formatting checks.
4. Run tests.
5. Run Clippy.
6. Make sure dependency changes are intentional.
7. Provide a clear description of what changed and why.

A typical final verification is:

```
cargo fmt -- --check
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Pull requests should be small and focused whenever possible.

## Releases

Releases are automated through GitHub Actions.

Contributors should **not** manually create release tags or GitHub Releases.

The release workflow creates GitHub releases from the repository's automated release process. Dependency or source changes should therefore be submitted through normal pull requests rather than by manually modifying release metadata.

## Questions and issues

If you find a bug or have an idea for an improvement, open an issue in the repository:

https://github.com/karr-company/rs-utils/issues

For substantial changes, discussing the approach before implementation can help avoid unnecessary work.