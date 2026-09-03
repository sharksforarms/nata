set shell := ["bash", "-euc"]

stable := env_var_or_default("NATA_STABLE_TOOLCHAIN", "stable")
msrv := env_var_or_default("NATA_MSRV_TOOLCHAIN", "1.88.0")
beta := env_var_or_default("NATA_BETA_TOOLCHAIN", "beta")
pipeline := env_var_or_default("NATA_TOOLCHAIN", "stable")
toolchain := if pipeline == "msrv" { msrv } else if pipeline == "stable" { stable } else if pipeline == "beta" { beta } else { pipeline }

# Portable feature combinations; netmap needs platform-specific headers.
feature_matrix := "std libpcap std,libpcap"

# List the available build commands.
default:
    @just --list

# Compile the root crate, examples, tests, and benchmark harness.
build:
    cargo +{{toolchain}} build --all-targets

# Run the test matrix used by CI.
test:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo +{{toolchain}} test --all-targets
    cargo +{{toolchain}} test --no-default-features --all-targets
    for features in {{feature_matrix}}; do
        cargo +{{toolchain}} test --no-default-features --features="${features}" --all-targets
    done

# Check formatting and lint every target with stable Rust.
lint:
    cargo +{{stable}} fmt --all -- --check
    cargo +{{stable}} fmt --manifest-path example_no_std/Cargo.toml -- --check
    cargo +{{stable}} fmt --manifest-path example_wasm/Cargo.toml -- --check
    cargo +{{stable}} clippy --all-targets -- -D warnings
    cargo +{{stable}} clippy --no-default-features --all-targets -- -D warnings
    cargo +{{stable}} clippy --no-default-features --features="std,libpcap" --all-targets -- -D warnings
    cargo +{{stable}} clippy --manifest-path example_no_std/Cargo.toml --lib -- -D warnings
    cargo +{{stable}} clippy --manifest-path example_wasm/Cargo.toml --lib -- -D warnings

# Compile the no_std fixture for a target.
no-std target:
    cargo +{{toolchain}} build --manifest-path example_no_std/Cargo.toml --release --target {{target}}

# Run the thumbv7em no_std checks.
no-std-v7:
    just no-std thumbv7em-none-eabihf

# Run the thumbv6m no_std checks.
no-std-v6:
    just no-std thumbv6m-none-eabi

# Build and test the WebAssembly fixture.
wasm:
    cd example_wasm && RUSTUP_TOOLCHAIN={{toolchain}} wasm-pack build --target web
    cd example_wasm && RUSTUP_TOOLCHAIN={{toolchain}} wasm-pack test --node

# Run the build, test, no_std, and WebAssembly checks for the selected toolchain.
ci: build test no-std-v7 no-std-v6 wasm

# Run the complete CI pipeline with the MSRV toolchain.
ci-msrv:
    NATA_TOOLCHAIN=msrv just ci

# Run the complete CI pipeline with stable Rust.
ci-stable:
    NATA_TOOLCHAIN=stable just ci

# Run formatting and Clippy checks with stable Rust.
ci-lint:
    NATA_TOOLCHAIN=stable just lint

# Run the complete CI pipeline with beta Rust.
ci-beta:
    NATA_TOOLCHAIN=beta just ci

# Generate one Codecov JSON report from the feature test matrix.
coverage:
    #!/usr/bin/env bash
    set -euo pipefail

    # Discard stale execution data while retaining instrumented build artifacts.
    cargo +{{stable}} llvm-cov clean --profraw-only

    cargo +{{stable}} llvm-cov --no-report
    cargo +{{stable}} llvm-cov --no-default-features --no-report
    for features in {{feature_matrix}}; do
        cargo +{{stable}} llvm-cov --no-default-features --features="${features}" --no-report
    done

    cargo +{{stable}} llvm-cov report --codecov --output-path codecov.json

# Run the Criterion benchmarks.
bench:
    cargo +{{toolchain}} bench --bench bench_layers
