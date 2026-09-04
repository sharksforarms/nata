set shell := ["bash", "-euc"]

stable := env_var_or_default("NATA_STABLE_TOOLCHAIN", "stable")
msrv := env_var_or_default("NATA_MSRV_TOOLCHAIN", "1.88.0")
beta := env_var_or_default("NATA_BETA_TOOLCHAIN", "beta")
nightly := env_var_or_default("NATA_NIGHTLY_TOOLCHAIN", "nightly")
pipeline := env_var_or_default("NATA_TOOLCHAIN", "stable")
toolchain := if pipeline == "msrv" { msrv } else if pipeline == "stable" { stable } else if pipeline == "beta" { beta } else { pipeline }

# Feature combinations exercised by the test and coverage matrix.
feature_matrix := "std libpcap std,libpcap"

default:
    @just --list

build:
    cargo +{{toolchain}} build --all-targets

examples:
    cargo +{{toolchain}} build --examples --features libpcap

test:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo +{{toolchain}} test --all-targets
    cargo +{{toolchain}} test --no-default-features --all-targets
    for features in {{feature_matrix}}; do
        cargo +{{toolchain}} test --no-default-features --features="${features}" --all-targets
    done

lint:
    cargo +{{stable}} fmt --all -- --check
    cargo +{{stable}} fmt --manifest-path example_no_std/Cargo.toml -- --check
    cargo +{{stable}} fmt --manifest-path example_wasm/Cargo.toml -- --check
    cargo +{{stable}} clippy --all-targets -- -D warnings
    cargo +{{stable}} clippy --no-default-features --all-targets -- -D warnings
    cargo +{{stable}} clippy --no-default-features --features="std,libpcap" --all-targets -- -D warnings
    cargo +{{stable}} clippy --manifest-path example_no_std/Cargo.toml --lib -- -D warnings
    cargo +{{stable}} clippy --manifest-path example_wasm/Cargo.toml --lib -- -D warnings

no-std target:
    cargo +{{toolchain}} build --manifest-path example_no_std/Cargo.toml --release --target {{target}}

no-std-v7:
    just no-std thumbv7em-none-eabihf

no-std-v6:
    just no-std thumbv6m-none-eabi

wasm:
    cd example_wasm && RUSTUP_TOOLCHAIN={{toolchain}} wasm-pack build --target web
    cd example_wasm && RUSTUP_TOOLCHAIN={{toolchain}} wasm-pack test --node

ci: build test examples no-std-v7 no-std-v6 wasm

ci-msrv:
    NATA_TOOLCHAIN=msrv just ci

ci-stable:
    NATA_TOOLCHAIN=stable just ci

ci-lint:
    NATA_TOOLCHAIN=stable just lint

ci-beta:
    NATA_TOOLCHAIN=beta just ci

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

bench:
    cargo +{{toolchain}} bench --bench bench_layers

fuzz target="fuzz_tcp" max_time="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{max_time}}" ]; then
        cargo +{{nightly}} fuzz run {{target}} -- -max_total_time={{max_time}}
    else
        cargo +{{nightly}} fuzz run {{target}}
    fi
