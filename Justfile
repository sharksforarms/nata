set shell := ["bash", "-euc"]

stable := env_var_or_default("NATA_STABLE_TOOLCHAIN", "stable")
msrv := env_var_or_default("NATA_MSRV_TOOLCHAIN", "1.88.0")
beta := env_var_or_default("NATA_BETA_TOOLCHAIN", "beta")
nightly := env_var_or_default("NATA_NIGHTLY_TOOLCHAIN", "nightly")
pipeline := env_var_or_default("NATA_TOOLCHAIN", "stable")
toolchain := if pipeline == "msrv" { msrv } else if pipeline == "stable" { stable } else if pipeline == "beta" { beta } else { pipeline }

# Feature combinations exercised by the test and coverage matrix.
feature_matrix := "std libpcap std,libpcap"
wireshark_repo := env_var_or_default("NATA_WIRESHARK_REPO", "https://gitlab.com/wireshark/wireshark.git")
wireshark_revision := env_var_or_default("NATA_WIRESHARK_REVISION", "4f63ea0eae68cf6facea31604994f1a339e43640")
tshark_manifest := "nata-tshark/Cargo.toml"

default:
    @just --list

build:
    cargo +{{toolchain}} build --workspace --all-targets

examples:
    cargo +{{toolchain}} build --examples --features libpcap

test:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo +{{toolchain}} test -p nata --all-targets
    cargo +{{toolchain}} test -p nata --no-default-features --all-targets
    for features in {{feature_matrix}}; do
        cargo +{{toolchain}} test -p nata --no-default-features --features="${features}" --all-targets
    done
    cargo +{{toolchain}} test -p nata-tshark --all-targets
    just tshark-test

tshark-test capture="" wireshark_dir="":
    #!/usr/bin/env bash
    set -euo pipefail

    local_dir={{ quote(wireshark_dir) }}
    if [ -n "$local_dir" ] && [ -n "${NATA_WIRESHARK_DIR:-}" ]; then
        echo "provide the Wireshark checkout either as a recipe argument or NATA_WIRESHARK_DIR, not both" >&2
        exit 2
    fi

    if [ -n "$local_dir" ]; then
        corpus_dir="$local_dir"
        local_checkout=true
    elif [ -n "${NATA_WIRESHARK_DIR:-}" ]; then
        corpus_dir="$NATA_WIRESHARK_DIR"
        local_checkout=true
    else
        corpus_dir="target/wireshark-tests/{{wireshark_revision}}"
        local_checkout=false
        if ! git -C "$corpus_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            if [ -e "$corpus_dir" ]; then
                echo "Wireshark corpus path exists but is not a git checkout: $corpus_dir" >&2
                exit 2
            fi
            mkdir -p "$(dirname "$corpus_dir")"
            git clone --depth 1 --filter=blob:none --no-tags --sparse \
                "{{wireshark_repo}}" "$corpus_dir"
            git -C "$corpus_dir" sparse-checkout set test/captures
        fi
    fi

    if ! git -C "$corpus_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "Wireshark directory is not a git checkout: $corpus_dir" >&2
        exit 2
    fi

    if [ "$local_checkout" = false ]; then
        checked_out_revision=$(git -C "$corpus_dir" rev-parse HEAD)
        if [ "$checked_out_revision" != "{{wireshark_revision}}" ]; then
            git -C "$corpus_dir" fetch --depth 1 origin "{{wireshark_revision}}"
            git -C "$corpus_dir" checkout --detach "{{wireshark_revision}}"
        fi
    fi

    if [ ! -d "$corpus_dir/test/captures" ]; then
        echo "Wireshark checkout has no test/captures directory: $corpus_dir" >&2
        exit 2
    fi

    capture_name={{ quote(capture) }}
    if [ -n "$capture_name" ]; then
        cargo +{{toolchain}} run --manifest-path "{{tshark_manifest}}" -- compare \
            "$corpus_dir" "$capture_name"
    else
        cargo +{{toolchain}} run --manifest-path "{{tshark_manifest}}" -- suite \
            "$corpus_dir" nata-tshark/tests/wireshark_expectations.txt
    fi

lint:
    cargo +{{stable}} fmt --all -- --check
    cargo +{{stable}} fmt --manifest-path example_no_std/Cargo.toml -- --check
    cargo +{{stable}} fmt --manifest-path example_wasm/Cargo.toml -- --check
    cargo +{{stable}} clippy -p nata --all-targets -- -D warnings
    cargo +{{stable}} clippy -p nata --no-default-features --all-targets -- -D warnings
    cargo +{{stable}} clippy -p nata --no-default-features --features="std,libpcap" --all-targets -- -D warnings
    cargo +{{stable}} clippy --manifest-path {{tshark_manifest}} --all-targets -- -D warnings
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
