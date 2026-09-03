set shell := ["bash", "-euc"]

# List the available commands.
default:
    @just --list

# Compile every target.
build:
    cargo build --all-targets

# Run the complete test suite.
test:
    cargo test --all-targets

# Check formatting and lint every target.
lint:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings

# Verify Hatchet without its default std-backed features.
no-std:
    cargo check --no-default-features
    cargo run --manifest-path example_no_std/Cargo.toml --release

# Build and test the WebAssembly fixture.
wasm:
    cd example_wasm && wasm-pack build --target web
    cd example_wasm && wasm-pack test --node

# Run all checks required by CI.
ci: build test lint no-std wasm

# Generate the Codecov JSON report.
coverage:
    cargo llvm-cov --codecov --output-path codecov.json
