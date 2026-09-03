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
    cargo fmt --manifest-path example_no_std/Cargo.toml -- --check
    cargo clippy --all-targets -- -D warnings

# Compile the no_std fixture for a bare-metal target.
no-std-target target:
    cargo build --manifest-path example_no_std/Cargo.toml --release --target {{target}}

# Verify Hatchet and the example without std.
no-std:
    cargo check --no-default-features
    cargo test --manifest-path example_no_std/Cargo.toml --lib
    just no-std-target thumbv7em-none-eabihf
    just no-std-target thumbv6m-none-eabi

# Build and test the WebAssembly fixture.
wasm:
    cd example_wasm && wasm-pack build --target web
    cd example_wasm && wasm-pack test --node

# Build and host the WebAssembly example at http://127.0.0.1:<port>.
wasm-serve port="8000":
    cd example_wasm && wasm-pack build --target web
    cd example_wasm && python3 -m http.server {{port}} --bind 127.0.0.1

# Run all checks required by CI.
ci: build test lint no-std wasm

# Generate the Codecov JSON report.
coverage:
    cargo llvm-cov --codecov --output-path codecov.json
