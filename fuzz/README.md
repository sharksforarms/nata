# Fuzzing

Install nightly Rust and `cargo-fuzz`, then run a target from the repository root:

```sh
just fuzz
just fuzz fuzz_ipv4
just fuzz fuzz_tcp 60
```

The default target is `fuzz_tcp`; an optional duration limits a run in seconds.

## Coverage

Example to retrieve coverage

```
cargo +nightly fuzz run fuzz_tcp
cargo +nightly fuzz coverage fuzz_tcp
llvm-cov show -format=html -output-dir=cov/ -instr-profile=./coverage/fuzz_tcp/coverage.profdata target/x86_64-unknown-linux-gnu/release/fuzz_tcp
firefox cov/index.html
```
