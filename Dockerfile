# syntax=docker/dockerfile:1.7

FROM node:24-bookworm-slim AS node-runtime

FROM rust:1.98-bookworm

ARG JUST_VERSION=1.58.0
ARG WASM_PACK_VERSION=0.15.0
ARG CARGO_LLVM_COV_VERSION=0.8.7

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        libpcap-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy rustfmt llvm-tools-preview \
    && rustup target add \
        thumbv7em-none-eabihf \
        thumbv6m-none-eabi \
        wasm32-unknown-unknown

RUN --mount=type=cache,id=hatchet-tools-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=hatchet-tools-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=hatchet-tools-target,target=/tmp/cargo-target,sharing=locked \
    export CARGO_TARGET_DIR=/tmp/cargo-target \
    && cargo install just --version "${JUST_VERSION}" --locked \
    && cargo install wasm-pack --version "${WASM_PACK_VERSION}" --locked \
    && cargo install cargo-llvm-cov --version "${CARGO_LLVM_COV_VERSION}" --locked

WORKDIR /workspace

ENV CARGO_HOME=/usr/local/cargo \
    CARGO_TARGET_DIR=/workspace/target \
    CARGO_TERM_COLOR=always

CMD ["sleep", "infinity"]
