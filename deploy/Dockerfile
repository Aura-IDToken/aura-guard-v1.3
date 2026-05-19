# syntax=docker/dockerfile:1.7
# ─── builder ─────────────────────────────────────────────────────────────
FROM rust:1.86-slim-bookworm AS builder

ARG TARGET=x86_64-unknown-linux-gnu

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Pre-fetch deps for better layer caching.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs && \
    cargo build --release --locked || true

# Build the real binaries.
COPY . .
RUN cargo build --release --locked --bins

# ─── runtime ─────────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app
COPY --from=builder /build/target/release/aura-guard         /app/aura-guard
COPY --from=builder /build/target/release/aura-replay        /app/aura-replay
COPY --from=builder /build/target/release/aura-sign-policy   /app/aura-sign-policy

# Policies and logs are bind-mounted at runtime.
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/aura-guard"]
