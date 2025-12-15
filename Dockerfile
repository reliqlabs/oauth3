# Multi-stage Dockerfile for building and running the oauth3 server (Axum + Diesel)
# - Build stage compiles with the `pg` feature and links against libpq
# - Runtime stage contains only the binary and the libpq runtime

# Use latest stable Rust toolchain
FROM rust:1.92-bullseye AS builder

# Install system dependencies for linking to Postgres (libpq)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libpq-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Ensure pq-sys (Diesel) can locate libpq via pkg-config on Debian
ENV PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig
ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu
ENV LIBRARY_PATH=/usr/lib/x86_64-linux-gnu

WORKDIR /app

# Copy toolchain file early so the correct rust/cargo are used during caching
COPY rust-toolchain.toml ./

# Show toolchain versions for diagnostics
RUN rustc --version && cargo --version

# Install diesel_cli for migrations
RUN cargo install diesel_cli --no-default-features --features postgres

# Create a dummy build to cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --no-default-features --features pg || true

# Copy actual source and build
COPY . .

# Quick sanity: ensure libpq is discoverable (will print flags or fail)
RUN pkg-config --libs libpq
# Print the exact dependency feature lines seen by the builder
RUN echo "== Cargo.toml (openidconnect/oauth2 lines) ==" && \
    grep -nE '^(openidconnect|oauth2)\s*=.*' Cargo.toml || true
RUN cargo build --release --no-default-features --features pg

FROM debian:bullseye-slim AS runtime

# Install libpq runtime and CA certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/oauth3 /usr/local/bin/oauth3
COPY --from=builder /usr/local/cargo/bin/diesel /usr/local/bin/diesel
COPY migrations ./migrations
COPY diesel.toml ./diesel.toml

# Non-root user (optional)
RUN useradd -m -u 10001 appuser && \
    mkdir -p /app/src && \
    chown -R appuser:appuser /app
USER appuser

# Default environment (can be overridden by Compose)
ENV APP_BIND_ADDR=0.0.0.0:8080 \
    APP_PUBLIC_URL=http://localhost:8080

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/oauth3"]
