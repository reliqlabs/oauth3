# Reproducible build using Nix with minimal runtime
FROM nixos/nix:2.26.3 AS builder

# Enable flakes
RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf

WORKDIR /build

# Copy source
COPY . .

# Build the application using Nix
RUN nix build .#oauth3 --no-link --print-out-paths > /tmp/out-path

# Get all runtime dependencies (closure)
RUN nix-store -qR $(cat /tmp/out-path) > /tmp/closure-paths

# Create a minimal root with only runtime dependencies
RUN mkdir -p /tmp/minimal-root/nix/store && \
    cat /tmp/closure-paths | xargs -I {} cp -r {} /tmp/minimal-root/nix/store/

# Minimal runtime - Debian slim base with only Nix closure
FROM debian:bullseye-slim

# Copy only the Nix store paths needed at runtime
COPY --from=builder /tmp/minimal-root/nix /nix

# Copy binary path for easy access
COPY --from=builder /tmp/out-path /tmp/out-path

# Copy migrations
COPY --from=builder /build/migrations /app/migrations
COPY --from=builder /build/diesel.toml /app/diesel.toml

# Install only essential runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create nobody user
RUN useradd -u 65534 -r -s /bin/false nobody || true

USER nobody

EXPOSE 8080

# Run the binary from its Nix store path
CMD ["sh", "-c", "$(cat /tmp/out-path)/bin/oauth3"]
