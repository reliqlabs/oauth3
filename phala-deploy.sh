#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env.phala}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Error: Environment file not found: $ENV_FILE"
  echo "Usage: $0 [env-file]"
  echo "Example: $0 .env.phala"
  exit 1
fi

echo "Reading environment from: $ENV_FILE"

# Source the env file
set -a
source "$ENV_FILE"
set +a

# Required variables
REQUIRED_VARS=(
  "DOCKER_IMAGE"
  "POSTGRES_PASSWORD"
  "APP_PUBLIC_URL"
  "COOKIE_KEY_BASE64"
)

# Check required variables
for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "Error: Required variable $var is not set in $ENV_FILE"
    exit 1
  fi
done

# Optional variables with defaults
TEEPOD_ID="${TEEPOD_ID:-}"
CVM_NAME="${CVM_NAME:-oauth3-prod}"
VCPU="${VCPU:-2}"
MEMORY="${MEMORY:-4096}"
DISK_SIZE="${DISK_SIZE:-60}"
DSTACK_IMAGE="${DSTACK_IMAGE:-dstack-dev-0.3.5}"

# Build env args for phala command
ENV_ARGS=()
while IFS='=' read -r key value; do
  # Skip comments and empty lines
  [[ "$key" =~ ^#.*$ ]] && continue
  [[ -z "$key" ]] && continue

  # Expand variable if it starts with $
  if [[ "$value" =~ ^\$\{?([A-Z_]+)\}?$ ]]; then
    var_name="${BASH_REMATCH[1]}"
    value="${!var_name:-}"
  fi

  # Add to env args
  ENV_ARGS+=("-e" "${key}=${value}")
done < "$ENV_FILE"

# Build the command
CMD=(
  phala cvms create
  --name "$CVM_NAME"
  --compose ./docker-compose.phala.yml
  --vcpu "$VCPU"
  --memory "$MEMORY"
  --diskSize "$DISK_SIZE"
  --image "$DSTACK_IMAGE"
)

# Add teepod if specified
if [[ -n "$TEEPOD_ID" ]]; then
  CMD+=(--teepod-id "$TEEPOD_ID")
fi

# Add all environment variables
CMD+=("${ENV_ARGS[@]}")

# Print the command
echo ""
echo "Running deployment command:"
echo "${CMD[@]}"
echo ""

# Confirm before running
read -p "Deploy to Phala? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Deployment cancelled"
  exit 0
fi

# Execute
"${CMD[@]}"
