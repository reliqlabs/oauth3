#!/usr/bin/env bash
set -euo pipefail

# Parse arguments
ENV_FILE="${1:-.env.phala}"
APP_ID="${2:-}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Error: Environment file not found: $ENV_FILE"
  echo "Usage: $0 [env-file] [app-id]"
  echo "Example: $0 .env.phala"
  echo "Example: $0 .env.phala my-app-123"
  exit 1
fi

echo "Reading environment from: $ENV_FILE"

# Parse env file and build list of variables defined in it
declare -A ENV_VARS
while IFS= read -r line; do
  # Skip comments and empty lines
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  [[ "$line" =~ ^[[:space:]]*$ ]] && continue

  # Remove 'export ' prefix if present
  line="${line#export }"

  # Extract variable name
  if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]]; then
    var_name="${BASH_REMATCH[1]}"
    ENV_VARS[$var_name]=1
  fi
done < "$ENV_FILE"

# Now source the file to get actual values
set -a
source "$ENV_FILE"
set +a

# Apply defaults for variables that may not be set
: "${POSTGRES_PASSWORD:=postgres}"

# Check critical variables (no sensible defaults)
REQUIRED_VARS=(
  "DOCKER_IMAGE"
  "COOKIE_KEY_BASE64"
)

for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "Error: Required variable $var is not set in $ENV_FILE"
    exit 1
  fi
done

# Warn if APP_PUBLIC_URL is not set (needed for OAuth callbacks)
if [[ -z "${APP_PUBLIC_URL:-}" ]]; then
  echo "⚠️  WARNING: APP_PUBLIC_URL is not set"
  echo "   OAuth providers will not work until you:"
  echo "   1. Get the public URL from Phala after deployment"
  echo "   2. Update APP_PUBLIC_URL environment variable"
  echo "   3. Configure OAuth callback URLs with providers"
  echo ""
  # Set a placeholder
  APP_PUBLIC_URL="http://placeholder-update-after-deployment"
  ENV_VARS[APP_PUBLIC_URL]=1
fi

# Optional variables with defaults
TEEPOD_ID="${TEEPOD_ID:-}"
CVM_NAME="${CVM_NAME:-oauth3-prod}"
VCPU="${VCPU:-2}"
MEMORY="${MEMORY:-4096}"
DISK_SIZE="${DISK_SIZE:-60}"
DSTACK_IMAGE="${DSTACK_IMAGE:-dstack-dev-0.5.5}"

# Apply defaults for docker-compose variables (Phala doesn't support ${VAR:-default} syntax)
: "${APP_BIND_ADDR:=0.0.0.0:8080}"
: "${RUST_LOG:=info,oauth3=info}"

# Mark defaults as defined
ENV_VARS[POSTGRES_PASSWORD]=1
ENV_VARS[APP_BIND_ADDR]=1
ENV_VARS[RUST_LOG]=1
ENV_VARS[DOCKER_IMAGE]=1

# Create temp directory for generated env file
TEMP_DIR=$(mktemp -d)
TEMP_ENV_FILE="$TEMP_DIR/phala-deploy.env"

# Cleanup on exit
trap "rm -rf '$TEMP_DIR'" EXIT

# Generate env file from current environment
echo "# Generated environment file for Phala deployment" > "$TEMP_ENV_FILE"
echo "# Source: $ENV_FILE" >> "$TEMP_ENV_FILE"
echo "# Generated: $(date)" >> "$TEMP_ENV_FILE"
echo "" >> "$TEMP_ENV_FILE"

for var in "${!ENV_VARS[@]}"; do
  value="${!var}"
  # Strip surrounding quotes if present
  if [[ "$value" =~ ^\"(.*)\"$ ]] || [[ "$value" =~ ^\'(.*)\'$ ]]; then
    value="${BASH_REMATCH[1]}"
  fi
  echo "${var}=${value}" >> "$TEMP_ENV_FILE"
done

# Show generated env file
echo ""
echo "Generated environment file at: $TEMP_ENV_FILE"
echo "────────────────────────────────────────"
cat "$TEMP_ENV_FILE"
echo "────────────────────────────────────────"
echo ""

# Build the command
CMD=(
  phala deploy
  --name "$CVM_NAME"
  --compose ./docker-compose.phala.yml
  --vcpu "$VCPU"
  --memory "$MEMORY"
  --disk-size "$DISK_SIZE"
  --image "$DSTACK_IMAGE"
  --env-file "$TEMP_ENV_FILE"
)

# Add app-id if specified
if [[ -n "$APP_ID" ]]; then
  CMD+=(--cvm-id "$APP_ID")
fi

# Add teepod if specified
if [[ -n "$TEEPOD_ID" ]]; then
  CMD+=(--teepod-id "$TEEPOD_ID")
fi

# Print the command
echo "Deployment command:"
echo "${CMD[@]}"
echo ""

# Confirm before running
read -p "Deploy to Phala? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Deployment cancelled"
  echo "Generated env file preserved at: $TEMP_ENV_FILE"
  trap - EXIT  # Disable cleanup
  exit 0
fi

# Execute
"${CMD[@]}"
