#!/bin/bash
# Custom pre-launch script for OAuth3 Phala deployment
# Replaces the default Phala v0.0.14 script which hangs during image pull checks

echo "----------------------------------------------"
echo "Running OAuth3 Pre-Launch Script"
echo "----------------------------------------------"

# Docker login for private GHCR registry
if [ -n "$DSTACK_DOCKER_USERNAME" ] && [ -n "$DSTACK_DOCKER_PASSWORD" ]; then
    REGISTRY="${DSTACK_DOCKER_REGISTRY:-ghcr.io}"
    echo "Logging in to Docker registry: $REGISTRY"
    echo "$DSTACK_DOCKER_PASSWORD" | docker login "$REGISTRY" -u "$DSTACK_DOCKER_USERNAME" --password-stdin
    if [ $? -eq 0 ]; then
        echo "Docker login successful: $REGISTRY"
    else
        echo "ERROR: Docker login failed for $REGISTRY"
        exit 1
    fi
else
    echo "No Docker credentials found, using public registry"
fi

# Always pull latest images before docker compose up
echo "Pulling latest images..."
docker compose pull
echo "Pre-launch complete, handing off to docker compose"
