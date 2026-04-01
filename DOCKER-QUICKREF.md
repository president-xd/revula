# Docker Quick Reference

## Build

```bash
docker build -t revula:latest .
```

## Run Modes

### stdio (for MCP clients like Claude Desktop)
```bash
docker run -i --rm \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

### SSE (for remote access)
```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/workspace:/workspace \
  --name revula-server \
  revula:latest --sse --host 0.0.0.0 --port 8000
```

### Interactive Shell
```bash
docker run -it --rm \
  -v $(pwd)/workspace:/workspace \
  revula:latest /bin/bash
```

## Docker Compose

### Start SSE server
```bash
docker-compose --profile sse up -d
```

### View logs
```bash
docker-compose logs -f revula-sse
```

### Stop server
```bash
docker-compose --profile sse down
```

## Common Commands

```bash
# Check version
docker run --rm revula:latest --version

# List available tools
docker run --rm revula:latest --list-tools

# Test the build
./scripts/docker/test.sh

# View logs
docker logs <container_id>

# Execute command in running container
docker exec -it <container_id> /bin/bash
```

## Environment Variables

```bash
docker run -i --rm \
  -e REVULA_MAX_MEMORY_MB=2048 \
  -e REVULA_DEFAULT_TIMEOUT=300 \
  -e REVULA_ALLOWED_DIRS="/workspace" \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

## Volumes

```bash
# Workspace (binaries to analyze)
-v $(pwd)/workspace:/workspace

# Configuration and cache
-v revula-data:/home/revula/.revula

# Custom config file
-v $(pwd)/config.toml:/home/revula/.revula/config.toml
```

## Troubleshooting

```bash
# Clean build
docker build --no-cache -t revula:latest .

# Check disk space
docker system df

# Clean up
docker system prune -a

# Check container logs
docker logs <container_id>

# Run as specific user
docker run --user $(id -u):$(id -g) -i --rm revula:latest

# Increase memory
docker run -i --rm --memory="4g" revula:latest
```

## Advanced

```bash
# Multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t revula:latest .

# Run with resource limits
docker run -i --rm \
  --cpus="2.0" \
  --memory="2g" \
  revula:latest

# Run as non-root
docker run --user revula -i --rm revula:latest

# Network isolation
docker run -i --rm --network none revula:latest
```

For complete documentation, see [DOCKER.md](DOCKER.md).
