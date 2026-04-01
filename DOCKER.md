# Docker Setup Guide for Revula

This guide provides complete instructions for running Revula in Docker containers.

## Table of Contents

- [Quick Start](#quick-start)
- [Build Options](#build-options)
- [Running Modes](#running-modes)
- [Docker Compose](#docker-compose)
- [Configuration](#configuration)
- [Volumes and Persistence](#volumes-and-persistence)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Build the Docker Image

```bash
docker build -t revula:latest .
```

### 2. Run Basic Test

```bash
# Check version
docker run --rm revula:latest --version

# List available tools
docker run --rm revula:latest --list-tools
```

### 3. Run in stdio Mode (for MCP clients)

```bash
docker run -i --rm \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

### 4. Run in SSE Mode (for remote access)

```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/workspace:/workspace \
  --name revula-server \
  revula:latest --sse --host 0.0.0.0 --port 8000
```

## Build Options

### Standard Build

```bash
docker build -t revula:latest .
```

### Build with BuildKit (faster, better caching)

```bash
DOCKER_BUILDKIT=1 docker build -t revula:latest .
```

### Multi-platform Build (for ARM and x86)

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t revula:latest .
```

## Running Modes

### stdio Mode (Default)

Used for local MCP clients like Claude Desktop:

```bash
docker run -i --rm \
  -v $(pwd)/workspace:/workspace \
  -v revula-data:/home/revula/.revula \
  revula:latest
```

**Use cases:**
- Local Claude Desktop integration
- VS Code with GitHub Copilot
- Cursor IDE
- Any local MCP client

### SSE Mode (Server-Sent Events)

Used for remote access over HTTP:

```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/workspace:/workspace \
  -v revula-data:/home/revula/.revula \
  --name revula-server \
  revula:latest --sse --host 0.0.0.0 --port 8000
```

**Use cases:**
- Remote client connections
- Web-based interfaces
- Multi-user environments

### Interactive Shell (for debugging)

```bash
docker run -it --rm \
  -v $(pwd)/workspace:/workspace \
  revula:latest /bin/bash
```

## Docker Compose

Docker Compose provides simplified management with pre-configured profiles.

### SSE Server Mode

```bash
# Start the SSE server
docker-compose --profile sse up -d

# View logs
docker-compose logs -f revula-sse

# Stop the server
docker-compose --profile sse down
```

### stdio Mode

```bash
# Run stdio mode
docker-compose --profile stdio run --rm revula-stdio
```

### Development Mode

```bash
# Start development container with source mounted
docker-compose --profile dev run --rm revula-dev

# Inside container, you can:
# - Edit code (changes reflected immediately)
# - Run tests: pytest
# - Run linters: ruff check src/
```

## Configuration

### Environment Variables

Configure Revula behavior via environment variables:

```bash
docker run -i --rm \
  -e REVULA_MAX_MEMORY_MB=2048 \
  -e REVULA_DEFAULT_TIMEOUT=300 \
  -e REVULA_ALLOWED_DIRS="/workspace:/tmp" \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

**Available variables:**
- `REVULA_MAX_MEMORY_MB` - Maximum memory per tool execution (default: 512)
- `REVULA_DEFAULT_TIMEOUT` - Default timeout in seconds (default: 60)
- `REVULA_ALLOWED_DIRS` - Restrict filesystem access (default: "/")
- `GHIDRA_PATH` - Custom Ghidra installation path
- `GDB_PATH` - Custom GDB binary path
- `FRIDA_PATH` - Custom Frida installation path

### Configuration File

Mount a custom config file:

```bash
docker run -i --rm \
  -v $(pwd)/config.toml:/home/revula/.revula/config.toml \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

Example `config.toml`:

```toml
[security]
allowed_dirs = ["/workspace"]
max_memory_mb = 1024
default_timeout = 120

[tools.ghidra]
path = "/opt/ghidra"
headless_path = "/opt/ghidra/support/analyzeHeadless"

[tools.radare2]
path = "/usr/bin/r2"
```

## Volumes and Persistence

### Workspace Volume

Mount your workspace directory for analyzing binaries:

```bash
-v $(pwd)/workspace:/workspace
```

### Cache and Configuration Volume

Persist Revula's cache and configuration:

```bash
-v revula-data:/home/revula/.revula
```

This volume contains:
- `/home/revula/.revula/config.toml` - Configuration
- `/home/revula/.revula/cache/` - Result caching
- `/home/revula/.revula/ghidra_projects/` - Ghidra analysis cache

### Complete Example

```bash
docker run -i --rm \
  -v $(pwd)/workspace:/workspace \
  -v $(pwd)/binaries:/binaries:ro \
  -v revula-data:/home/revula/.revula \
  revula:latest
```

## Security Considerations

### Running as Non-Root User

By default, the container runs as root to allow debugging tools (GDB attach, Frida) to function properly.

To run as non-root user `revula` (UID 1000):

```bash
docker run --user revula -i --rm \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

**Note:** Some dynamic analysis features require root privileges:
- Attaching to processes with GDB/LLDB
- Using Frida on certain targets
- Android ADB in some scenarios

### Filesystem Restrictions

Limit filesystem access via `REVULA_ALLOWED_DIRS`:

```bash
docker run -i --rm \
  -e REVULA_ALLOWED_DIRS="/workspace" \
  -v $(pwd)/workspace:/workspace:ro \
  revula:latest
```

### Network Isolation

Run with no network access (except for SSE mode):

```bash
docker run -i --rm \
  --network none \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

### Resource Limits

Limit CPU and memory usage:

```bash
docker run -i --rm \
  --cpus="2.0" \
  --memory="2g" \
  --memory-swap="2g" \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

## Troubleshooting

### Image Build Fails

**Problem:** Docker build fails during dependency installation.

**Solution:**
```bash
# Clean build without cache
docker build --no-cache -t revula:latest .

# Check Docker disk space
docker system df

# Clean up old images
docker system prune -a
```

### Container Exits Immediately

**Problem:** Container starts but exits without output.

**Solution:**
```bash
# Check logs
docker logs <container_id>

# Run with interactive shell
docker run -it --rm revula:latest /bin/bash

# Check if command is correct
docker run --rm revula:latest --help
```

### Permission Denied Errors

**Problem:** Cannot access files in workspace.

**Solution:**
```bash
# Fix ownership on host
sudo chown -R $(id -u):$(id -g) workspace/

# Or run as specific user
docker run --user $(id -u):$(id -g) -i --rm \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

### Tool Not Found

**Problem:** External tool (like radare2) not available in container.

**Solution:**
```bash
# Check what's installed
docker run --rm revula:latest r2 -v
docker run --rm revula:latest gdb --version

# Install additional tools (rebuild with custom Dockerfile)
# Or mount tools from host:
docker run -i --rm \
  -v /usr/local/bin/my-tool:/usr/local/bin/my-tool \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

### Memory Issues

**Problem:** Container OOM (Out of Memory).

**Solution:**
```bash
# Increase Docker memory limit
docker run -i --rm \
  --memory="4g" \
  -e REVULA_MAX_MEMORY_MB=3072 \
  -v $(pwd)/workspace:/workspace \
  revula:latest
```

### SSE Mode Health Check Fails

**Problem:** Container reports unhealthy.

**Solution:**
```bash
# Check if server is actually running
docker exec <container_id> curl http://localhost:8000/health

# Check logs
docker logs <container_id>

# Ensure port mapping is correct
docker run -d -p 8000:8000 revula:latest --sse --host 0.0.0.0
```

## Performance Tips

### 1. Use BuildKit for Faster Builds

```bash
export DOCKER_BUILDKIT=1
docker build -t revula:latest .
```

### 2. Leverage Layer Caching

Order your Dockerfile from least to most frequently changing:
- ✅ System packages first
- ✅ Python dependencies second
- ✅ Application code last

### 3. Use Named Volumes

Named volumes are faster than bind mounts:

```bash
docker volume create revula-data
docker run -v revula-data:/home/revula/.revula revula:latest
```

### 4. Limit Resource Usage

Prevent one analysis from consuming all resources:

```bash
docker run -i --rm \
  --cpus="2.0" \
  --memory="2g" \
  -e REVULA_MAX_MEMORY_MB=1536 \
  revula:latest
```

## Advanced Usage

### Running Multiple Instances

```bash
# Instance 1
docker run -d -p 8001:8000 --name revula-1 revula:latest --sse --host 0.0.0.0

# Instance 2
docker run -d -p 8002:8000 --name revula-2 revula:latest --sse --host 0.0.0.0
```


### CI/CD Integration

Example GitHub Actions workflow:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker image
        run: docker build -t revula:test .
      - name: Test image
        run: ./scripts/docker/test.sh
```

## Support

For issues related to Docker setup:
1. Check this troubleshooting guide
2. Review Docker logs: `docker logs <container>`
3. Open an issue at https://github.com/president-xd/revula/issues
