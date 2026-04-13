# Docker Setup Guide for Revula

Revula runs over **stdio transport only**. Docker usage is therefore local-process style (attach stdin/stdout), not HTTP/SSE server mode.

## Quick Start

### 1. Build the image

```bash
docker build -t revula:latest .
```

### 2. Smoke test the image

```bash
docker run --rm --entrypoint python revula:latest -c "import revula; print(revula.__version__)"
docker run --rm --entrypoint python revula:latest -c "from revula.server import _register_all_tools; from revula.tools import TOOL_REGISTRY; _register_all_tools(); print(TOOL_REGISTRY.count())"
```

### 3. Run in stdio mode (default runtime mode)

```bash
docker run -i --rm \
  -v "$(pwd)/workspace:/workspace" \
  -v revula-data:/root/.revula \
  revula:latest
```

## Docker Compose

The compose file provides:

- `revula-stdio` profile: stdio runtime container
- `revula-dev` profile: interactive development container
- `revula-stdio` intentionally sets `tty: false` to keep MCP JSON-RPC framing stable over stdio

### Run stdio profile

```bash
docker compose --profile stdio run --rm revula-stdio
```

### Run development profile

```bash
docker compose --profile dev run --rm revula-dev
```

## Configuration

### Environment variables

```bash
docker run -i --rm \
  -e REVULA_MAX_MEMORY_MB=2048 \
  -e REVULA_DEFAULT_TIMEOUT=300 \
  -e REVULA_ALLOWED_DIRS="/workspace:/tmp" \
  -v "$(pwd)/workspace:/workspace" \
  -v revula-data:/root/.revula \
  revula:latest
```

### Config file mount

```bash
docker run -i --rm \
  -v "$(pwd)/config.toml:/root/.revula/config.toml" \
  -v "$(pwd)/workspace:/workspace" \
  revula:latest
```

Example tool override keys use the current runtime schema:

```toml
[security]
allowed_dirs = ["/workspace"]
max_memory_mb = 1024
default_timeout = 120

[tools.ghidra_headless]
path = "/opt/ghidra/support/analyzeHeadless"

[tools.radare2]
path = "/usr/bin/r2"
```

## Volumes and Persistence

- Workspace bind mount: `-v "$(pwd)/workspace:/workspace"`
- Revula state volume: `-v revula-data:/root/.revula`

Persisted state includes:

- `/root/.revula/config.toml`
- `/root/.revula/cache/`
- `/root/.revula/ghidra_projects/`

## Security Notes

- Default container user is root to preserve debugger/tool compatibility.
- For non-privileged workflows, run with `--user revula`.
- You can isolate network access with `--network none` for offline analysis workflows.

## Troubleshooting

### Build fails

```bash
docker build --no-cache -t revula:latest .
docker system df
```

### Validate installed capabilities

```bash
./scripts/docker/test.sh
```

### Check runtime logs / open shell

```bash
docker logs <container_id>
docker run -it --rm --entrypoint /bin/bash revula:latest
```
