# Docker Quick Reference

> Revula is **stdio-only** in Docker (no `--sse` mode).

## Build

```bash
docker build -t revula:latest .
```

## Smoke Test

```bash
docker run --rm revula:latest python -c "import revula; print(revula.__version__)"
docker run --rm revula:latest python -c "from revula.server import _register_all_tools; from revula.tools import TOOL_REGISTRY; _register_all_tools(); print(TOOL_REGISTRY.count())"
```

## Run Modes

### stdio (for MCP clients)

```bash
docker run -i --rm \
  -v "$(pwd)/workspace:/workspace" \
  -v revula-data:/root/.revula \
  revula:latest
```

### Interactive Shell

```bash
docker run -it --rm revula:latest /bin/bash
```

## Docker Compose

```bash
docker compose --profile stdio run --rm revula-stdio
docker compose --profile dev run --rm revula-dev
```

## Validation

```bash
./scripts/docker/test.sh
```

## Common Flags

```bash
docker run -i --rm \
  -e REVULA_MAX_MEMORY_MB=2048 \
  -e REVULA_DEFAULT_TIMEOUT=300 \
  -e REVULA_ALLOWED_DIRS="/workspace:/tmp" \
  -v "$(pwd)/workspace:/workspace" \
  -v revula-data:/root/.revula \
  revula:latest
```
