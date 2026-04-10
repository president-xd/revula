# Docker Scripts

Automation scripts for Docker build/test and Docker config validation.

## `scripts/docker/test.sh`

Builds `revula:latest` and runs stdio-compatible checks:

1. Docker availability
2. Image build
3. Python package/version smoke test
4. Tool registry load test
5. Availability report command
6. Core Python dependency imports
7. Core external binary checks

Run:

```bash
./scripts/docker/test.sh
```

## `scripts/docker/validate.sh`

Validates Docker-related repo configuration:

1. Required files exist
2. Dockerfile/compose structure checks
3. `.dockerignore` sanity
4. Requirements/docs presence checks

Run:

```bash
./scripts/docker/validate.sh
```

## Quick usage

```bash
./scripts/docker/validate.sh
./scripts/docker/test.sh
docker compose --profile stdio run --rm revula-stdio
```

## References

- [DOCKER.md](../../DOCKER.md)
- [DOCKER-QUICKREF.md](../../DOCKER-QUICKREF.md)
