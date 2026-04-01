# Docker Scripts

This directory contains automation scripts for Docker build, test, and validation.

## Scripts

### test.sh

Automated Docker build and comprehensive testing script.

**Usage:**
```bash
./scripts/docker/test.sh
```

**What it does:**
1. Checks if Docker is installed and running
2. Builds the Docker image with all tools
3. Tests revula command (--version, --list-tools)
4. Tests Python dependencies (capstone, lief, pefile, yara, angr, frida, androguard)
5. Tests GDB availability
6. Tests radare2 availability
7. Tests Ghidra availability (analyzeHeadless)
8. Tests Frida availability
9. Tests Android tools (apktool, jadx)

**Requirements:**
- Docker installed and running
- Current directory: project root

**Exit codes:**
- 0: All tests passed
- 1: Test failed or Docker not available

### validate.sh

Docker configuration validation script.

**Usage:**
```bash
./scripts/docker/validate.sh
```

**What it does:**
1. Checks all required Docker files exist
2. Validates Dockerfile syntax
3. Validates docker-compose.yml structure
4. Checks .dockerignore patterns
5. Verifies Python requirements
6. Validates documentation completeness
7. Checks script executability

**Requirements:**
- Current directory: project root

**Exit codes:**
- 0: All checks passed or warnings only
- 1: Critical errors found

## Quick Reference

```bash
# Validate configuration before building
./scripts/docker/validate.sh

# Build and test Docker image
./scripts/docker/test.sh

# If tests pass, use the image
docker run -i --rm -v $(pwd)/workspace:/workspace revula:latest

# Or use docker-compose
docker-compose --profile sse up -d
```

## Integration with CI/CD

These scripts are designed to be used in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Validate Docker configuration
  run: ./scripts/docker/validate.sh

- name: Build and test Docker image
  run: ./scripts/docker/test.sh
```

## Troubleshooting

### Docker not available
```
ERROR: Docker is not installed or not in PATH
```
**Solution:** Install Docker from https://docs.docker.com/get-docker/

### Docker daemon not running
```
ERROR: Docker daemon is not running
```
**Solution:** Start Docker Desktop or run `sudo systemctl start docker`

### Build fails
```
[FAIL] Docker build failed
```
**Solution:** Check build logs and ensure all dependencies are available

### Tests fail
```
[FAIL] Test X failed
```
**Solution:** Check test output for specific errors and verify tool installation

## See Also

- [DOCKER.md](../../DOCKER.md) - Complete Docker documentation
- [DOCKER-QUICKREF.md](../../DOCKER-QUICKREF.md) - Quick reference guide
- [DOCKER-COMPLETE.md](../../DOCKER-COMPLETE.md) - Technical specifications
