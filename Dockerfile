# Revula Reverse Engineering MCP Server - Complete Production Build
# 
# This Dockerfile creates a complete reverse engineering environment with:
# - All Python dependencies (including angr, frida)
# - Ghidra headless analyzer
# - GDB, radare2, rizin, binutils
# - Android tools (ADB, apktool, jadx)
# - Network analysis tools
# - All FLARE tools (FLOSS, capa)

# =============================================================================
# Stage 1: Builder - Install all dependencies and tools
# =============================================================================
FROM python:3.12-slim-bookworm AS builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    GHIDRA_VERSION=11.0.1 \
    GHIDRA_SHA256=c5f2d39bd1d4c7f8c82c0559b53f223b6b887db8e38a09f45b645e87fc2d6e1a \
    GHIDRA_INSTALL_DIR=/opt/ghidra

# Install build dependencies and all RE tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    gcc \
    g++ \
    make \
    cmake \
    git \
    wget \
    curl \
    ca-certificates \
    pkg-config \
    # Java for Ghidra and Android tools
    openjdk-17-jdk-headless \
    openjdk-17-jre-headless \
    # Library dependencies
    libssl-dev \
    libffi-dev \
    libmagic-dev \
    libcapstone-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libxml2-dev \
    libxmlsec1-dev \
    liblzma-dev \
    # Debugging tools
    gdb \
    gdb-multiarch \
    strace \
    ltrace \
    # Disassemblers and binary tools
    binutils \
    binutils-multiarch \
    radare2 \
    rizin \
    objdump \
    # Android tools
    adb \
    aapt \
    zipalign \
    # Network analysis
    tcpdump \
    tshark \
    nmap \
    # Utilities
    unzip \
    zip \
    file \
    vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
RUN mkdir -p ${GHIDRA_INSTALL_DIR} && \
    cd /tmp && \
    wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20240130.zip && \
    unzip -q ghidra_${GHIDRA_VERSION}_PUBLIC_*.zip && \
    mv ghidra_${GHIDRA_VERSION}_PUBLIC/* ${GHIDRA_INSTALL_DIR}/ && \
    rm -rf /tmp/ghidra_* && \
    chmod +x ${GHIDRA_INSTALL_DIR}/support/analyzeHeadless

# Install apktool
RUN cd /usr/local/bin && \
    wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool && \
    wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O apktool.jar && \
    chmod +x apktool apktool.jar

# Install jadx
RUN cd /tmp && \
    wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip && \
    unzip -q jadx-1.5.0.zip -d /opt/jadx && \
    chmod +x /opt/jadx/bin/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm jadx-1.5.0.zip

# Create virtual environment for Python packages
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/requirements.txt

# Install core dependencies first
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Install angr and all optional dependencies
RUN pip install --no-cache-dir \
    angr>=9.2.0 \
    frida>=16.0.0 \
    frida-tools>=12.0.0 \
    androguard>=3.4.0a1 \
    r2pipe>=1.8.0 \
    python-tlsh>=4.5.0 \
    ppdeep>=1.1 \
    scapy>=2.5.0 \
    uncompyle6>=3.9.0 \
    flare-floss>=3.0.0 \
    flare-capa>=7.0.0

# =============================================================================
# Stage 2: Runtime - Complete production image with all tools
# =============================================================================
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Revula" \
      org.opencontainers.image.description="Complete Reverse Engineering MCP Server with Ghidra, angr, Frida" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.authors="Revula Contributors" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    libmagic1 \
    libcapstone4 \
    libssl3 \
    file \
    # Java for Ghidra and Android tools
    openjdk-17-jre-headless \
    # Debugging tools
    gdb \
    gdb-multiarch \
    strace \
    ltrace \
    # Disassemblers and binary tools
    binutils \
    binutils-multiarch \
    radare2 \
    rizin \
    # Android tools
    adb \
    aapt \
    zipalign \
    # Network tools
    tcpdump \
    tshark \
    nmap \
    # Utilities
    curl \
    wget \
    ca-certificates \
    unzip \
    zip \
    vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# Copy Python virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy Ghidra from builder
COPY --from=builder /opt/ghidra /opt/ghidra

# Copy jadx from builder
COPY --from=builder /opt/jadx /opt/jadx

# Copy apktool from builder
COPY --from=builder /usr/local/bin/apktool /usr/local/bin/apktool
COPY --from=builder /usr/local/bin/apktool.jar /usr/local/bin/apktool.jar

# Add tools to PATH
ENV PATH="/opt/ghidra/support:/opt/jadx/bin:$PATH"

# Set up working directory
WORKDIR /app

# Copy application code
COPY src/ /app/src/
COPY pyproject.toml /app/
COPY README.md /app/
COPY LICENSE /app/

# Install the application
RUN pip install --no-cache-dir -e .

# Create revula config directory for root
RUN mkdir -p /root/.revula/cache /root/.revula/ghidra_projects /root/.revula/yara_rules

# Create a non-root user for running the application
RUN useradd -m -u 1000 -s /bin/bash revula && \
    mkdir -p /home/revula/.revula/cache /home/revula/.revula/ghidra_projects /home/revula/.revula/yara_rules && \
    chown -R revula:revula /home/revula/.revula

# Set up volumes for persistent data
VOLUME ["/home/revula/.revula", "/workspace"]

# Expose SSE port
EXPOSE 8000

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    REVULA_MAX_MEMORY_MB=2048 \
    REVULA_DEFAULT_TIMEOUT=300 \
    GHIDRA_PATH=/opt/ghidra \
    GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless

# Health check for SSE mode
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD timeout 2 bash -c '</dev/tcp/localhost/8000' || exit 1

# Default: Run as root for access to debugging tools
WORKDIR /workspace

# Default command: stdio mode for MCP clients
ENTRYPOINT ["revula"]
CMD []
