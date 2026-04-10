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
    GHIDRA_DATE=20240130 \
    GHIDRA_SHA256=a0bc9450aa3a231096b13a823c66311b9f84cb9cec4624393221cfed40ef6924 \
    APKTOOL_VERSION=2.10.0 \
    SMALI_VERSION=2.5.2 \
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
    lldb \
    strace \
    ltrace \
    # Disassemblers and binary tools
    binutils \
    binutils-multiarch \
    binwalk \
    # radare2/rizin/upx are not available in bookworm default repos
    qemu-user \
    qemu-system \
    qemu-utils \
    wabt \
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
    wget -q -O ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    echo "${GHIDRA_SHA256}  ghidra.zip" | sha256sum -c - && \
    unzip -q ghidra.zip && \
    mv ghidra_${GHIDRA_VERSION}_PUBLIC/* ${GHIDRA_INSTALL_DIR}/ && \
    rm -rf /tmp/ghidra_* /tmp/ghidra.zip && \
    chmod +x ${GHIDRA_INSTALL_DIR}/support/analyzeHeadless

# Install apktool
RUN cd /usr/local/bin && \
    wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/v${APKTOOL_VERSION}/scripts/linux/apktool" && \
    wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" -O apktool.jar && \
    chmod +x apktool apktool.jar

# Install jadx
RUN cd /tmp && \
    wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip && \
    unzip -q jadx-1.5.0.zip -d /opt/jadx && \
    chmod +x /opt/jadx/bin/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm jadx-1.5.0.zip

# Install smali/baksmali wrappers
RUN mkdir -p /opt/smali && \
    cd /opt/smali && \
    wget -q -O smali.jar "https://repo.maven.apache.org/maven2/org/smali/smali/${SMALI_VERSION}/smali-${SMALI_VERSION}.jar" && \
    wget -q -O baksmali.jar "https://repo.maven.apache.org/maven2/org/smali/baksmali/${SMALI_VERSION}/baksmali-${SMALI_VERSION}.jar" && \
    printf '#!/usr/bin/env bash\nexec java -jar /opt/smali/smali.jar \"$@\"\n' > /usr/local/bin/smali && \
    printf '#!/usr/bin/env bash\nexec java -jar /opt/smali/baksmali.jar \"$@\"\n' > /usr/local/bin/baksmali && \
    chmod +x /usr/local/bin/smali /usr/local/bin/baksmali

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
    flare-capa>=7.0.0 \
    semgrep \
    quark-engine \
    ROPGadget \
    ropper

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
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
    CFR_VERSION=0.152 \
    RADARE2_VERSION=6.1.2 \
    RIZIN_VERSION=0.8.2 \
    DYNAMORIO_VERSION=11.91.20545 \
    DIE_VERSION=3.10 \
    UPX_VERSION=5.1.1 \
    RETDEC_VERSION=5.0

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
    lldb \
    strace \
    ltrace \
    # Disassemblers and binary tools
    binutils \
    binutils-multiarch \
    binwalk \
    checksec \
    apksigner \
    mono-utils \
    mono-devel \
    ruby-full \
    llvm-19 \
    gnupg \
    qemu-user \
    qemu-system \
    qemu-utils \
    wabt \
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
    xz-utils \
    vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# Install third-party tools not available from bookworm main
RUN set -eux; \
    curl -fsSL -o /tmp/radare2.deb "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb"; \
    curl -fsSL -o /tmp/die.deb "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Debian_12_amd64.deb"; \
    curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | gpg --dearmor -o /usr/share/keyrings/metasploit-framework.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/metasploit-framework.gpg] https://apt.metasploit.com/ lucid main" > /etc/apt/sources.list.d/metasploit-framework.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends metasploit-framework /tmp/radare2.deb /tmp/die.deb; \
    gem install --no-document one_gadget; \
    mkdir -p /opt/rizin /opt/dynamorio /opt/upx /opt/retdec /opt/capa-rules; \
    curl -fsSL -o /tmp/rizin.tar.xz "https://github.com/rizinorg/rizin/releases/download/v${RIZIN_VERSION}/rizin-v${RIZIN_VERSION}-static-x86_64.tar.xz"; \
    tar -xf /tmp/rizin.tar.xz -C /opt/rizin; \
    ln -sf /opt/rizin/bin/rizin /usr/local/bin/rizin; \
    ln -sf /opt/rizin/bin/rz /usr/local/bin/rz; \
    ln -sf /opt/rizin/bin/rz-diff /usr/local/bin/rz-diff; \
    curl -fsSL -o /tmp/dynamorio.tar.gz "https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-${DYNAMORIO_VERSION}/DynamoRIO-Linux-${DYNAMORIO_VERSION}.tar.gz"; \
    tar -xzf /tmp/dynamorio.tar.gz -C /opt/dynamorio --strip-components=1; \
    printf '#!/usr/bin/env bash\nexec /opt/dynamorio/bin64/drrun "$@"\n' > /usr/local/bin/drrun; \
    chmod +x /usr/local/bin/drrun; \
    curl -fsSL -o /tmp/upx.tar.xz "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz"; \
    tar -xf /tmp/upx.tar.xz -C /opt/upx; \
    ln -sf /opt/upx/upx-${UPX_VERSION}-amd64_linux/upx /usr/local/bin/upx; \
    curl -fsSL -o /tmp/retdec.tar.xz "https://github.com/avast/retdec/releases/download/v${RETDEC_VERSION}/RetDec-v${RETDEC_VERSION}-Linux-Release.tar.xz"; \
    tar -xf /tmp/retdec.tar.xz -C /opt/retdec; \
    ln -sf /opt/retdec/bin/retdec-decompiler /usr/local/bin/retdec-decompiler; \
    curl -fsSL -o /tmp/cfr.jar "https://www.benf.org/other/cfr/cfr-${CFR_VERSION}.jar"; \
    mv /tmp/cfr.jar /opt/cfr.jar; \
    printf '#!/usr/bin/env bash\nexec java -jar /opt/cfr.jar "$@"\n' > /usr/local/bin/cfr; \
    chmod +x /usr/local/bin/cfr; \
    curl -fsSL -o /tmp/capa-rules.tar.gz "https://github.com/mandiant/capa-rules/archive/refs/heads/master.tar.gz"; \
    tar -xzf /tmp/capa-rules.tar.gz -C /opt/capa-rules --strip-components=1; \
    rm -rf /var/lib/apt/lists/* /tmp/*; \
    rm -f /etc/apt/sources.list.d/metasploit-framework.list /usr/share/keyrings/metasploit-framework.gpg

# Copy Python virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy Ghidra from builder
COPY --from=builder /opt/ghidra /opt/ghidra

# Copy jadx from builder
COPY --from=builder /opt/jadx /opt/jadx

# Copy smali tools from builder
COPY --from=builder /opt/smali /opt/smali
COPY --from=builder /usr/local/bin/smali /usr/local/bin/smali
COPY --from=builder /usr/local/bin/baksmali /usr/local/bin/baksmali

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
VOLUME ["/root/.revula", "/workspace"]

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    REVULA_MAX_MEMORY_MB=2048 \
    REVULA_DEFAULT_TIMEOUT=300 \
    GHIDRA_PATH=/opt/ghidra \
    GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless

# Default: Run as root for access to debugging tools
WORKDIR /workspace

# Default command: stdio mode for MCP clients
ENTRYPOINT ["revula"]
CMD []
