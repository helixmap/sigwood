FROM python:3.12-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy project definition and source tree
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY sigwood/ ./sigwood/

# Build wheels and install sigwood with all extras (splunk, cloudtrail, fast-hdbscan)
RUN pip install --no-cache-dir --upgrade pip build && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels . && \
    pip install --no-cache-dir --prefix=/install .[all]


FROM python:3.12-slim-bookworm AS runner

# Create non-root user and working directories
ENV HOME=/home/sigwood
RUN groupadd -g 1000 sigwood && \
    useradd -u 1000 -g sigwood -m -d /home/sigwood -s /bin/bash sigwood && \
    mkdir -p /data /reports && \
    chmod 1777 /reports && \
    chown -R sigwood:sigwood /data /reports /home/sigwood

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /data
USER sigwood

ENTRYPOINT ["sigwood"]
CMD ["--help"]
