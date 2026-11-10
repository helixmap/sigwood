FROM python:3.12-slim-bookworm AS builder

# A compiler for any dependency without a prebuilt wheel on this platform.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy project definition and source tree
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY sigwood/ ./sigwood/

# Install sigwood with the [all] extra into a prefix the runtime stage copies.
RUN pip install --no-cache-dir --prefix=/install ".[all]"


FROM python:3.12-slim-bookworm AS runner

# Create non-root user and working directories
ENV HOME=/home/sigwood
# numba (used by the DNS clustering backend) caches compiled code. The installed
# packages are read-only to the runtime user, and HOME is not writable under an
# arbitrary --user, so point the cache at /tmp, which every user can write.
ENV NUMBA_CACHE_DIR=/tmp/numba-cache
RUN groupadd -g 1000 sigwood && \
    useradd -u 1000 -g sigwood -m -d /home/sigwood -s /bin/bash sigwood && \
    mkdir -p /data /reports && \
    chown -R sigwood:sigwood /data /reports /home/sigwood

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /data
USER sigwood

ENTRYPOINT ["sigwood"]
CMD ["--help"]
