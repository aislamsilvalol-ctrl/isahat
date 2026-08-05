# IsaHat container image.
# Build:  docker build -t isahat:local .
# Run:    docker run --rm isahat:local scan https://example.com --yes
FROM python:3.12-slim AS base

# Do not write .pyc; flush stdout; no pip cache.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ISAHAT_HOME=/data

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

# Run as a non-root user; persist scans under /data.
RUN useradd --create-home --uid 10001 isahat \
    && mkdir -p /data \
    && chown -R isahat:isahat /data /app
USER isahat

VOLUME ["/data"]

ENTRYPOINT ["isahat"]
CMD ["--help"]
