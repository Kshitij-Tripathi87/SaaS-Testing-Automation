FROM python:3.11-slim

WORKDIR /app

# Install system deps needed by git (for shallow clones) + curl (for ollama, if needed later)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy local shared packages first (worker depends on them)
COPY packages/core-schema/ /app/packages/core-schema/
COPY packages/common-utils/ /app/packages/common-utils/

# Install the shared packages
RUN pip install --no-cache-dir /app/packages/core-schema \
    && pip install --no-cache-dir /app/packages/common-utils

# Now copy and install the worker itself
COPY apps/worker-engine/pyproject.toml /app/worker-engine/pyproject.toml
COPY apps/worker-engine/src/ /app/worker-engine/src/

# Install the worker (excludes playwright dep via optional extras not required here)
# NOTE: pyproject lists playwright as a hard dep, so pip will try to install it as a wheel
# (small Python package), but won't trigger the ~500MB Chromium binary download unless
# `playwright install` is run. The Chromium download is deferred to a separate image
# (workflo-worker-browser:latest) which adds the binary layer on top of this base.
RUN pip install --no-cache-dir /app/worker-engine

ENV WORKER_MODE=queue
ENV PYTHONUNBUFFERED=1

WORKDIR /app/worker-engine
CMD ["python", "-m", "tenant_shield_worker.main"]
