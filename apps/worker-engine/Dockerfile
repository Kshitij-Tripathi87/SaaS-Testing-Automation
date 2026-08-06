FROM python:3.11

WORKDIR /app

COPY pyproject.toml ./
COPY packages/ ./packages/
RUN pip install --no-cache-dir .

RUN playwright install chromium --with-deps

COPY src/ ./src/

ENV WORKER_MODE=queue

CMD ["python", "-m", "tenant_shield_worker.main"]
