FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
COPY services/shared /app/shared
COPY tools /app/tools
COPY contracts /app/contracts
COPY services/ws2-normalization /app/ws2-normalization
# PyYAML is required: the A5 enrichment stage (enrichment/__init__.py) loads
# contracts/enrichment/*.yml at import time. Without it ws2 crash-loops on
# `import yaml` -- a real bug the zero-infra test gate misses (local Python
# has yaml). `redis` is the bus backend. Fail-closed: a broken requirements.txt
# must fail the build, not silently produce an image that can't start.
RUN pip install --no-cache-dir --require-hashes -r /app/ws2-normalization/requirements.txt
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
# Security-adversarial #2 (2026-07-29 audit): drop root before running.
RUN groupadd --system app && useradd --system --gid app --uid 10001 --no-create-home app \
    && chown -R app:app /app
USER app
WORKDIR /app/ws2-normalization
CMD ["python", "main.py"]
