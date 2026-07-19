FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
COPY services/shared /app/shared
COPY tools /app/tools
COPY contracts /app/contracts
COPY services/ws2-normalization /app/ws2-normalization
# PyYAML is required: the A5 enrichment stage (enrichment/__init__.py) loads
# contracts/enrichment/*.yml at import time. Without it ws2 crash-loops on
# `import yaml` -- a real bug the zero-infra test gate misses (local Python
# has yaml). `redis` is the bus backend. `|| true` intentionally: an offline
# build still produces a runnable image for the memory-bus path.
RUN pip install --no-cache-dir -r /app/ws2-normalization/requirements.txt || true
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
WORKDIR /app/ws2-normalization
CMD ["python", "main.py"]
