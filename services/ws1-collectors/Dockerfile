FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
# shared lib + this service
COPY services/shared /app/shared
COPY services/ws1-collectors /app/ws1-collectors
RUN pip install --no-cache-dir -r /app/ws1-collectors/requirements.txt
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
# Security-adversarial #2 (2026-07-29 audit): no service ran as a non-root
# container user. This service parses attacker-controlled network input
# directly (syslog UDP), so it's the highest-value one to drop privileges on.
# The UDP listener already binds 5514, not 514, specifically so root was never
# required (see syslog_udp_server.py's docstring). SYSLOG_SPOOL_PATH (opt-in,
# off by default) must point at a path writable by this uid if enabled.
RUN groupadd --system app && useradd --system --gid app --uid 10001 --no-create-home app \
    && chown -R app:app /app
USER app
WORKDIR /app/ws1-collectors
CMD ["python", "main.py"]
