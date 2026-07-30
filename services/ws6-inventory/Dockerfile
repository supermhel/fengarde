FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
COPY services/ws6-inventory /app/ws6-inventory
ENV PYTHONPATH=/app
ENV INVENTORY_DB=/data/inventory.db
ENV PORT=8000
# Security-adversarial #2 (2026-07-29 audit): drop root before running. /data
# (the SQLite volume) must exist and be owned by the app uid BEFORE the
# VOLUME instruction -- Docker copies an image path's existing content/
# ownership into the volume on first use, so creating it root-owned here
# would leave inventory.db unwritable under USER app.
RUN groupadd --system app && useradd --system --gid app --uid 10001 --no-create-home app \
    && mkdir -p /data && chown -R app:app /app /data
VOLUME ["/data"]
EXPOSE 8000
USER app
WORKDIR /app/ws6-inventory
CMD ["python", "app.py"]
