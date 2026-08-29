FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
COPY services/shared /app/shared
COPY contracts /app/contracts
COPY services/ws4-detection /app/ws4-detection
RUN pip install --no-cache-dir --require-hashes -r /app/ws4-detection/requirements.txt
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
# Security-adversarial #2 (2026-07-29 audit): drop root before running.
RUN groupadd --system app && useradd --system --gid app --uid 10001 --no-create-home app \
    && chown -R app:app /app
USER app
WORKDIR /app/ws4-detection
CMD ["python", "main.py"]
