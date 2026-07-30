FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
COPY services/shared /app/shared
COPY services/ws5-ai /app/ws5-ai
RUN pip install --no-cache-dir -r /app/ws5-ai/requirements.txt || true
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
# Point at a local Ollama to enable the real LLM; unset -> deterministic StubLLM.
# ENV OLLAMA_URL=http://ollama:11434
# ENV OLLAMA_MODEL=qwen2.5:7b-instruct
# Security-adversarial #2 (2026-07-29 audit): drop root before running.
RUN groupadd --system app && useradd --system --gid app --uid 10001 --no-create-home app \
    && chown -R app:app /app
USER app
WORKDIR /app/ws5-ai
CMD ["python", "main.py"]
