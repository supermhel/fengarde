FROM python:3.12-slim
WORKDIR /app
COPY services/shared /app/shared
COPY services/ws5-ai /app/ws5-ai
RUN pip install --no-cache-dir -r /app/ws5-ai/requirements.txt || true
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
# Point at a local Ollama to enable the real LLM; unset -> deterministic StubLLM.
# ENV OLLAMA_URL=http://ollama:11434
# ENV OLLAMA_MODEL=qwen2.5:7b-instruct
WORKDIR /app/ws5-ai
CMD ["python", "main.py"]
