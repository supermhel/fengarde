FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
COPY services/shared /app/shared
COPY contracts /app/contracts
COPY services/ws3-indexer /app/ws3-indexer
RUN pip install --no-cache-dir -r /app/ws3-indexer/requirements.txt || true
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
ENV STORAGE_BACKEND=opensearch
ENV OPENSEARCH_URL=http://opensearch:9200
WORKDIR /app/ws3-indexer
CMD ["python", "main.py"]
