FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
# shared lib + this service
COPY services/shared /app/shared
COPY services/ws1-collectors /app/ws1-collectors
RUN pip install --no-cache-dir -r /app/ws1-collectors/requirements.txt || true
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
WORKDIR /app/ws1-collectors
CMD ["python", "main.py"]
