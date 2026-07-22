FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot.py .

RUN useradd --create-home --uid 10001 honeypot \
    && mkdir -p /app/data \
    && chown -R honeypot:honeypot /app

USER honeypot

EXPOSE 2222

VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.create_connection(('127.0.0.1', 2222), timeout=2); s.close()" || exit 1

CMD [ \
    "python", \
    "honeypot.py", \
    "--host", "0.0.0.0", \
    "--port", "2222", \
    "--host-key", "/app/data/ssh_host_rsa_key", \
    "--log-file", "/app/data/honeypot.jsonl" \
]
