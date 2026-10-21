FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY phishbot ./phishbot
COPY pyproject.toml README.md ./

# The service only ever parses untrusted input - never run it as root.
RUN useradd --create-home --uid 10001 phishbot \
    && chown -R phishbot:phishbot /app
USER phishbot

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "phishbot.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
