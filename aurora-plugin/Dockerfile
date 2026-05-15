# syntax=docker/dockerfile:1.7
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LLM_BACKEND=stub \
    PORT=8000

WORKDIR /app

# Dipendenze — layer cache separata dal codice
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Codice applicativo
COPY app/ ./app/
COPY run.py ./

# Utente non-root
RUN useradd --create-home --shell /sbin/nologin aurora \
 && chown -R aurora:aurora /app
USER aurora

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; \
urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3); sys.exit(0)" || exit 1

# In produzione non vogliamo --reload (il file watcher sprecherebbe CPU e
# causerebbe riavvii spuri nei volumi montati). run.py lo attiva per local dev.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "warning"]
