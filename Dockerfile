# GrishaKey container image
FROM python:3.14-slim

# Python: no .pyc files, logs show up right away
# App: listen on all interfaces inside the container, keep data in /data
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GRISHAKEY_HOST=0.0.0.0 \
    GRISHAKEY_PORT=9500 \
    GRISHAKEY_DATA=/data \
    NICEGUI_STORAGE_PATH=/data/.nicegui

WORKDIR /app

# Run as a normal user, never root
RUN useradd --create-home --uid 1000 grishakey

# Install dependencies first, so code changes don't reinstall everything
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code (.dockerignore keeps secrets, data, and the venv out)
COPY . .

# Data folder for the database and NiceGUI storage, owned by the app user
RUN mkdir -p /data && chown -R grishakey:grishakey /data /app
USER grishakey

EXPOSE 9500

# Docker marks the container unhealthy if the sign-in page stops answering
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9500/login', timeout=4)" || exit 1

CMD ["python", "main.py"]