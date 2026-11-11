# Image de dev : Python + pytest. Le code n'est pas copié, il est monté dans /app
# par compose.dev.yml.
FROM python:3.15-slim

RUN pip install --no-cache-dir --disable-pip-version-check pytest==9.2.0

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
