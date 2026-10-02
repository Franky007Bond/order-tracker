FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY incident-response ./incident-response

ENV INCIDENT_DATA_DIR=/data/incidents
EXPOSE 8001
CMD ["uv", "run", "--no-sync", "uvicorn", "app:app", "--app-dir", "/app/incident-response", "--host", "0.0.0.0", "--port", "8001"]
