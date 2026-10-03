FROM node:22-alpine AS frontend
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build
FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY backend/requirements.lock ./
RUN python -m pip install --upgrade pip && pip install --no-cache-dir --only-binary=pydantic-core -r requirements.lock && useradd --create-home --uid 10001 agent && mkdir -p /app/data /app/workspace /app/static && chown -R agent:agent /app
COPY --chown=agent:agent backend/ /app/
COPY --chown=agent:agent --from=frontend /ui/dist /app/static
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 CMD ["python","-c","import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health',timeout=2)"]
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--no-server-header"]
