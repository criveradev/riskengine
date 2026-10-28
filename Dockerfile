FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app/backend
COPY backend/ ./
RUN pip install --no-cache-dir -r requirements.lock
RUN pip install --no-cache-dir --no-deps .
COPY --from=web /web/dist /app/frontend/dist
RUN useradd --uid 10001 --create-home riskengine
USER riskengine
EXPOSE 8000
CMD ["python", "-m", "riskengine.serve"]
