# Stage 1: Build React frontend
FROM node:20-slim AS frontend-builder

WORKDIR /frontend
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
# Output: /frontend/dist/

# Stage 2: Python API + static files
FROM python:3.12-slim

WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application files
COPY main.py seed.py sandbox_models.py sandbox_state.py ./

# Copy built frontend from Stage 1
COPY --from=frontend-builder /frontend/dist ./dist

# Single worker: session dict is in-process memory.
# Multi-worker would split sessions across processes.
EXPOSE 7860
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
