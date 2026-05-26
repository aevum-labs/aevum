FROM python:3.12-slim

WORKDIR /app

# Dependencies first — cached layer unless requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application files
COPY main.py seed.py sandbox_models.py sandbox_state.py ./

# HF Spaces requires port 7860
EXPOSE 7860

# Single worker: session dict is in-process memory.
# Multi-worker would split sessions across processes.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
