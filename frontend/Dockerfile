# ── Frontend Dockerfile ─────────────────────────────────────────────────────
# Python 3.11 slim image for the Streamlit frontend.

FROM python:3.11-slim

# Security: run as non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Switch to non-root user
USER appuser

EXPOSE 8501

# Streamlit config is in .streamlit/config.toml (already committed)
CMD ["streamlit", "run", "app.py", "--server.port", "8501", "--server.address", "0.0.0.0"]
