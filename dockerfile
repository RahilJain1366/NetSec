FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs and outputs directories
RUN mkdir -p logs outputs

# Runtime defaults (override via docker-compose .env)
ENV FLASK_APP=dashboard/app.py
ENV PORT=5001

EXPOSE 5001

# Health check against the gunicorn bind port
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001').read()"

# Start the dashboard
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5001", "--timeout", "120", "wsgi:app"]