# ZED: Zero-day Endpoint Detection & Response
# Lightweight Production Docker Container

FROM python:3.12-slim-bookworm

# System dependencies for psutil and network diagnostics
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    procps \
    net-tools \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Set environment defaults
ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000

# Expose EDR Web & Telemetry port
EXPOSE 8000

# Launch ZED Server & Telemetry Monitor
CMD ["python", "run_server.py"]
