FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-update -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional dependencies for the scan functionality
RUN pip install --no-cache-dir eventlet flask-socketio

# Copy backend code
COPY backend/ ./
COPY scan.py /app/
COPY config/ /app/config/

# Make directory for scan results
RUN mkdir -p reports

# Expose port
EXPOSE 5001

# Command to run the server
CMD ["python", "run_server.py"]
