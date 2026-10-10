FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose Proxy Port (8080) and Admin Dashboard Port (8081)
EXPOSE 8080 8081

# Create volume for database persistence
VOLUME ["/app/data"]

CMD ["python", "main.py", "--port", "8080", "--dashboard-port", "8081"]
