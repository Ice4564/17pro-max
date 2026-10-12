FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Install the package
RUN pip install --no-cache-dir -e ".[dev]"

# Expose web UI port
EXPOSE 8787

# Run web server
CMD ["python", "-m", "sleuth", "--web", "--host", "0.0.0.0", "--port", "8787"]
