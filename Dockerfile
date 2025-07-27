# Multi-stage Dockerfile for Betting App Security Test Framework

# Stage 1: Base Python environment
FROM python:3.10-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    unzip \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt requirements-dev.txt ./
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install -r requirements-dev.txt

# Stage 2: Mock Server
FROM base as mock-server

# Copy mock server files
COPY mock_server/ ./mock_server/
COPY test_data/ ./test_data/

# Create directories for logs and reports
RUN mkdir -p logs reports

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Start mock server
CMD ["python", "mock_server/app.py"]

# Stage 3: Test Environment
FROM base as test-environment

# Install additional testing tools
RUN pip install \
    locust \
    bandit[toml] \
    safety \
    pytest-xdist \
    pytest-cov \
    allure-pytest

# Install Node.js for Appium (if needed)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g appium@2.0.0 && \
    npm install -g appium-doctor

# Copy all application files
COPY . .

# Create necessary directories
RUN mkdir -p logs reports screenshots

# Make scripts executable
RUN chmod +x run_tests.sh

# Default command for testing
CMD ["./run_tests.sh", "all"]

# Stage 4: Locust Load Testing
FROM base as load-testing

# Install Locust
RUN pip install locust

# Copy performance testing files
COPY performance/ ./performance/
COPY test_data/ ./test_data/

# Expose Locust web interface
EXPOSE 8089

# Default Locust command
CMD ["locust", "-f", "performance/locustfile.py", "--host=http://betting-mock-server:5000"]