# RuleHub Dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install git and other dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/rules /app/index /app/tmp /app/stats /app/versions

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    RULEHUB_CONFIG_DIR=/app/config \
    RULEHUB_RULES_DIR=/app/rules \
    RULEHUB_INDEX_DIR=/app/index

# Create non-root user
RUN useradd -m rulehub
RUN chown -R rulehub:rulehub /app
USER rulehub

# Expose port if needed (e.g., for future API/web interface)
# EXPOSE 8000

# Set entrypoint
ENTRYPOINT ["python", "rulehub.py"]

# Default command (display help)
CMD ["--help"]