# Sample Dockerfile for testing container image vulnerability scanning
# Uses python:3.12-slim for a more current base image with fewer OS-level CVEs.
# Intentionally vulnerable Python dependencies are preserved in requirements.txt
# so that Trivy dependency scanning still demonstrates vulnerability detection.
FROM python:3.12-slim

WORKDIR /app

# Patch OS-level packages to fix CRITICAL CVEs (OpenSSL, perl-base)
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency definition and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]
