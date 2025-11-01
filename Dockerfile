# Use Python 3.12 as base image
FROM python:3.12

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Ensure necessary directories exist
RUN mkdir -p /app/data /app/models /app/static /app/templates

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose port 8000 for the webapp
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "webapp.app:app", "--host", "0.0.0.0", "--port", "8000"]
