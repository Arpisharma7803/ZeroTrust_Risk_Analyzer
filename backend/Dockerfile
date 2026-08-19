# Use Python 3.12
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements first (for caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all backend code
COPY . .

# Expose port (informational; Render assigns the real port at runtime)
EXPOSE 8000

# Start the server, binding to whatever port Render provides via $PORT
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}