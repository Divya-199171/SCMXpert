FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy application files
COPY . .

# Install system dependencies (optional, useful for compiling)
RUN apt-get update && apt-get install -y build-essential

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose FastAPI default port
EXPOSE 8000

# Run app with uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
