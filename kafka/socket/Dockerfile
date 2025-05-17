FROM python:3.9

WORKDIR /app

# Copy server.py and requirements.txt
COPY server.py .


# Install the dependencies from requirements.txt
RUN pip install --no-cache-dir kafka-python pymongo

# Expose the necessary port (if applicable)
EXPOSE 5050

# Command to run the server
CMD ["python", "server.py"]
