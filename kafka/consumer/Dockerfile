FROM python:3.9
WORKDIR /app
COPY consumer.py .
RUN pip install kafka-python pymongo
CMD ["python", "consumer.py"]
