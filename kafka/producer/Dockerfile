FROM python:3.9
WORKDIR /app
COPY producer.py .
RUN pip install kafka-python
CMD ["python", "producer.py"]
