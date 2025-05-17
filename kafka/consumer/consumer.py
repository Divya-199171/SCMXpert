# === Consumer.py - Corrected MongoDB Collection Check ===
import os
# Set PYTHONUNBUFFERED if running outside Docker compose with env vars
# os.environ['PYTHONUNBUFFERED'] = "1" # Already set via Dockerfile usually

from kafka import KafkaConsumer # Correct class name
import json
import pymongo
import sys
import time

print("[Consumer] Starting consumer.py...", flush=True)

# Mogodb Connection Parameters
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("[Consumer] ERROR: DATABASE_URL environment variable not set. Exiting.", flush=True)
    sys.exit(1)

DB_NAME = "projectfast" # Or read from env if needed
COLLECTION_NAME = "datastream" # Or read from env if needed

# Retry MongoDB connection
db_client = None
db = None
collection = None
db_attempts = 0
max_db_attempts = 10 # Increase attempts for potentially slower Atlas connection
while collection is None and db_attempts < max_db_attempts: # Loop until collection is assigned or max attempts reached
    db_attempts += 1
    print(f"[Consumer] Attempt {db_attempts}/{max_db_attempts}: Connecting to MongoDB at {DATABASE_URL[:30]}...", flush=True) # Log truncated URL
    try:
        # Add timeout to prevent hanging indefinitely
        db_client = pymongo.MongoClient(DATABASE_URL, serverSelectionTimeoutMS=5000) # 5 second timeout
        # The ismaster command is cheap and does not require auth. Forces connection check.
        db_client.admin.command('ismaster')
        db = db_client[DB_NAME]
        collection = db[COLLECTION_NAME] # Assign the collection object here
        print(f"[Consumer] Successfully connected to MongoDB. DB: '{DB_NAME}', Collection: '{COLLECTION_NAME}'.", flush=True)
        # If successful, the loop condition 'collection is None' becomes false, and the loop exits.

    except pymongo.errors.ConfigurationError as e:
        print(f"[Consumer] MongoDB Configuration Error: {e}. Check DATABASE_URL format.", flush=True)
        # No point retrying on config error usually
        print("[Consumer] Exiting due to MongoDB configuration error.", flush=True)
        if db_client: db_client.close()
        sys.exit(1)
    except pymongo.errors.ConnectionFailure as e:
        print(f"[Consumer] Failed to connect to MongoDB: {e}", flush=True)
        if db_client: db_client.close() # Close potentially partially opened client
        db_client = None # Reset client for retry logic
        collection = None # Ensure collection is None if connection failed
        if db_attempts >= max_db_attempts:
             print("[Consumer] Max MongoDB connection attempts reached.", flush=True)
             # No exit here yet, let the final check handle it
             break # Exit retry loop
        print("[Consumer] Retrying MongoDB connection in 10 seconds...", flush=True)
        time.sleep(10) # Longer sleep for external connections
    except Exception as e: # Catch other potential errors
        print(f"[Consumer] An unexpected error occurred during MongoDB connection: {e}", flush=True)
        if db_client: db_client.close()
        db_client = None # Reset client for retry logic
        collection = None # Ensure collection is None if connection failed
        if db_attempts >= max_db_attempts:
             print("[Consumer] Max MongoDB connection attempts reached.", flush=True)
             # No exit here yet, let the final check handle it
             break # Exit retry loop
        print("[Consumer] Retrying MongoDB connection in 10 seconds...", flush=True)
        time.sleep(10)

# *** CORRECTED CHECK ***
if collection is None:
    print("[Consumer] Could not establish MongoDB collection object after attempts. Exiting.", flush=True)
    if db_client: db_client.close() # Close client if exiting
    sys.exit(1)
# ***********************


# Kafka Parameters
KAFKA_BROKER = os.getenv("KAFKA_BROKER", 'kafka:9092') # Get from env or default
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", 'sensor-data') # Get from env or default
CONSUMER_GROUP_ID = 'sensor-data-consumer-group' # Define a group ID

print(f"[Consumer] Kafka Broker: {KAFKA_BROKER}", flush=True)
print(f"[Consumer] Kafka Topic: {KAFKA_TOPIC}", flush=True)
print(f"[Consumer] Consumer Group ID: {CONSUMER_GROUP_ID}", flush=True)


# Create a Kafka consumer instance with retries
consumer = None
kafka_attempts = 0
max_kafka_attempts = 10 # Increase attempts
while not consumer and kafka_attempts < max_kafka_attempts:
     kafka_attempts += 1
     print(f"[Consumer] Attempt {kafka_attempts}/{max_kafka_attempts}: Connecting to Kafka Broker {KAFKA_BROKER}...", flush=True)
     try:
         consumer = KafkaConsumer(
             KAFKA_TOPIC,
             bootstrap_servers=KAFKA_BROKER,
             value_deserializer=lambda x: json.loads(x.decode('utf-8')),
             auto_offset_reset='earliest',
             group_id=CONSUMER_GROUP_ID,
             consumer_timeout_ms=-1,
         )
         topics = consumer.topics()
         print(f"[Consumer] Successfully connected to Kafka. Available topics include: {topics}", flush=True)
         if KAFKA_TOPIC not in topics:
             print(f"[Consumer] WARNING: Subscribed topic '{KAFKA_TOPIC}' not yet found in broker topics. It might be created automatically.", flush=True)

     except Exception as e:
         print(f"[Consumer] Failed to connect to Kafka or subscribe: {e}", flush=True)
         if consumer:
             consumer.close()
         consumer = None
         if kafka_attempts >= max_kafka_attempts:
              print("[Consumer] Max Kafka connection attempts reached. Exiting.", flush=True)
              if db_client: db_client.close() # Close DB connection on exit
              sys.exit(1)
         print("[Consumer] Retrying Kafka connection in 10 seconds...", flush=True)
         time.sleep(10)


if not consumer: # Checking the consumer object itself like this is usually okay
    print("[Consumer] Could not connect to Kafka after multiple attempts. Exiting.", flush=True)
    if db_client: db_client.close()
    sys.exit(1)

print(f"[Consumer] Starting to listen for messages on topic '{KAFKA_TOPIC}'...", flush=True)
# Consume messages
try:
    for message in consumer:
        try:
            msg_value = message.value
            print(f"[Consumer] Received from Kafka (Topic: {message.topic}, Partition: {message.partition}, Offset: {message.offset}): {msg_value}", flush=True)

            print(f"[Consumer] Inserting into MongoDB collection '{COLLECTION_NAME}'...", flush=True)
            insert_result = collection.insert_one(msg_value)
            print(f"[Consumer] Successfully inserted document with ID: {insert_result.inserted_id}", flush=True)

        except pymongo.errors.PyMongoError as e:
            print(f"[Consumer] MongoDB Error inserting document: {e}", flush=True)
            print(f"[Consumer] Failed document: {msg_value}", flush=True)
        except json.JSONDecodeError as e:
             print(f"[Consumer] Error: Could not deserialize message value from Kafka: {e}", flush=True)
             print(f"[Consumer] Raw message value: {message.value}", flush=True)
        except Exception as e:
            print(f"[Consumer] Unexpected error processing message or inserting into DB: {e}", flush=True)
            print(f"[Consumer] Problematic message value: {message.value}", flush=True)

except KeyboardInterrupt:
    print("\n[Consumer] KeyboardInterrupt received. Shutting down...", flush=True)
except Exception as e:
    print(f"[Consumer] An unexpected error occurred in Kafka consumer loop: {e}", flush=True)
finally:
    print("[Consumer] Closing Kafka consumer...", flush=True)
    if consumer:
        consumer.close()
        print("[Consumer] Kafka consumer closed.", flush=True)
    print("[Consumer] Closing MongoDB connection...", flush=True)
    if db_client:
        db_client.close()
        print("[Consumer] MongoDB connection closed.", flush=True)
    print("[Consumer] Cleanup complete.", flush=True)