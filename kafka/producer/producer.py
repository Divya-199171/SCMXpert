# === Updated producer.py with Message Framing ===
import socket
from kafka import KafkaProducer
import json
import time
import sys
import struct  # <-- Import struct for unpacking the length

FORMAT = 'utf-8'
SERVER = 'socket'  # Docker service name for the server
PORT = 5050
ADDR = (SERVER, PORT)
KAFKA_BROKER = 'kafka:9092'
KAFKA_TOPIC = 'sensor-data' # Make sure this matches the consumer

# Define the format used by the server for the length prefix (MUST MATCH SERVER)
LENGTH_STRUCT_FORMAT = '!Q' # !Q = 8 bytes unsigned long long
LENGTH_PREFIX_SIZE = struct.calcsize(LENGTH_STRUCT_FORMAT)

# Configure Kafka Producer with Retries
producer = None
kafka_connection_attempts = 0
max_kafka_connection_attempts = 5
while producer is None and kafka_connection_attempts < max_kafka_connection_attempts:
    kafka_connection_attempts += 1
    try:
        print(f"[Producer] Attempt {kafka_connection_attempts}/{max_kafka_connection_attempts}: Connecting to Kafka Broker at {KAFKA_BROKER}...", flush=True)
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKER,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            retries=5,
            linger_ms=100
        )
        print("[Producer] Successfully connected to Kafka.", flush=True)
    except Exception as e:
        print(f"[Producer] Failed to connect to Kafka: {e}", flush=True)
        if kafka_connection_attempts >= max_kafka_connection_attempts:
             print("[Producer] Max Kafka connection attempts reached. Exiting.", flush=True)
             sys.exit(1)
        print("[Producer] Retrying Kafka connection in 5 seconds...", flush=True)
        time.sleep(5)

if not producer:
     print("[Producer] Could not establish connection to Kafka. Exiting.", flush=True)
     sys.exit(1)


# Connect to Socket Server with Retries
client_socket = None
socket_attempts = 0
max_socket_attempts = 12 # Try for ~60 seconds
while not client_socket and socket_attempts < max_socket_attempts:
    socket_attempts += 1
    print(f"[Producer] Attempt {socket_attempts}/{max_socket_attempts}: Connecting to Socket Server {SERVER}:{PORT}...", flush=True)
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(5) # Timeout for connection attempt
        client_socket.connect(ADDR)
        client_socket.settimeout(None) # Reset timeout for blocking recv
        print("[Producer] Successfully connected to Socket Server.", flush=True)
    except socket.timeout:
        print(f"[Producer] Connection attempt timed out.", flush=True)
        if client_socket: client_socket.close()
        client_socket = None
        if socket_attempts >= max_socket_attempts:
            print("[Producer] Max connection attempts reached. Exiting.", flush=True)
            sys.exit(1)
        print("[Producer] Retrying Socket connection in 5 seconds...", flush=True)
        time.sleep(5)
    except socket.error as e:
        print(f"[Producer] Socket connection failed: {e}", flush=True)
        if client_socket: client_socket.close()
        client_socket = None
        if socket_attempts >= max_socket_attempts:
            print("[Producer] Max connection attempts reached. Exiting.", flush=True)
            sys.exit(1)
        print("[Producer] Retrying Socket connection in 5 seconds...", flush=True)
        time.sleep(5)
    except Exception as e: # Catch any other unexpected error during connection
        print(f"[Producer] Unexpected error during socket connection: {e}", flush=True)
        if client_socket: client_socket.close()
        client_socket = None
        if socket_attempts >= max_socket_attempts:
            print("[Producer] Max connection attempts reached. Exiting.", flush=True)
            sys.exit(1)
        print("[Producer] Retrying Socket connection in 5 seconds...", flush=True)
        time.sleep(5)


# Only proceed if connection was successful
if not client_socket:
    print("[Producer] Could not connect to Socket Server after multiple attempts. Exiting.", flush=True)
    if producer: producer.close() # Close Kafka producer if socket failed
    sys.exit(1)

print("[Producer] Starting to receive data from Socket Server...", flush=True)

try:
    while True:
        message_body = None # Reset for each new message attempt
        message_body_bytes = b''
        try:
            # --- Receive Framed Message ---
            # 1. Receive the length prefix (exactly LENGTH_PREFIX_SIZE bytes)
            length_prefix_bytes = b''
            bytes_recd = 0
            while bytes_recd < LENGTH_PREFIX_SIZE:
                # Read exactly the remaining bytes needed for the prefix
                chunk = client_socket.recv(LENGTH_PREFIX_SIZE - bytes_recd)
                if not chunk:
                    print("[Producer] Socket connection broken while receiving length prefix. Exiting.", flush=True)
                    raise ConnectionError("Socket closed prematurely receiving length")
                length_prefix_bytes += chunk
                bytes_recd = len(length_prefix_bytes)

            # Ensure we got the full prefix (should be guaranteed by the loop above, but check)
            if len(length_prefix_bytes) != LENGTH_PREFIX_SIZE:
                 print(f"[Producer] Error: Received incomplete length prefix ({len(length_prefix_bytes)} bytes). Protocol desync likely. Exiting.", flush=True)
                 raise ConnectionError("Incomplete length prefix received")

            # 2. Unpack the length prefix
            message_length = struct.unpack(LENGTH_STRUCT_FORMAT, length_prefix_bytes)[0]
            print(f"[Producer] Received length prefix: Expecting {message_length} bytes for message body.", flush=True)

            # 3. Receive the message body (exactly message_length bytes)
            message_body_bytes = b''
            bytes_recd = 0
            while bytes_recd < message_length:
                # Request remaining bytes needed, but recv might return less
                bytes_to_recv = min(message_length - bytes_recd, 4096) # Read in chunks up to 4KB
                chunk = client_socket.recv(bytes_to_recv)
                if not chunk:
                    print("[Producer] Socket connection broken while receiving message body. Exiting.", flush=True)
                    raise ConnectionError("Socket closed prematurely receiving body")
                message_body_bytes += chunk
                bytes_recd = len(message_body_bytes)
                # print(f"[Producer] Received chunk: {len(chunk)} bytes, Total body received: {bytes_recd}/{message_length}", flush=True) # Optional detailed logging

            # Ensure we received the full message body
            if len(message_body_bytes) != message_length:
                 print(f"[Producer] Error: Received incomplete message body ({len(message_body_bytes)}/{message_length} bytes). Skipping message.", flush=True)
                 continue # Skip this message and try to receive the next length prefix

            # 4. Decode the complete message body bytes to a string
            message_body = message_body_bytes.decode(FORMAT)

            # 5. Parse the string as JSON
            message = json.loads(message_body)
            # --- End Receive Framed Message ---

            print(f"[Producer] Successfully received and parsed message: {message}", flush=True)
            print(f"[Producer] Sending to Kafka topic '{KAFKA_TOPIC}'...", flush=True)
            producer.send(KAFKA_TOPIC, message)
            # producer.flush() # Optional: Flush immediately if needed for lower latency visibility

        except ConnectionError as e: # Catch explicit ConnectionErrors raised above
             print(f"[Producer] Connection Error: {e}", flush=True)
             break # Exit the main while loop
        except struct.error as e:
             print(f"[Producer] Error unpacking length prefix: {e}. Malformed data stream? Exiting.", flush=True)
             break # Exit loop
        except socket.timeout:
             # This shouldn't happen with settimeout(None), but good practice
             print("[Producer] Socket recv timed out (unexpected). Continuing...", flush=True)
             continue
        except socket.error as e:
             print(f"[Producer] Socket error during recv: {e}. Exiting.", flush=True)
             break # Exit loop on other socket errors
        except UnicodeDecodeError as e:
             print(f"[Producer] Error decoding message body bytes: {e}", flush=True)
             print(f"[Producer] Problematic bytes (first 100): {message_body_bytes[:100]}", flush=True)
             continue # Skip this potentially corrupt message
        except json.JSONDecodeError as e:
             print(f"[Producer] Error decoding JSON from message body: {e}", flush=True)
             print(f"[Producer] Received problematic body string: {message_body}", flush=True)
             continue # Skip this malformed JSON message
        except Exception as e:
             # Catch any other unexpected error within the loop
             print(f"[Producer] An unexpected error occurred in receive/process loop: {e}", flush=True)
             # Depending on the error, you might want to 'continue' or 'break'
             break # Exit loop for safety on unknown errors

except KeyboardInterrupt:
    print("\n[Producer] KeyboardInterrupt received. Shutting down...", flush=True)
finally:
    # Ensure resources are cleaned up regardless of how the loop exited
    if client_socket:
        try:
            client_socket.close()
            print("[Producer] Socket connection closed.", flush=True)
        except Exception as e:
             print(f"[Producer] Error closing socket: {e}", flush=True)
    if producer:
        try:
            print("[Producer] Flushing remaining Kafka messages...", flush=True)
            producer.flush(timeout=10) # Wait up to 10s for messages to send
            print("[Producer] Closing Kafka producer.", flush=True)
            producer.close(timeout=10)
        except Exception as e:
             print(f"[Producer] Error flushing/closing Kafka producer: {e}", flush=True)
    print("[Producer] Cleanup complete.", flush=True)