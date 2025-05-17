# === Updated server.py with Message Framing ===
import os
# Set this environment variable as early as possible
os.environ['PYTHONUNBUFFERED'] = "1"

import socket
import sys
import errno
import json
import time
import random
import struct  # <-- Import struct for packing the length

print("--- Starting server.py ---", flush=True) # Add an initial print

PORT = 5050
SERVER = '0.0.0.0'
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# Define the format for the length prefix (MUST MATCH PRODUCER)
LENGTH_STRUCT_FORMAT = '!Q' # !Q = 8 bytes unsigned long long

server = None # Initialize server to None
conn = None   # Initialize conn to None

try:
    print(f"Attempting to create socket...", flush=True)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created successfully.", flush=True)

    print(f"Attempting to bind socket to {ADDR}...", flush=True)
    server.bind(ADDR)
    print(f"Socket bound successfully to {ADDR}.", flush=True)

    print(f"Attempting to listen for connections (backlog 2)...", flush=True)
    server.listen(2)
    print(f"[LISTENING] Server is listening on {ADDR[0]}:{ADDR[1]}", flush=True)

    print(">>> Waiting for a client connection...", flush=True)
    conn, addr = server.accept() # This line waits
    print(f'CONNECTION FROM {addr} HAS BEEN ESTABLISHED', flush=True)

    connected = True
    while connected:
            try:
                # Keep the infinite loop for testing continuity
                route = ['Newyork,USA','Chennai, India','Bengaluru, India','London,UK']
                routefrom = random.choice(route)
                routeto = random.choice(route)

                if (routefrom!=routeto):
                    data = {
                        "Battery_Level": round(random.uniform(2.00, 5.00), 2),
                        "Device_ID": random.randint(1150, 1158),
                        "First_Sensor_temperature": round(random.uniform(10, 40.0), 1),
                        "Route_From": routefrom,
                        "Route_To": routeto
                        }

                    # Encode data to JSON bytes (no indentation needed)
                    userdata_bytes = json.dumps(data).encode(FORMAT)

                    # --- Message Framing ---
                    # 1. Get length of the message
                    message_length = len(userdata_bytes)

                    # 2. Pack the length into bytes using the defined format
                    length_prefix = struct.pack(LENGTH_STRUCT_FORMAT, message_length)

                    print(f"Sending Length Prefix: {message_length} bytes", flush=True)
                    print(f"Sending Data: {userdata_bytes.decode(FORMAT)}", flush=True)

                    # 3. Send the length prefix (use sendall)
                    conn.sendall(length_prefix)

                    # 4. Send the actual message data (use sendall)
                    conn.sendall(userdata_bytes)
                    # --- End Message Framing ---

                    time.sleep(10) # Wait before sending the next message

                else:
                    # Route From and To were the same, skip sending
                    print(">>> Generated same route, skipping and trying again...", flush=True)
                    time.sleep(1) # Small delay even when skipping
                    continue # Go to next iteration of the loop

            except IOError as e:
                if e.errno == errno.EPIPE:
                    print(">>> Client disconnected (Broken Pipe). Stopping loop.", flush=True)
                    connected = False # Exit the loop if client disconnects
                else:
                    print(f">>> An IOError occurred in send loop: {e}. Stopping loop.", flush=True)
                    connected = False # Exit on other IOErrors too
            except socket.error as e: # Catch potential socket errors during sendall
                 print(f">>> A Socket Error occurred in send loop: {e}. Stopping loop.", flush=True)
                 connected = False
            except Exception as e:
                 print(f">>> An unexpected error occurred in server send loop: {e}. Stopping loop.", flush=True)
                 connected = False # Exit on any other error

except socket.error as e:
    print(f"!!! Socket Error during setup (create/bind/listen): {e}", flush=True)
except Exception as e:
    print(f"!!! An unexpected error occurred during server setup: {e}", flush=True)
finally:
    # Ensure connection and server socket are closed if they were opened
    print("--- Server execution finished or error occurred. Cleaning up... ---", flush=True)
    if conn:
        try:
            conn.close()
            print(">>> Client connection closed.", flush=True)
        except Exception as e:
            print(f"Error closing client connection: {e}", flush=True)
    if server:
        try:
            server.close()
            print(">>> Server socket closed.", flush=True)
        except Exception as e:
            print(f"Error closing server socket: {e}", flush=True)
    print("--- Cleanup complete. ---", flush=True)