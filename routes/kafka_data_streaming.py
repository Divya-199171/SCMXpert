# routes/kafka_data_streaming.py
import os
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pymongo import MongoClient, DESCENDING # Import DESCENDING for sorting
from typing import Annotated # Needed for Depends syntax

# --- Attempt to import the authentication dependency ---
# This assumes your main app file is named 'app.py' and is structured
# correctly to allow this import. This might be fragile.
try:
    # Adjust 'app' if your main FastAPI file has a different name
    from app import get_required_current_user
    print("Successfully imported get_required_current_user into kafka_data_streaming.py")
except ImportError as e:
    print(f"WARN: Could not import get_required_current_user from app: {e}. Authentication will be skipped for /data-streaming.")
    # Define a dummy dependency as a fallback (will likely cause errors later if auth is truly needed)
    # Or, better, raise an error during startup if auth is mandatory.
    # For now, we'll let it proceed without auth if import fails, but add a warning.
    async def get_required_current_user() -> dict:
        print("WARNING: Running /data-streaming without authentication due to import error.")
        # Return a dummy user dict or None, depending on what your template expects minimally
        return {"name": "Guest (Auth Failed)", "role": "guest", "email": ""}

router = APIRouter()
templates = Jinja2Templates(directory="templates")


MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    print("FATAL ERROR: MONGO_URI environment variable not set.")
    raise ValueError("MONGO_URI is required but not configured.")

datastream_collection = None
try:
    print("Attempting MongoDB connection in kafka_data_streaming.py...")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000) # Add connect timeout
    # The ismaster command is cheap and does not require auth. Forces connection check.
    client.admin.command('ismaster')
    db = client['projectfast'] # Use your database name
    datastream_collection = db['datastream'] # Use the correct collection name
    print("MongoDB connection successful in kafka_data_streaming.py.")
except Exception as e:
    print(f"FATAL ERROR: Failed to connect to MongoDB in kafka_data_streaming.py: {e}")
    # If the DB connection fails here, the route won't work.
    # Option 1: Raise error to prevent app startup/inform admin
    raise RuntimeError(f"Failed to establish MongoDB connection for streaming route: {e}")
    # Option 2: Let it run, but the route will fail later (less ideal)
    # datastream_collection = None # Ensure it's None


@router.get("/data-streaming", response_class=HTMLResponse)
async def data_streaming(request: Request):
    return templates.TemplateResponse("datastream.html", {"request": request})

@router.get("/device-data", response_class=HTMLResponse)
async def data_streaming(request: Request):
    return templates.TemplateResponse("datastream.html", {"request": request})

@router.get("/api/device-data")
async def get_device_data():
    try:
        # Query all documents, sorted by latest first (optional)
        data_streams = list(datastream_collection.find().sort("_id", -1)) 
        
        for doc in data_streams:
            doc["_id"] = str(doc["_id"])  # Convert ObjectId to string for JSON serialization
            
        return {"status": "success", "data": data_streams}
    except Exception as e:
        return {"status": "error", "message": str(e)}




# --- Define the route with the correct path ---
@router.get("/data-streaming", response_class=HTMLResponse)
async def streaming_page(
    request: Request,
    # Add the authentication dependency
    current_user: Annotated[dict, Depends(get_required_current_user)]
):

    # Check if MongoDB connection succeeded during setup
    if datastream_collection is None:
         print("Error: /data-streaming called but DB connection failed during startup.")
         raise HTTPException(status_code=503, detail="Database connection is unavailable.")

    try:
        # Query the correct collection
        streaming_values = list(datastream_collection.find().sort("_id", -1)) # Get most recent first
                                

        context = {
            "request": request,
            "streaming_values": streaming_values,
            # Pass user name if needed by the base template
            "name": current_user.get("name", "User")
        }
        return templates.TemplateResponse("datastream.html", context)

    except Exception as e:
        print(f"ERROR fetching/rendering data for /data-streaming route: {e}")
        # Handle error gracefully - render the page with an error message
        context = {
            "request": request,
            "streaming_values": [], # Pass empty list on error
            "error_message": "Could not load device data due to a server error.",
             "name": current_user.get("name", "User") # Still pass name
        }
        # Render the same template but with an error message
        return templates.TemplateResponse("datastream.html", context, status_code=500)

# --- Add any other routes specific to data streaming in this file ---