# app/core/database.py

from pymongo import MongoClient
from core.config import MONGO_URI

client = MongoClient(MONGO_URI)
db = client["projectfast"]

# Collections
users_collection = db["user"]
logins_collection = db["logins"]
shipments_collection = db["shipments"]
datastream_collection = db["datastream"]

