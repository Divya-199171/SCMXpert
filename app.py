import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Annotated # Use Annotated for Depends
from fastapi import FastAPI, Request, Form, status, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient
from passlib.context import CryptContext
import requests
from jose import JWTError, jwt # Import JWT handling
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv # Import dotenv
from routes import createshipment, manage_users , allshipments , kafka_data_streaming, user
from pymongo import DESCENDING
import threading
import time
from core.admin import create_default_admin

app = FastAPI()


create_default_admin()
# Static files 
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates 
templates = Jinja2Templates(directory="templates")

MONGO_URI = os.getenv("MONGO_URI")
# And use it when creating your MongoDB client
client = MongoClient(MONGO_URI)
# Routes 

app.include_router(manage_users.router,tags=["Manage users"])
app.include_router(allshipments.router,tags=["all shipments"])
app.include_router(user.router,tags=["users"])
app.include_router(createshipment.router,tags=["create shipment"])
app.include_router(kafka_data_streaming.router,tags=["kafka"])



if __name__ == "__main__":

    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)