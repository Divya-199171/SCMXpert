from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import os
from fastapi import Form
from fastapi.responses import RedirectResponse
from fastapi import status
from core.auth import get_required_current_user, get_current_admin_user
from fastapi import APIRouter, Request, Form, Depends

# Load .env variables
load_dotenv()

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# MongoDB connection using MONGO_URI from .env
client = MongoClient(os.getenv("MONGO_URI"))
db = client['projectfast']
users_collection = db['user']

@router.get("/Manageusers")
async def manage_users(request: Request, current_user: dict = Depends(get_current_admin_user)):
    users = list(users_collection.find())

    for user in users:
        user['_id'] = str(user['_id'])


    return templates.TemplateResponse("manage_users.html", {
        "request": request,
        "users": users
    })

@router.get("/edit_user/{user_id}")
async def edit_user(request: Request, user_id: str, current_user: dict = Depends(get_current_admin_user)):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        user['_id'] = str(user['_id'])
        return templates.TemplateResponse("edit_user.html", {"request": request, "user": user})
    return RedirectResponse(url="/Manageusers", status_code=status.HTTP_302_FOUND)

@router.post("/edit_user/{user_id}")
async def update_user(user_id: str, name: str = Form(...), email: str = Form(...), role: str = Form(...), current_user: dict = Depends(get_current_admin_user)):
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"name": name, "email": email, "role": role}}
    )
    return RedirectResponse(url="/Manageusers", status_code=status.HTTP_302_FOUND)

@router.post("/delete_user/{user_id}")
async def delete_user(user_id: str):
    users_collection.delete_one({"_id": ObjectId(user_id)})
    return RedirectResponse(url="/Manageusers", status_code=status.HTTP_302_FOUND)

