# core/admin.py

from datetime import datetime, timezone
from core.auth import get_password_hash
from core.database import users_collection
from core.config import DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD

def create_default_admin():
    if not DEFAULT_ADMIN_EMAIL or not DEFAULT_ADMIN_PASSWORD:
        print("Admin email/password not set in .env")
        return

    if not users_collection.find_one({"email": DEFAULT_ADMIN_EMAIL}):
        users_collection.insert_one({
            "name": "Admin User",
            "email": DEFAULT_ADMIN_EMAIL,
            "password_hash": get_password_hash(DEFAULT_ADMIN_PASSWORD),
            "role": "admin",
            "created_at": datetime.now(timezone.utc)
        })
        print(f"Default admin user '{DEFAULT_ADMIN_EMAIL}' created.")
    else:
        print(f"Admin user '{DEFAULT_ADMIN_EMAIL}' already exists.")
