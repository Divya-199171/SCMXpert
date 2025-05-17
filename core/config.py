# app/core/config.py

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)

# Environment config values
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1"))
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
MONGO_URI = os.getenv("MONGO_URI")

# Check for missing critical env variables
if not all([SECRET_KEY, ALGORITHM, RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY, MONGO_URI]):
    raise ValueError("Missing critical environment variables. Check your .env file.")
