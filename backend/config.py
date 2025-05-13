import os
from dotenv import load_dotenv
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongo://localhost:27017")
DB_NAME = "fortifile"
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "googleclientid")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "googleclientsecret")
GOOGLE_API_SCOPE = os.getenv("GOOGLE_API_SCOPE", "api scope")
GOOGLE_OAUTH2_URL = os.getenv("GOOGLE_OAUTH2_URL", "Oauth2 url")
GOOGLE_API_URL = os.getenv("GOOGLE_API_URL", "base url")