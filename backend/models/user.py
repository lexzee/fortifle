from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import base64
import os

from config import MONGO_URI, DB_NAME

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_collection = db["users"]

def test_mongo_connection():
  try:
    client.admin.command('ping')
    print("Connection Successful")
  except ConnectionError as e:
    print(f"Failed to connect: {e}")

def create_user(email, name, password):
  if users_collection.find_one({"email": email}):
    return False, "User already exists"

  user_doc = {
    "email": email,
    "name": name,
    "password_hash": generate_password_hash(password),
    "auth_provider": "email",
    "created_at": datetime.now()
  }

  users_collection.insert_one(user_doc)
  return True, "User created"

def verify_user(email, password):
  user = users_collection.find_one({"email": email})
  if not user:
    return False, "User not found"
  if not check_password_hash(user["password_hash"], password):
    return False, "Invalid Credentials"

  return True, user