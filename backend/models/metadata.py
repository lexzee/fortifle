from pymongo import MongoClient
from config import MONGO_URI, DB_NAME

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
meta_collection = db["file_data"]

def save_file_metadata(meta):
  meta_collection.insert_one(meta)

def get_user_files(user_id):
  return list(meta_collection.find(
    {"user_id": user_id},
    {"_id": 0, "file_name": 1, "timestamp": 1, "encrypted": 1}
  ))