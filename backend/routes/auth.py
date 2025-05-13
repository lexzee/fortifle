from flask import Blueprint, request, jsonify, redirect, url_for, session
from flask_jwt_extended import create_access_token

from flask_dance.contrib.google import make_google_blueprint, google
from datetime import datetime
from werkzeug.security import check_password_hash
import os
from uuid import uuid4
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError

from models.user import users_collection
from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

# Blueprint
auth_bp = Blueprint('auth_bp', __name__)

google_bp = make_google_blueprint(
  client_id=GOOGLE_CLIENT_ID,
  client_secret=GOOGLE_CLIENT_SECRET,
  scope=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
  redirect_url="/auth/google/callback"
)

# Email/Password Login
@auth_bp.route('/login', methods=['POST'])
def login():
  data = request.get_json()
  email = data.get("email")
  password = data.get("password")

  user = users_collection.find_one({"email": email})
  if not user:
    return jsonify({"success": False, "message": "user not found"}), 404

  if not check_password_hash(user["password_hash"],password):
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

  access_token = create_access_token(identity=str(user["_id"]))
  return jsonify({"success": True, "token": access_token, "user_id": str(user["_id"]), "name": user["name"]}), 200

# Google OAuth login
# @GET "/login/google"
@auth_bp.route('/login/google')
def login_google():
  if not google.authorized:
    return redirect(url_for("google.login"))
  return redirect(url_for("auth_bp.google_callback"))

# Callback
@auth_bp.route("/google/callback")
def google_callback():
  if not google.authorized:
    return redirect(url_for("google.login"))

  try:
    res = google.get("/oauth2/v2/userinfo")
  except TokenExpiredError:
    return redirect(url_for("google.login"))

  if not res.ok:
    return jsonify({"success": False, "message": "Failed to fetch user info"}), 400

  info = res.json()
  email = info["email"]
  name = info["given_name"]
  picture = info["picture"]

  user = users_collection.find_one({"email": email})
  if not user:
    users_collection.insert_one({
      "email": email,
      "name": name,
      "auth_provider": "google",
      "created_at": datetime.now(),
      "picture": picture
    })

    user = users_collection.find_one({"email": email})
  access_token = create_access_token(identity=str(user["_id"]))

  return redirect(f"http://localhost:5173/oauth-success?token={access_token}&name={user["name"]}&id={user["_id"]}")
