
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.pool import QueuePool
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)

# Get Database URL from Replit Secrets or Render Environment Variables
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL is not set. Add it to Replit Secrets or Render Env Variables."
    )

# Parse the URL to check if sslmode is already present
parsed_url = urlparse(DATABASE_URL)
query_params = parse_qs(parsed_url.query)

# Only add sslmode if it's not already in the URL
if 'sslmode' not in query_params:
    if "?" not in DATABASE_URL:
        DATABASE_URL += "?sslmode=require"
    else:
        DATABASE_URL += "&sslmode=require"

# Configure SQLAlchemy with Connection Pooling
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": 5,  # Allow up to 5 connections
    "pool_recycle": 1800,  # Recycle connections every 30 minutes
    "pool_pre_ping": True  # Test connections before using
}

# Initialize Database
db = SQLAlchemy(app)
