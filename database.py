import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.pool import QueuePool

app = Flask(__name__)

# Get Database URL from Replit Secrets or Render Environment Variables
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL is not set. Add it to Replit Secrets or Render Env Variables."
    )

# Ensure SSL connection for Render
if "?" not in DATABASE_URL:
    DATABASE_URL += "?sslmode=require"
else:
    # If URL already has parameters, add SSL mode as another parameter
    DATABASE_URL += "&sslmode=require" if "&" in DATABASE_URL else "&sslmode=require"

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
