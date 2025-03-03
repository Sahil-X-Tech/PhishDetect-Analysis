import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from urllib.parse import urlparse, parse_qs

db = SQLAlchemy()

app = Flask(__name__)

# Get database URL from environment variables
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL is not set. Add it to Replit Secrets or Environment Variables."
    )

# Parse the URL to check if sslmode is already present
parsed_url = urlparse(DATABASE_URL)
query_params = parse_qs(parsed_url.query)

# Only add sslmode if it's not already in the URL and if it's a postgres URL
if 'postgres' in DATABASE_URL and 'sslmode' not in query_params:
    if "?" not in DATABASE_URL:
        DATABASE_URL += "?sslmode=require"
    else:
        DATABASE_URL += "&sslmode=require"

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": 5,  # Allow up to 5 connections
    "pool_recycle": 1800,  # Recycle connections every 30 minutes
    "pool_pre_ping": True  # Test connections before using
}

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Enable Flask-Migrate
