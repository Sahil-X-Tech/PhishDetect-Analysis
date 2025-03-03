import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize db object
db = SQLAlchemy()

app = Flask(__name__)

# Get database URL from environment variables
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Fallback to Render database URL if not provided
    DATABASE_URL = "postgresql://phishing_db_user:ffBzIYjtFjLrRbdfjlXzYSRKX9xIzzCX@dpg-cv3126bqf0us7382uu5g-a.oregon-postgres.render.com/phishing_db"
    logger.warning("DATABASE_URL not found in environment, using fallback URL")

# Fix Render Postgres URL format if needed (Render provides "postgres://" but SQLAlchemy needs "postgresql://")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    logger.info("Updated DATABASE_URL format for SQLAlchemy compatibility")

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
    "pool_pre_ping": True,  # Test connections before using
    "connect_args": {
        "connect_timeout": 10,  # Increase connection timeout
        "keepalives": 1,        # Enable keepalives
        "keepalives_idle": 30,  # Idle time before sending keepalives
        "keepalives_interval": 10,  # Interval between keepalives
        "keepalives_count": 5   # Number of keepalives before closing
    }
}

# Initialize SQLAlchemy with the app
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Enable Flask-Migrate

logger.info("Database initialization completed successfully")
