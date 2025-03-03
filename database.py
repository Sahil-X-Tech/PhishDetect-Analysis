import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Use the same database URL for both Replit and Render
DATABASE_URL = os.getenv("DATABASE_URL")  # Make sure this is set in Replit secrets

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set. Add it to Replit Secrets or Render Env Variables.")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)