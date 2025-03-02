import os
import logging
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

# Configure logging
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

def init_db(app):
    # Configure SQLAlchemy
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        # Add SSL mode if not already present
        if "sslmode=" not in database_url.lower():
            if "?" in database_url:
                database_url += "&sslmode=require"
            else:
                database_url += "?sslmode=require"

        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    else:
        raise RuntimeError("DATABASE_URL is not set")

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "connect_args": {
            "sslmode": "require"
        }
    }

    # Initialize the app with the extension
    db.init_app(app)

    # Test database connection
    try:
        with app.app_context():
            # Execute test query
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            logger.info("Database connection test successful")
    except Exception as e:
        logger.error(f"Database connection test failed: {str(e)}")
        raise RuntimeError(f"Failed to connect to database: {str(e)}")