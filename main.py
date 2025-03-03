
from app import app

if __name__ == "__main__":
    with app.app_context():
        from database import db
        db.create_all()
        from app import create_admin_user
        create_admin_user()
    app.run(host="0.0.0.0", port=8080, debug=True)
