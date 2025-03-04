from datetime import datetime
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Report(db.Model):
    __tablename__ = 'report'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence_score = db.Column(db.Float, nullable=False)
    reported_at = db.Column(db.DateTime, default=datetime.utcnow)
    reporter_email = db.Column(db.String(120))
    report_type = db.Column(db.String(20))  # false_positive, false_negative, technical, suggestion, automatic
    description = db.Column(db.Text)
    expected_result = db.Column(db.String(20))  # safe, phishing
    actual_result = db.Column(db.String(20))  # safe, phishing

    def __repr__(self):
        return f'<Report {self.url}>'