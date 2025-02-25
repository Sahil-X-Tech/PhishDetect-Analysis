from datetime import datetime
from database import db

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence_score = db.Column(db.Float, nullable=False)
    reported_at = db.Column(db.DateTime, default=datetime.utcnow)
    reporter_email = db.Column(db.String(120))
    report_type = db.Column(db.String(20))  # false_positive, false_negative, technical, suggestion
    description = db.Column(db.Text)
    expected_result = db.Column(db.String(20))  # safe, phishing
    actual_result = db.Column(db.String(20))    # safe, phishing

    def __repr__(self):
        return f'<Report {self.url}>'