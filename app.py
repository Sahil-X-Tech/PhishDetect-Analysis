import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import os
from dotenv import load_dotenv
from phishing_detector import PhishingURLDetector
import validators
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
load_dotenv()

# Configure app
app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    logger.warning("SESSION_SECRET not set. Using fallback secret key for development.")
    app.secret_key = "dev-fallback-secret-please-set-proper-secret-in-production"

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": 5,
    "pool_recycle": 1800,
    "pool_pre_ping": True,
    "connect_args": {
        "connect_timeout": 10,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 5
    }
}

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

# Import models after db initialization
from models import Report, User

# Initialize phishing detector
try:
    detector = PhishingURLDetector()
    detector.load_models('phishing_detector.joblib')
    logger.info("Model loaded successfully")
except Exception as e:
    logger.error(f"Error loading model: {str(e)}")
    detector = None

@app.route('/')
def index():
    """Home page with URL analysis functionality"""
    return render_template('index.html')

@app.route('/about')
def about():
    """About page with project information"""
    return render_template('about.html')

@app.route('/security-guide')
def security_guide():
    """Security guide page with phishing prevention tips"""
    return render_template('security-guide.html')

@app.route('/statistics')
def statistics():
    """Statistics page showing detection metrics"""
    return render_template('statistics.html')

@app.route('/documentation')
def documentation():
    """Documentation page with technical details"""
    return render_template('documentation.html')

@app.route('/faq')
def faq():
    """FAQ page with common questions"""
    return render_template('faq.html')

@app.route('/report')
def report():
    """Report page for false positives/negatives"""
    return render_template('report.html')

@app.route('/submit_report', methods=['POST'])
def submit_report():
    """Submit a new report"""
    try:
        # Check if form data or JSON data
        if request.is_json:
            data = request.json
        else:
            data = request.form

        url = data.get('url')
        actual_result = data.get('actualResult')
        report_type = data.get('reportType')

        # Validate required fields
        if not url or not actual_result or not report_type:
            logger.warning(
                f"Missing required fields in report submission: url={url}, actual_result={actual_result}, report_type={report_type}"
            )
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400

        # Create the report object
        report = Report(
            url=url,
            is_phishing=actual_result == 'phishing',
            confidence_score=1.0,  # Default confidence for manual reports
            reporter_email=data.get('email', "anonymous@user.com"),
            report_type=report_type,
            description=data.get('description', ''),
            expected_result=data.get('expectedResult', ''),
            actual_result=actual_result)

        # Add to session and commit
        db.session.add(report)
        db.session.commit()
        logger.info(f"Report submitted successfully for URL: {url}")
        return jsonify({
            'success': True,
            'message': 'Report submitted successfully'
        })
    except Exception as e:
        logger.error(f"Error submitting report: {str(e)}")
        if 'db' in globals() and hasattr(db, 'session'):
            db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing detection"""
    try:
        if detector is None:
            return jsonify({'error': 'Model not initialized. Please try again later.'}), 500

        url = request.form.get('url', '').strip()

        # Validate URL
        if not url:
            return jsonify({'error': 'Please enter a URL'}), 400

        if not validators.url(url):
            return jsonify({'error': 'Invalid URL format'}), 400

        # Get prediction
        result = detector.predict(url)

        # Extract features for visualization
        features = detector.feature_extractor.extract_features(url)

        # Prepare feature groups for visualization
        security_metrics = {
            'HTTPS': bool(features['is_https']),
            'Special Characters': features['special_char_count'],
            'Suspicious Keywords': features['suspicious_keyword_count'],
            'Suspicious TLD': bool(features['has_suspicious_tld'])
        }

        url_structure = {
            'URL Length': features['url_length'],
            'Domain Length': features['domain_length'],
            'Path Length': features['path_length'],
            'Directory Depth': features['directory_depth'],
            'Query Parameters': features['query_param_count']
        }

        suspicious_patterns = {
            'IP Address': bool(features['is_ip_address']),
            'Misspelled Domain': bool(features['has_misspelled_domain']),
            'Shortened URL': bool(features['is_shortened_url']),
            'At Symbol': bool(features['has_at_symbol']),
            'Multiple Subdomains': features['subdomain_count'] > 1
        }

        # Save report to database
        try:
            report = Report(
                url=url,
                is_phishing=result['prediction'] == 'phishing',
                confidence_score=result['confidence'],
                reporter_email="anonymous@user.com",
                report_type='automatic',
                actual_result=result['prediction']
            )
            db.session.add(report)
            db.session.commit()
        except Exception as db_error:
            logger.error(f"Error saving report to database: {str(db_error)}")

        response = {
            'prediction': result['prediction'],
            'confidence': round(result['confidence'] * 100, 2),
            'probability_phishing': round(result['probability_phishing'] * 100, 2),
            'probability_safe': round(result['probability_safe'] * 100, 2),
            'security_metrics': security_metrics,
            'url_structure': url_structure,
            'suspicious_patterns': suspicious_patterns
        }

        logger.info(f"Analysis completed for URL: {url}")
        return jsonify(response)

    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return jsonify({'error': 'Error analyzing URL. Please try again.'}), 500

@app.route('/reports')
def view_reports():
    """View all user-submitted reports (excludes automatic search reports)"""
    try:
        # Only show reports that were manually submitted (excluding 'automatic' reports)
        reports = Report.query.filter(
            Report.report_type != 'automatic').order_by(
                Report.reported_at.desc()).all()

        # Ensure description is displayed
        for report in reports:
            if not report.description:
                report.description = "No additional details provided"

        return render_template('reports.html', reports=reports)
    except Exception as e:
        logger.error(f"Error fetching reports: {str(e)}")
        return render_template('reports.html',
                               reports=[],
                               error="Error fetching reports")

@app.route('/api/check', methods=['POST'])
def check_url():
    """Simple API endpoint to check if a URL is phishing"""
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # 🔹 Replace this with your actual phishing detection logic
    is_phishing = "phish" in url.lower()

    return jsonify({"url": url, "is_phishing": is_phishing})


@app.route('/delete_reports', methods=['POST'])
def delete_reports():
    """Delete all reports"""
    try:
        Report.query.delete()
        db.session.commit()
        logger.info("All reports deleted successfully")
        return jsonify({
            'success': True,
            'message': 'All reports deleted successfully'
        })
    except Exception as e:
        logger.error(f"Error deleting reports: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/delete_selected_reports', methods=['POST'])
def delete_selected_reports():
    """Delete selected reports"""
    try:
        data = request.json
        report_ids = data.get('report_ids', [])

        if not report_ids:
            return jsonify({
                'success': False,
                'error': 'No reports selected'
            }), 400

        deleted_count = Report.query.filter(
            Report.id.in_(report_ids)).delete(synchronize_session='fetch')
        db.session.commit()

        logger.info(f"Successfully deleted {deleted_count} selected reports")
        return jsonify({
            'success': True,
            'message':
            f'Successfully deleted {deleted_count} selected reports',
            'count': deleted_count
        })
    except Exception as e:
        logger.error(f"Error deleting selected reports: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)