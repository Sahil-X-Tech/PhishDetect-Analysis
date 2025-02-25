import os
from flask import Flask, render_template, request, jsonify
import logging
from phishing_detector import PhishingURLDetector
import validators
from datetime import datetime
from database import db
from models import Report

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# Configure SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///phishing.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
# initialize the app with the extension
db.init_app(app)

# Initialize and load the model
detector = PhishingURLDetector()
try:
    detector.load_models('attached_assets/phishing_detector.joblib')
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

@app.route('/reports')
def view_reports():
    """View all submitted reports"""
    try:
        reports = Report.query.order_by(Report.reported_at.desc()).all()
        return render_template('reports.html', reports=reports)
    except Exception as e:
        logger.error(f"Error fetching reports: {str(e)}")
        return render_template('reports.html', reports=[], error="Error fetching reports")

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing detection"""
    if detector is None:
        return jsonify({'error': 'Model not initialized. Please try again later.'}), 500

    url = request.form.get('url', '').strip()

    # Validate URL
    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400

    if not validators.url(url):
        return jsonify({'error': 'Invalid URL format'}), 400

    try:
        # Get prediction
        result = detector.predict(url)

        # Save report to database
        report = Report(
            url=url,
            is_phishing=result['prediction'] == 'phishing',
            confidence_score=result['confidence']
        )
        db.session.add(report)
        db.session.commit()

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
        logger.debug(f"Prediction result: {result}")

        return jsonify(response)

    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return jsonify({'error': 'Error analyzing URL. Please try again.'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)