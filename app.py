import logging
import os
from flask import Flask, render_template, request, jsonify
import validators
import urllib.parse
import tldextract
import re
import joblib
import numpy as np
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configure app
app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    logger.warning("SESSION_SECRET not set. Using fallback secret key for development.")
    app.secret_key = "dev-fallback-secret-please-set-proper-secret-in-production"

# Load the phishing detection model
model_path = Path('phishing_detector.joblib')
try:
    if model_path.exists():
        model = joblib.load(model_path)
        logger.info("Successfully loaded phishing detection model")
    else:
        logger.warning("Model file not found. Using fallback heuristic analysis.")
        model = None
except Exception as e:
    logger.error(f"Error loading model: {str(e)}")
    model = None

def extract_features(url):
    """Extract features from URL for model prediction"""
    parsed_url = urllib.parse.urlparse(url)
    extracted = tldextract.extract(url)

    # Extract basic features
    features = {
        'url_length': len(url),
        'has_suspicious_words': int(bool(re.search(r'login|account|secure|banking', url.lower()))),
        'uses_https': int(parsed_url.scheme == 'https'),
        'has_suspicious_tld': int(extracted.suffix in ['xyz', 'top', 'fit', 'tk', 'ml']),
        'has_ip_address': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain))),
        'has_multiple_subdomains': int(len(extracted.subdomain.split('.')) > 2 if extracted.subdomain else False),
    }

    # Convert to numpy array for model prediction
    feature_array = np.array([
        features['url_length'],
        features['has_suspicious_words'],
        features['uses_https'],
        features['has_suspicious_tld'],
        features['has_ip_address'],
        features['has_multiple_subdomains']
    ]).reshape(1, -1)

    return features, feature_array

@app.route('/')
def index():
    """Home page with URL analysis functionality"""
    return render_template('index.html')

@app.route('/statistics')
def statistics():
    """Statistics page showing analysis metrics"""
    return render_template('statistics.html')

@app.route('/about')
def about():
    """About page with project information"""
    return render_template('about.html')

@app.route('/security-guide')
def security_guide():
    """Security guide page with phishing prevention tips"""
    return render_template('security-guide.html')

@app.route('/documentation')
def documentation():
    """Documentation page with technical details"""
    return render_template('documentation.html')

@app.route('/faq')
def faq():
    """FAQ page with common questions"""
    return render_template('faq.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing indicators"""
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        if not validators.url(url):
            return jsonify({'error': 'Invalid URL format'}), 400

        logger.debug(f"Analyzing URL: {url}")

        # Extract features and get model prediction
        features, feature_array = extract_features(url)

        logger.debug(f"Extracted features: {features}")

        if model is not None:
            # Get model prediction and probability
            prediction = model.predict(feature_array)[0]
            probabilities = model.predict_proba(feature_array)[0]
            probability_safe = probabilities[0]
            probability_phishing = probabilities[1]
            is_safe = not bool(prediction)  # Model output: 0 = safe, 1 = phishing
            logger.debug(f"Model prediction: {prediction}, Probabilities: {probabilities}")
        else:
            # Fallback to heuristic analysis if model is not available
            risk_factors = {
                'length': 1 if features['url_length'] > 100 else 0,
                'suspicious_words': 2 if features['has_suspicious_words'] else 0,
                'no_https': 0 if features['uses_https'] else 2,
                'suspicious_tld': 2 if features['has_suspicious_tld'] else 0,
                'ip_address': 3 if features['has_ip_address'] else 0,
                'multiple_subdomains': 1 if features['has_multiple_subdomains'] else 0
            }
            max_score = sum(x for x in [1, 2, 2, 2, 3, 1])
            risk_score = sum(risk_factors.values()) / max_score
            probability_safe = 1 - risk_score
            probability_phishing = risk_score
            is_safe = risk_score < 0.4
            logger.debug(f"Heuristic analysis: Risk score {risk_score}")

        response_data = {
            'safe': is_safe,
            'probability_safe': float(probability_safe),
            'probability_phishing': float(probability_phishing),
            'security_metrics': {
                'HTTPS': bool(features['uses_https']),
                'Domain Age': 'Unknown',  # Would require external API
                'SSL Certificate': bool(features['uses_https'])
            },
            'url_structure': {
                'URL Length': features['url_length'],
                'Multiple Subdomains': bool(features['has_multiple_subdomains']),
                'IP Address Used': bool(features['has_ip_address'])
            },
            'suspicious_patterns': {
                'Suspicious Keywords': bool(features['has_suspicious_words']),
                'Suspicious TLD': bool(features['has_suspicious_tld'])
            }
        }

        logger.debug(f"Response data: {response_data}")
        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error analyzing URL'}), 500

# Add error handlers to return JSON
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_error(error):
    if request.is_json:
        return jsonify({
            'success': False,
            'error': str(error)
        }), error.code
    return render_template('error.html', error=error), error.code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)