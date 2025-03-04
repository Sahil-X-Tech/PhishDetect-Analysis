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
import difflib

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    logger.warning("SESSION_SECRET not set. Using fallback secret key for development.")
    app.secret_key = "dev-fallback-secret-please-set-proper-secret-in-production"

# List of common legitimate domains for similarity checking
LEGITIMATE_DOMAINS = [
    'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'twitter.com', 'instagram.com', 'linkedin.com'
]

def extract_features(url):
    """Extract features from URL for model prediction"""
    parsed_url = urllib.parse.urlparse(url)
    extracted = tldextract.extract(url)
    path_segments = [segment for segment in parsed_url.path.split('/') if segment]

    # Check for domain similarity with legitimate domains
    domain_with_suffix = f"{extracted.domain}.{extracted.suffix}"
    similar_domains = []
    for legitimate_domain in LEGITIMATE_DOMAINS:
        similarity = difflib.SequenceMatcher(None, domain_with_suffix.lower(), legitimate_domain).ratio()
        if similarity > 0.8 and domain_with_suffix.lower() != legitimate_domain:
            similar_domains.append(legitimate_domain)

    # Extract basic features
    features = {
        # URL Structure Features
        'url_length': len(url),
        'domain_length': len(extracted.domain),
        'path_length': len(path_segments),
        'num_digits': sum(c.isdigit() for c in url),
        'num_parameters': len(urllib.parse.parse_qs(parsed_url.query)),

        # Security Features
        'uses_https': parsed_url.scheme == 'https',
        'has_port': bool(parsed_url.port),
        'has_special_chars': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', url)),

        # Suspicious Patterns
        'has_at_symbol': '@' in url,
        'has_ip_address': bool(re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain)),
        'is_misspelled_domain': len(similar_domains) > 0,
        'has_multiple_subdomains': len(extracted.subdomain.split('.')) > 2 if extracted.subdomain else False,
        'is_shortened_url': len(extracted.domain) <= 4 or any(short in extracted.domain for short in ['bit.ly', 'goo.gl', 't.co', 'tiny']),
        'has_suspicious_tld': extracted.suffix in ['xyz', 'top', 'fit', 'tk', 'ml', 'ga', 'cf', 'gq', 'nl'],
        'has_suspicious_keywords': bool(re.search(r'login|account|secure|banking|update|verify|signin|security', url.lower())),
        'has_suspicious_patterns': bool(re.search(r'(auth|log[io]n|verify|secure|account|update|service|confirm)', url.lower()))
    }

    return features

@app.route('/')
def index():
    """Home page with URL analysis functionality"""
    return render_template('index.html')

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
        features = extract_features(url)

        # Calculate risk score based on weighted features
        risk_factors = {
            'url_length': 1 if features['url_length'] > 75 else 0,
            'has_suspicious_keywords': 3 if features['has_suspicious_keywords'] else 0,
            'no_https': 0 if features['uses_https'] else 2,
            'suspicious_tld': 2 if features['has_suspicious_tld'] else 0,
            'ip_address': 3 if features['has_ip_address'] else 0,
            'multiple_subdomains': 2 if features['has_multiple_subdomains'] else 0,
            'special_chars': 1 if features['has_special_chars'] else 0,
            'at_symbol': 2 if features['has_at_symbol'] else 0,
            'misspelled_domain': 3 if features['is_misspelled_domain'] else 0,
            'shortened_url': 2 if features['is_shortened_url'] else 0,
            'suspicious_patterns': 2 if features['has_suspicious_patterns'] else 0
        }

        max_score = sum(x for x in [1, 3, 2, 2, 3, 2, 1, 2, 3, 2, 2])
        risk_score = sum(risk_factors.values()) / max_score

        response_data = {
            'safe': risk_score < 0.4,
            'probability_safe': float(1 - risk_score),
            'probability_phishing': float(risk_score),
            'security_metrics': {
                'HTTPS': features['uses_https'],
                'Special Characters': features['has_special_chars'],
                'Suspicious Keywords': features['has_suspicious_keywords'],
                'Suspicious TLD': features['has_suspicious_tld']
            },
            'url_structure': {
                'Domain Length': features['domain_length'],
                'URL Length': features['url_length'],
                'Path Length': features['path_length']
            },
            'suspicious_patterns': {
                'At Symbol (@)': features['has_at_symbol'],
                'IP Address': features['has_ip_address'],
                'Misspelled Domain': features['is_misspelled_domain'],
                'Multiple Subdomains': features['has_multiple_subdomains'],
                'Shortened URL': features['is_shortened_url']
            }
        }

        logger.debug(f"Response data: {response_data}")
        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error analyzing URL'}), 500

@app.route('/about')
def about():
    """About page with project information"""
    return render_template('about.html')

@app.route('/statistics')
def statistics():
    """Statistics page showing analysis metrics"""
    return render_template('statistics.html')

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

@app.route('/api/v1/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for URL analysis"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        url = data.get('url')

        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        if not validators.url(url):
            return jsonify({'error': 'Invalid URL format'}), 400

        features = extract_features(url)
        risk_factors = {
            'length': 1 if features['url_length'] > 100 else 0,
            'suspicious_words': 2 if features['has_suspicious_keywords'] else 0,
            'no_https': 0 if features['uses_https'] else 2,
            'suspicious_tld': 2 if features['has_suspicious_tld'] else 0,
            'ip_address': 3 if features['has_ip_address'] else 0,
            'multiple_subdomains': 1 if features['has_multiple_subdomains'] else 0
        }

        max_score = sum(x for x in [1, 2, 2, 2, 3, 1])
        risk_score = sum(risk_factors.values()) / max_score

        response = {
            'url': url,
            'analysis': {
                'is_safe': risk_score < 0.4,
                'risk_score': risk_score,
                'features': features,
                'security_metrics': {
                    'https_enabled': bool(features['uses_https']),
                    'suspicious_patterns_detected': bool(features['has_suspicious_keywords']),
                    'suspicious_tld': bool(features['has_suspicious_tld']),
                    'uses_ip_address': bool(features['has_ip_address'])
                }
            }
        }

        return jsonify(response)

    except Exception as e:
        logger.error(f"API Error: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

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