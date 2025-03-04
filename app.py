import logging
import os
from flask import Flask, render_template, request, jsonify
import validators
import urllib.parse
import tldextract
import re

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

        # Extract URL components
        parsed_url = urllib.parse.urlparse(url)
        extracted = tldextract.extract(url)

        # Simple analysis based on common phishing indicators
        analysis = {
            'length': len(url),
            'has_suspicious_words': bool(re.search(r'login|account|secure|banking', url.lower())),
            'uses_https': parsed_url.scheme == 'https',
            'has_suspicious_tld': extracted.suffix in ['xyz', 'top', 'fit', 'tk', 'ml'],
            'has_ip_address': bool(re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain)),
            'has_multiple_subdomains': len(extracted.subdomain.split('.')) > 2 if extracted.subdomain else False,
        }

        # Calculate risk score (simple weighted average)
        risk_factors = {
            'length': 1 if analysis['length'] > 100 else 0,
            'suspicious_words': 2 if analysis['has_suspicious_words'] else 0,
            'no_https': 0 if analysis['uses_https'] else 2,
            'suspicious_tld': 2 if analysis['has_suspicious_tld'] else 0,
            'ip_address': 3 if analysis['has_ip_address'] else 0,
            'multiple_subdomains': 1 if analysis['has_multiple_subdomains'] else 0
        }

        max_score = sum(x for x in [1, 2, 2, 2, 3, 1])
        risk_score = sum(risk_factors.values()) / max_score

        is_safe = risk_score < 0.4

        return jsonify({
            'safe': is_safe,
            'probability_safe': 1 - risk_score,
            'probability_phishing': risk_score,
            'security_metrics': {
                'HTTPS': analysis['uses_https'],
                'Domain Age': 'Unknown',  # Would require external API
                'SSL Certificate': analysis['uses_https']
            },
            'url_structure': {
                'URL Length': analysis['length'],
                'Multiple Subdomains': analysis['has_multiple_subdomains'],
                'IP Address Used': analysis['has_ip_address']
            },
            'suspicious_patterns': {
                'Suspicious Keywords': analysis['has_suspicious_words'],
                'Suspicious TLD': analysis['has_suspicious_tld']
            }
        })

    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
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