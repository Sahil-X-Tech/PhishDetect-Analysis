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
    'apple.com', 'netflix.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'gmail.com', 'yahoo.com', 'outlook.com', 'github.com', 'paypal.com',
    'openai.com', 'openai.org', 'chatgpt.com', 'anthropic.com', 'claude.ai'
]

# Common legitimate TLDs
LEGITIMATE_TLDS = ['com', 'org', 'net', 'edu', 'gov', 'int', 'mil']

# High-risk TLD variations that are commonly used in phishing
HIGH_RISK_TLD_VARIATIONS = {
    'com': ['con', 'cm', 'co', 'kom', 'cpm'],
    'org': ['ogr', 'ord', 'or'],
    'net': ['ner', 'met', 'et'],
    'edu': ['edw', 'ed'],
}

def check_domain_mimicry(domain, suffix):
    """Enhanced domain mimicry detection"""
    domain_with_suffix = f"{domain}.{suffix}"

    # Check for exact matches with legitimate domains
    if domain_with_suffix.lower() in LEGITIMATE_DOMAINS:
        return False, []

    similar_domains = []
    for legitimate_domain in LEGITIMATE_DOMAINS:
        legit_domain = legitimate_domain.split('.')[0]
        legit_suffix = legitimate_domain.split('.')[1]

        # Direct domain comparison (case-insensitive)
        if domain.lower() == legit_domain:
            # Check if TLD is suspicious
            if suffix != legit_suffix:
                # Check for common TLD typos
                if legit_suffix in HIGH_RISK_TLD_VARIATIONS and suffix in HIGH_RISK_TLD_VARIATIONS[legit_suffix]:
                    similar_domains.append(legitimate_domain)
                    continue
                # Check for similarity with legitimate TLD
                if difflib.SequenceMatcher(None, suffix, legit_suffix).ratio() > 0.6:
                    similar_domains.append(legitimate_domain)
                    continue

        # Direct hyphen check
        if domain.replace('-', '') == legit_domain:
            similar_domains.append(legitimate_domain)
            continue

        # Check for hyphen substitution
        if domain.replace('-', '.') == legitimate_domain:
            similar_domains.append(legitimate_domain)
            continue

        # Check for close misspellings
        similarity = difflib.SequenceMatcher(None, domain.lower(), legit_domain).ratio()
        if similarity > 0.75:
            similar_domains.append(legitimate_domain)

        # Check for character substitution (like 0 for o, 1 for l)
        normalized_domain = domain.lower().replace('0', 'o').replace('1', 'l')
        normalized_legit = legit_domain.lower()
        if normalized_domain == normalized_legit:
            similar_domains.append(legitimate_domain)

    return len(similar_domains) > 0, similar_domains

def extract_features(url):
    """Extract features from URL for model prediction"""
    parsed_url = urllib.parse.urlparse(url)
    extracted = tldextract.extract(url)
    path_segments = [segment for segment in parsed_url.path.split('/') if segment]

    # Check for domain mimicry
    is_misspelled, similar_domains = check_domain_mimicry(extracted.domain, extracted.suffix)

    # Extract features
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
        'is_misspelled_domain': is_misspelled,
        'has_multiple_subdomains': len(extracted.subdomain.split('.')) > 2 if extracted.subdomain else False,
        'is_shortened_url': len(extracted.domain) <= 4 or any(short in extracted.domain for short in ['bit.ly', 'goo.gl', 't.co', 'tiny']),
        'has_suspicious_tld': extracted.suffix not in LEGITIMATE_TLDS,
        'has_suspicious_keywords': bool(re.search(r'login|account|secure|banking|update|verify|signin|security', url.lower())),
        'has_hyphen_in_domain': '-' in extracted.domain,
        'similar_domains': similar_domains,
        'has_suspicious_tld_variation': any(
            extracted.suffix in HIGH_RISK_TLD_VARIATIONS.get(tld, [])
            for tld in HIGH_RISK_TLD_VARIATIONS.keys()
        )
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
            'has_suspicious_keywords': 2 if features['has_suspicious_keywords'] else 0,
            'no_https': 0 if features['uses_https'] else 2,
            'suspicious_tld': 2 if features['has_suspicious_tld'] else 0,
            'ip_address': 3 if features['has_ip_address'] else 0,
            'multiple_subdomains': 2 if features['has_multiple_subdomains'] else 0,
            'special_chars': 1 if features['has_special_chars'] else 0,
            'at_symbol': 2 if features['has_at_symbol'] else 0,
            'misspelled_domain': 5 if features['is_misspelled_domain'] else 0,
            'shortened_url': 2 if features['is_shortened_url'] else 0,
            'hyphen_in_domain': 3 if features['has_hyphen_in_domain'] else 0,
            'suspicious_tld_variation': 4 if features['has_suspicious_tld_variation'] else 0
        }

        max_score = sum(x for x in [1, 2, 2, 2, 3, 2, 1, 2, 5, 2, 3, 4])
        risk_score = sum(risk_factors.values()) / max_score

        # Even stricter thresholds
        is_safe = risk_score < 0.25

        # Automatic flagging for certain high-risk features
        if (features['is_misspelled_domain'] or 
            features['has_suspicious_tld_variation'] or 
            (features['has_hyphen_in_domain'] and len(features['similar_domains']) > 0)):
            is_safe = False
            risk_score = max(risk_score, 0.8)

        response_data = {
            'safe': is_safe,
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

        # Add similar domain information if available
        if features['similar_domains']:
            response_data['similar_to'] = features['similar_domains']

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)