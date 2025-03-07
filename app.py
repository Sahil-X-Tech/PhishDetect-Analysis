import logging
import os
from flask import Flask, render_template, request, jsonify
import validators
import urllib.parse
import tldextract
import re
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

# Update LEGITIMATE_DOMAINS list
LEGITIMATE_DOMAINS = [
    'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'gmail.com', 'yahoo.com', 'outlook.com', 'github.com', 'paypal.com',
    'openai.com', 'openai.org', 'chatgpt.com', 'anthropic.com', 'claude.ai'
]

# Common legitimate TLDs
LEGITIMATE_TLDS = ['com', 'org', 'net', 'edu', 'gov', 'int', 'mil']

# Government domains are always considered legitimate
GOVERNMENT_TLDS = ['gov', 'gov.in', 'gov.uk', 'gov.au', 'gov.ca', 'gc.ca', 'gov.sg']

# High-risk TLD variations that are commonly used in phishing
HIGH_RISK_TLD_VARIATIONS = {
    'com': ['con', 'cm', 'co', 'kom', 'cpm', 'om', 'corn', 'c0m', 'cam', 'comm'],
    'org': ['ogr', 'ord', 'or', '0rg', 'orq'],
    'net': ['ner', 'met', 'et', 'n3t', 'nat'],
    'edu': ['edw', 'ed', 'edu.co', 'edu.cm']
}

# Common phishing domain suffixes
SUSPICIOUS_DOMAIN_SUFFIXES = ['-free', '-premium', '-login', '-verify', '-secure', '-vip']

def check_domain_mimicry(domain, suffix):
    """Enhanced domain mimicry detection"""
    domain_with_suffix = f"{domain}.{suffix}"

    # Check for exact matches with legitimate domains
    if domain_with_suffix.lower() in LEGITIMATE_DOMAINS:
        return False, []

    # Check if it's a government domain
    if any(suffix.endswith(gov_tld) for gov_tld in GOVERNMENT_TLDS):
        return False, []

    similar_domains = []

    # Check for suspicious suffixes
    if any(suspicious_suffix in domain.lower() for suspicious_suffix in SUSPICIOUS_DOMAIN_SUFFIXES):
        base_domain = domain.lower()
        for suspicious_suffix in SUSPICIOUS_DOMAIN_SUFFIXES:
            if suspicious_suffix in base_domain:
                clean_domain = base_domain.replace(suspicious_suffix, '')
                for legitimate_domain in LEGITIMATE_DOMAINS:
                    if clean_domain in legitimate_domain:
                        similar_domains.append(legitimate_domain)

    for legitimate_domain in LEGITIMATE_DOMAINS:
        legit_domain = legitimate_domain.split('.')[0]
        legit_suffix = legitimate_domain.split('.')[1]

        # Direct domain comparison (case-insensitive)
        if domain.lower() == legit_domain:
            if suffix != legit_suffix:
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
    try:
        parsed_url = urllib.parse.urlparse(url)
        extracted = tldextract.extract(url)
        path_segments = [segment for segment in parsed_url.path.split('/') if segment]

        # Check for domain mimicry
        is_misspelled, similar_domains = check_domain_mimicry(extracted.domain, extracted.suffix)

        # Check for suspicious TLD variations
        has_suspicious_tld_variation = any(
            extracted.suffix in variations
            for legitimate_tld, variations in HIGH_RISK_TLD_VARIATIONS.items()
        )

        # Check for adult content and suspicious patterns
        adult_content_keywords = r'porn|xxx|adult|sex|nude|naked|cam'
        has_adult_content = bool(re.search(adult_content_keywords, extracted.domain.lower()))

        # Check for suspicious domain patterns
        has_suspicious_suffix = any(suffix in extracted.domain.lower() for suffix in SUSPICIOUS_DOMAIN_SUFFIXES)

        # Determine if it's a government domain
        is_gov_domain = any(extracted.suffix.endswith(gov_tld) for gov_tld in GOVERNMENT_TLDS)

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
            'has_suspicious_tld': not (extracted.suffix in LEGITIMATE_TLDS or is_gov_domain),
            'has_suspicious_keywords': bool(re.search(r'login|account|secure|banking|update|verify|signin|security', url.lower())),
            'has_hyphen_in_domain': '-' in extracted.domain,
            'has_adult_content': has_adult_content,
            'has_suspicious_suffix': has_suspicious_suffix,
            'similar_domains': similar_domains,
            'has_suspicious_tld_variation': has_suspicious_tld_variation,
            'is_government_domain': is_gov_domain
        }

        return features
    except Exception as e:
        logger.error(f"Error extracting features: {str(e)}")
        return {}

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
            'suspicious_tld_variation': 4 if features['has_suspicious_tld_variation'] else 0,
            'adult_content': 4 if features['has_adult_content'] else 0,
            'suspicious_suffix': 3 if features['has_suspicious_suffix'] else 0
        }

        max_score = sum(x for x in [1, 2, 2, 2, 3, 2, 1, 2, 5, 2, 3, 4, 4, 3])
        risk_score = sum(risk_factors.values()) / max_score

        # Government domains are considered safe by default
        if features['is_government_domain']:
            is_safe = True
            risk_score = min(risk_score, 0.2)  # Ensure low risk score for government domains
        else:
            is_safe = risk_score < 0.25  # Strict threshold for non-government domains

            # Override safety status for high-risk features
            if (features['is_misspelled_domain'] or 
                features['has_suspicious_tld_variation'] or 
                features['has_suspicious_tld'] or
                features['has_adult_content'] or
                features['has_suspicious_suffix'] or
                (features['has_hyphen_in_domain'] and len(features['similar_domains']) > 0)):
                is_safe = False
                risk_score = max(risk_score, 0.8)  # Ensure high risk score

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
    return render_template('about.html')

@app.route('/statistics')
def statistics():
    return render_template('statistics.html')

@app.route('/security-guide')
def security_guide():
    return render_template('security-guide.html')

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)