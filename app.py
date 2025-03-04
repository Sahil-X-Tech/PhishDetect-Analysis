import logging
import os
from flask import Flask, render_template, request, jsonify

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