import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from phishing_detector import PhishingURLDetector
import validators
from datetime import datetime
from database import db, app as db_app
from models import Report, User
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Use the app instance from database.py
app = db_app

# Configure secret key
app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    raise RuntimeError(
        "SESSION_SECRET is not set. Please provide a secure session secret key."
    )

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


# Update the model loading section
try:
    detector = PhishingURLDetector()
    detector.load_models(
        'phishing_detector.joblib'
    )  # Changed from 'attached_assets/phishing_detector.joblib'
    logger.info("Model loaded successfully")
except Exception as e:
    logger.error(f"Error loading model: {str(e)}")
    detector = None


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=request.form.get('remember', False))
            return redirect(url_for('index'))

        flash('Invalid email or password')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('register.html')

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


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


@app.route('/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing detection"""
    try:
        if detector is None:
            return jsonify(
                {'error':
                 'Model not initialized. Please try again later.'}), 500

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
            report = Report(url=url,
                            is_phishing=result['prediction'] == 'phishing',
                            confidence_score=result['confidence'],
                            reporter_email="anonymous@user.com",
                            report_type='automatic',
                            actual_result=result['prediction'])
            db.session.add(report)
            db.session.commit()
        except Exception as db_error:
            logger.error(f"Error saving report to database: {str(db_error)}")
            # Continue with the analysis even if saving to DB fails

        response = {
            'prediction': result['prediction'],
            'confidence': round(result['confidence'] * 100, 2),
            'probability_phishing': round(result['probability_phishing'] * 100,
                                          2),
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
        return jsonify({'error':
                        'Error analyzing URL. Please try again.'}), 500


@app.route('/submit_report', methods=['POST'])
def submit_report():
    """Submit a new report"""
    try:
        data = request.form
        url = data.get('url')
        actual_result = data.get('actualResult')
        report_type = data.get('reportType')

        # Validate required fields
        if not url or not actual_result or not report_type:
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400

        report = Report(
            url=url,
            is_phishing=actual_result == 'phishing',
            confidence_score=1.0,  # Default confidence for manual reports
            reporter_email="anonymous@user.com",
            report_type=report_type,
            description=data.get('description', ''),
            expected_result=data.get('expectedResult', ''),
            actual_result=actual_result)
        db.session.add(report)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Report submitted successfully'
        })
    except Exception as e:
        logger.error(f"Error submitting report: {str(e)}")
        db.session.rollback()  # Rollback transaction on error
        return jsonify({'success': False, 'error': str(e)}), 400


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


def create_admin_user():
    """Create admin user if it doesn't exist"""
    admin = User.query.filter_by(email='admin@phishingdetector.com').first()
    if not admin:
        admin = User(username='admin',
                     email='admin@phishingdetector.com',
                     is_admin=True)
        admin.set_password('Sahilkhan123')
        db.session.add(admin)
        db.session.commit()
        logger.info("Admin user created successfully")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(host='0.0.0.0', port=8080, debug=True)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()


# Make sure this is correctly set with your Render PostgreSQL URL
app.config[
    'SQLALCHEMY_DATABASE_URI'] = "postgresql://phishing_db_user:ffBzIYjtFjLrRbdfjlXzYSRKX9xIzzCX@dpg-cv3126bqf0us7382uu5g-a.oregon-postgres.render.com/phishing_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
