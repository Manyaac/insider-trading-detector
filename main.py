import os
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
import psycopg2

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', 'dev-fallback-key')

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:Manya@localhost/insidertracker"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


try:
    conn = psycopg2.connect(os.getenv('DATABASE_URL'))
    print("✅ Connection successful!")
    conn.close()
except Exception as e:
    print(f"❌ Connection failed: {e}")

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class InsiderTrade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), nullable=False)
    issuer = db.Column(db.String(100), nullable=False)
    insider = db.Column(db.String(100), nullable=False)
    transaction = db.Column(db.String(50), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    value = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    impact = db.Column(db.String(20), nullable=False)
    filing_url = db.Column(db.String(200))

# SEC API Helper
def fetch_insider_trades(symbol):
    headers = {
        "User-Agent": "InsiderTracker/1.0 (vinishkamanya24@gmail.com)",
        "Authorization": f"Bearer {os.getenv('SEC_API_KEY')}"
    }
    try:
        url = f"https://api.sec.gov/files/edgar/data/{symbol}/index.json"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return parse_sec_data(response.json(), symbol)
    except Exception as e:
        print(f"SEC API Error: {e}")
        return []

def parse_sec_data(data, symbol):
    trades = []
    for filing in data.get('directory', {}).get('item', [])[:10]:  # Limit to 10 filings
        if filing.get('name', '').endswith('.xml'):
            trades.append({
                'symbol': symbol,
                'issuer': filing.get('companyName', symbol),
                'insider': filing.get('reportingOwner', 'Unknown'),
                'transaction': filing.get('transactionType', 'Unknown'),
                'shares': abs(int(filing.get('shares', 0))),
                'value': abs(float(filing.get('value', 0))),
                'date': filing.get('filingDate', datetime.utcnow().strftime('%Y-%m-%d')),
                'impact': calculate_impact(filing),
                'filing_url': f"https://www.sec.gov/Archives/{filing.get('url')}"
            })
    return trades

def calculate_impact(filing):
    value = float(filing.get('value', 0))
    if value > 1000000:
        return '🔴 HIGH'
    elif value > 100000:
        return '🟠 MEDIUM'
    return '🟢 LOW'

# Flask-Login Setup
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    symbols = ['AAPL', 'TSLA', 'GOOG', 'MSFT']
    all_trades = []
    for symbol in symbols:
        all_trades.extend(fetch_insider_trades(symbol))
    return render_template('dashboard.html', trades=all_trades)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists', 'danger')
        else:
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# API Endpoint
@app.route('/api/trades')
@login_required
def api_trades():
    try:
        symbols = ['AAPL', 'TSLA', 'GOOG', 'MSFT']
        all_trades = []
        
        for symbol in symbols:
            trades = fetch_insider_trades(symbol)
            if trades:
                all_trades.extend(trades)
        
        return jsonify({
            "data": sorted(all_trades, key=lambda x: x['date'], reverse=True),
            "status": "success"
        })
    
    except Exception as e:
        return jsonify({
            "data": [],
            "error": str(e),
            "status": "error"
        }), 500
    
# Initialize Database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)