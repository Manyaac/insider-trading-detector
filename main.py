import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory,  get_flashed_messages
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import yfinance as yf
import pandas as pd
import numpy as np
import requests
from bs4 import BeautifulSoup
from sec_api import QueryApi
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# App configuration
app = Flask(__name__)
app.secret_key = '2424'  # Your SECRET_KEY

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Manya@localhost:5432/insiderdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'vinishkamanya24@gmail.com'
app.config['MAIL_PASSWORD'] = 'nztjeizglffxepbb'
app.config['MAIL_DEFAULT_SENDER'] = 'vinishkamanya24@gmail.com'

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = None  

# SEC API
query_api = QueryApi(api_key='74fed1ab3959e8feb8ba208d7b315f4e862a5f739e8e2e9c810652db10cedd0a')

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    alerts = db.relationship('Alert', backref='user', lazy=True)
    watchlist = db.relationship('Watchlist', backref='user', lazy=True)

class Watchlist(db.Model):
    __tablename__ = 'watchlist'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ticker = db.Column(db.String(10), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    ticker = db.Column(db.String(10), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reason = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    link = db.Column(db.String(200))
    form_type = db.Column(db.String(10))
    issuer = db.Column(db.String(200))
    insider = db.Column(db.String(200))
    transaction = db.Column(db.String(200))
    impact_score = db.Column(db.Integer, default=5)

# Auth setup
@login_manager.unauthorized_handler
def unauthorized():
    # Only flash once if needed
    if not any(m.startswith('Please log in') for m in get_flashed_messages()):
        flash('Please log in to access this page', 'info')
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Helper functions
def get_insider_trades(ticker):
    try:
        query = {
            "query": f"ticker:{ticker} AND formType:\"4\"",
            "from": "0",
            "size": "5",
            "sort": [{"filedAt": {"order": "desc"}}]
        }
        filings = query_api.get_filings(query)
        
        return [{
            "ticker": filing.get("ticker", ""),
            "filedAt": filing.get("filedAt", "")[:10],
            "formType": filing.get("formType", ""),
            "title": filing.get("title", ""),
            "link": filing.get("linkToFilingDetails", "")
        } for filing in filings.get("filings", [])]
    except Exception as e:
        print(f"SEC API Error: {str(e)}")
        return []

def send_alert_email(user, alert):
    try:
        msg = Message(
            subject=f"🚨 Insider Alert: {alert.ticker}",
            recipients=[user.email],
            html=render_template(
                "email_alert.html",
                alert=alert,
                user=user
            )
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email failed: {str(e)}")
        return False

def extract_filing_details(link):
    try:
        response = requests.get(link, timeout=10)
        text = response.text.replace('\n', ' ')
        
        issuer = text.split('<issuerName>')[1].split('</issuerName>')[0][:100] if '<issuerName>' in text else "N/A"
        insider = text.split('<rptOwnerName>')[1].split('</rptOwnerName>')[0][:100] if '<rptOwnerName>' in text else "N/A"
        
        transaction = "N/A"
        if '<transactionShares>' in text:
            shares = text.split('<transactionShares>')[1].split('</transactionShares>')[0]
            price = text.split('<transactionPricePerShare>')[1].split('</transactionPricePerShare>')[0] if '<transactionPricePerShare>' in text else ""
            transaction = f"{shares} shares @ {price}" if price else f"{shares} shares"
        
        impact_score = 5
        if "sale" in transaction.lower(): impact_score += 3
        if "purchase" in transaction.lower(): impact_score += 1
        impact_score = max(1, min(10, impact_score))

        return {
            "issuer": issuer,
            "insider": insider,
            "transaction": transaction,
            "impact_score": impact_score
        }
    except Exception as e:
        print(f"Failed to parse filing: {e}")
        return {
            "issuer": "N/A",
            "insider": "N/A",
            "transaction": "N/A",
            "impact_score": 5
        }

# Routes
@app.route('/')
@login_required
def index():
    alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.date.desc()).limit(10).all()
    watchlist = Watchlist.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', alerts=alerts, watchlist=watchlist)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
        else:
            user = User(
                username=username,
                email=email,
                password=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/watchlist/add', methods=['POST'])
@login_required
def add_to_watchlist():
    ticker = request.form.get('ticker', '').upper()
    if not ticker:
        flash('Please enter a valid ticker symbol', 'danger')
        return redirect(url_for('index'))

    if not Watchlist.query.filter_by(user_id=current_user.id, ticker=ticker).first():
        item = Watchlist(user_id=current_user.id, ticker=ticker)
        db.session.add(item)
        db.session.commit()
        flash(f'{ticker} added to watchlist!', 'success')
    else:
        flash(f'{ticker} is already in your watchlist', 'info')
    
    return redirect(url_for('index'))

@app.route('/watchlist/remove/<int:id>')
@login_required
def remove_from_watchlist(id):
    item = Watchlist.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Removed from watchlist', 'info')
    return redirect(url_for('index'))

@app.route('/chart/<ticker>')
@login_required
def chart(ticker):
    try:
        stock = yf.Ticker(ticker)
        hist = stock.history(period='1mo', interval='1d')
        
        if hist.empty:
            hist = stock.history(period='6mo', interval='1d')
            
        if hist.empty:
            flash(f"No price data available for {ticker}", "warning")
            return redirect(url_for('index'))
        
        prices = hist['Close'].fillna(method='ffill').tolist()
        dates = hist.index.strftime('%Y-%m-%d').tolist()
        
        return render_template('chart.html',
            ticker=ticker,
            dates=dates,
            prices=prices,
            info=stock.info,
            insider_dates=[alert.date.strftime('%Y-%m-%d') for alert in current_user.alerts if alert.ticker == ticker]
        )
        
    except Exception as e:
        flash(f"Chart error: {str(e)}", "danger")
        return redirect(url_for('index'))

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    ticker = request.form.get('ticker', '').upper()
    if not ticker:
        flash('Please enter a valid ticker symbol', 'danger')
        return redirect(url_for('index'))

    alerts_created = 0
    
    try:
        stock = yf.Ticker(ticker)
        data = stock.history(period="1mo", auto_adjust=True, timeout=10)
        if data.empty:
            data = stock.history(period='1mo', interval='1d')
        
        if data.empty:
            flash(f"No data found for {ticker}", 'warning')
            return redirect(url_for('index'))

        # Volume anomalies
        data['Z-Score'] = (data['Volume'] - data['Volume'].mean()) / data['Volume'].std()
        anomalies = data[data['Z-Score'] > 2]
        
        # Insider trades
        insider_trades = get_insider_trades(ticker)
        
        # Create alerts
        for date, row in anomalies.iterrows():
            try:
                alert = Alert(
                    ticker=ticker,
                    date=date.to_pydatetime(),
                    reason=f"Abnormal volume spike (Z-Score: {float(row['Z-Score']):.2f})",
                    severity="HIGH",
                    user_id=current_user.id
                )
                db.session.add(alert)
                alerts_created += 1
                if current_user.email:
                    send_alert_email(current_user, alert)
            except Exception as e:
                print(f"Error creating volume alert: {e}")
                continue

        for trade in insider_trades:
            try:
                filing_details = extract_filing_details(trade["link"])
                
                alert = Alert(
                    ticker=trade["ticker"],
                    date=datetime.strptime(trade["filedAt"], '%Y-%m-%d'),
                    reason=f"SEC {trade['formType']}: {filing_details['transaction'] or 'No details'}",
                    severity="HIGH" if "sale" in filing_details['transaction'].lower() else "MEDIUM",
                    user_id=current_user.id,
                    link=trade["link"],
                    form_type=trade["formType"],
                    issuer=filing_details['issuer'],
                    insider=filing_details['insider'],
                    transaction=filing_details['transaction'],
                    impact_score=filing_details['impact_score']
                )
                db.session.add(alert)
                alerts_created += 1
                if current_user.email:
                    send_alert_email(current_user, alert)
                    
            except Exception as e:
                print(f"Failed to process filing: {e}")
                continue

            if success:
                return redirect(url_for('index', scan=1))
            else:
                return redirect(url_for('index'))


        db.session.commit()
        flash(f"Scan complete. Found {alerts_created} alerts for {ticker}", 'success')
        return redirect(url_for('index', scan=1))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error scanning {ticker}: {str(e)}", 'danger')
        return redirect(url_for('index'))


@app.route('/get-price-data/<ticker>')
@login_required
def get_price_data(ticker):
    try:
        stock = yf.Ticker(ticker)
        hist = stock.history(period='1mo', interval='1d')
        return jsonify({
            'dates': hist.index.strftime('%Y-%m-%d').tolist(),
            'prices': hist['Close'].fillna(method='ffill').tolist()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                           'favicon.ico', mimetype='image/vnd.microsoft.icon')

def create_tables():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin')
            )
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)