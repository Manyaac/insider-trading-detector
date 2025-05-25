from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
import yfinance as yf
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sec_api import QueryApi
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
import requests
from bs4 import BeautifulSoup
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)
mail = Mail(app)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-123')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://postgres:Manya@localhost:5432/insiderdb'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,  # Changed from 587 to 465
    MAIL_USE_SSL=True,  # Changed from TLS
    MAIL_USERNAME='vinishkamanya24@gmail.com',
    MAIL_PASSWORD='nztjeizglffxepbb', 
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USERNAME')
)

# Test email sending first:
with app.app_context():
    try:
        msg = Message("Test Email",
                     recipients=["your@test.email"])
        mail.send(msg)
        print("✓ Email test successful")
    except Exception as e:
        print(f"Email test failed: {e}")

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    alerts = db.relationship('Alert', backref='user', lazy=True)
    watchlist = db.relationship('Watchlist', backref='user', lazy=True)

class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticker = db.Column(db.String(10), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticker = db.Column(db.String(10), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    link = db.Column(db.String(200))
    formType = db.Column(db.String(10))  # SEC form type (4, 3, etc.)
    issuer = db.Column(db.String(200))  # Company name
    insider = db.Column(db.String(200))  # Insider name
    transaction = db.Column(db.String(200))  # Transaction type
    impact_score = db.Column(db.Integer,  default=5) 

# Auth Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Helper Functions
def get_insider_trades(ticker):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) MyCompany/1.0 (Contact: your@email.com)',
            'Accept-Encoding': 'gzip, deflate',
            'Host': 'api.sec-api.io'
        }

        query_api = QueryApi(api_key=os.getenv("SEC_API_KEY"), headers=headers)
        query = {
            "query": f"ticker:{ticker} AND formType:\"4\"",
            "from": "0",
            "size": "3",  # Reduced from 5 to 3
            "sort": [{"filedAt": {"order": "desc"}}]
        }
        filings = query_api.get_filings(query)
        
        # Add delay between requests
        time.sleep(2)   
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
            recipients=[user.email]
        )
        msg.html = render_template("email_alert.html", alert=alert)
        mail.send(msg)
        print(f"Email sent to {user.email}")
        return True
    except Exception as e:
        print(f"Email failed: {str(e)}")
        return False

def scan_filing_for_redflags(link):
    try:
        response = requests.get(link, timeout=15)
        text = response.text.lower()

        redflags = {
            "CRITICAL": ["sale", "dispose", "sell", "transfer", "sold", "divest"],
            "HIGH": ["purchase", "acquire", "buy", "added", "accumulate"],
            "MEDIUM": ["option", "exercise", "derivative", "swap", "pledge", "10b5"]
        }
        
        for severity, keywords in redflags.items():
            if any(keyword in text for keyword in keywords):
                return {'severity': severity, 'keywords': keywords}
        
        return {'severity': 'LOW', 'keywords': []}
        
    except Exception as e:
        print(f"Error scanning filing: {e}")
        return {'severity': 'UNKNOWN', 'keywords': []}
    
def extract_filing_details(link):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) YourCompany/1.0',
            'Accept': 'application/xml'
        }
        response = requests.get(link, headers=headers, timeout=20)
        
        if "SEC.gov | Request Rate Threshold" in response.text:
            raise Exception("SEC rate limit exceeded")
            
        soup = BeautifulSoup(response.text, 'lxml-xml')
        
        # Debug raw XML if needed
        with open("last_filing.xml", "w") as f:
            f.write(response.text)

        # Extract with multiple fallbacks
        issuer = (
            soup.find('issuerName') or 
            soup.find('issuer').find('issuerName') if soup.find('issuer') else
            soup.find(lambda t: 'issuer' in t.name.lower())
        )
        
        insider = (
            soup.find('rptOwnerName') or
            soup.find('reportingOwner').find('rptOwnerName') if soup.find('reportingOwner') else
            soup.find('filerName')
        )
        
        # Transaction parsing
        trans = soup.find('nonDerivativeTransaction') or soup.find('transaction')
        shares = price = code = None
        if trans:
            shares = trans.find('transactionShares') or trans.find('shares')
            price = trans.find('transactionPricePerShare') or trans.find('pricePerShare')
            code = trans.find('transactionCode') or trans.find('transactionCd')
        
        return {
            "issuer": issuer.text.strip() if issuer else "Unknown Company",
            "insider": insider.text.strip() if insider else "Unknown Insider",
            "transaction": f"{shares.text.strip()} @ ${price.text.strip()}" 
                          if shares and price else "Shares traded",
            "transaction_type": "Sale" if code and code.text.strip() == 'S' else 
                              "Purchase" if code and code.text.strip() == 'P' else "Trade",
            "reason": "SEC Filing",
            "impact_score": 8 if code and code.text.strip() == 'S' else 5
        }
        
    except Exception as e:
        print(f"⚠️ Failed to parse filing: {str(e)}")
        return {
            "issuer": "Company (Error)",
            "insider": "Insider (Error)",
            "transaction": "Details unavailable",
            "transaction_type": "N/A",
            "reason": str(e),
            "impact_score": 5
        }
    
# Routes
@app.route('/')
@login_required
def index():
    alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.date.desc()).all()
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
            flash('Username exists', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email exists', 'danger')
        else:
            user = User(
                username=username,
                email=email,
                password=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful!', 'success')
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
        hist = stock.history(period='1mo')
        
        if hist.empty or hist['Close'].isnull().all():
            flash(f"No valid price data found for {ticker}", "danger")
            return redirect(url_for('index'))

        # Convert prices to floats and handle NaN values
        prices = []
        valid_dates = []
        for date, price in zip(hist.index.strftime('%Y-%m-%d'), hist['Close']):
            if not pd.isna(price):
                prices.append(float(price))
                valid_dates.append(date)

        if not prices:
            flash(f"No valid price points for {ticker}", "danger")
            return redirect(url_for('index'))

        # Get insider trading dates
        alerts = Alert.query.filter_by(
            user_id=current_user.id, 
            ticker=ticker
        ).all()
        insider_dates = [alert.date for alert in alerts] if alerts else []

        # Safely handle stock info with fallbacks
        stock_info = {
            'shortName': stock.info.get('shortName', ticker),
            'sector': stock.info.get('sector', 'N/A'),
            'industry': stock.info.get('industry', 'N/A'),
            'currentPrice': float(stock.info.get('currentPrice', 0)),
            'regularMarketChangePercent': float(stock.info.get('regularMarketChangePercent', 0)),
            'fiftyTwoWeekLow': float(stock.info.get('fiftyTwoWeekLow', 0)),
            'fiftyTwoWeekHigh': float(stock.info.get('fiftyTwoWeekHigh', 0))
        }

        return render_template('chart.html',
            ticker=ticker,
            dates=valid_dates,  # Only dates with valid prices
            prices=prices,      # Guaranteed to be float values
            info=stock_info,
            insider_dates=insider_dates
        )
        
    except Exception as e:
        flash(f"Chart error for {ticker}: {str(e)}", "danger")
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
        # Get stock data
        stock = yf.Ticker(ticker)
        data = stock.history(period="1mo", auto_adjust=True)
        
        if data.empty:
            flash(f"No data found for {ticker}", 'warning')
            return redirect(url_for('index'))

        # Process volume anomalies
        data['Z-Score'] = (data['Volume'] - data['Volume'].mean()) / data['Volume'].std()
        anomalies = data[data['Z-Score'] > 2]
        
        # Process insider trades
        insider_trades = get_insider_trades(ticker)
        
        # Create volume alerts
        for date, row in anomalies.iterrows():
            try:
                alert = Alert(
                    ticker=ticker,
                    date=date.strftime("%Y-%m-%d"),
                    reason=f"Abnormal volume spike (Z-Score: {float(row['Z-Score']):.2f})",
                    severity="HIGH",
                    user_id=current_user.id
                )
                db.session.add(alert)
                alerts_created += 1
                
                if current_user.email:
                    try:
                        send_alert_email(current_user, alert)
                    except Exception as email_error:
                        print(f"Email failed for {ticker}: {email_error}")
            except Exception as alert_error:
                print(f"Error creating volume alert: {alert_error}")
                continue

        # Process insider trades
        for trade in insider_trades:
            try:
                # Parse filing date
                try:
                    alert_date = datetime.strptime(trade["filedAt"], '%Y-%m-%d').strftime('%Y-%m-%d')
                except (ValueError, KeyError):
                    alert_date = datetime.utcnow().strftime('%Y-%m-%d')

                try:
                    # First make the request to get the SEC filing
                    response = requests.get(
                        trade["link"],
                        headers={'User-Agent': 'YourApp'},
                        timeout=20
                    )
                    
                    # Now that we have the response, we can print it
                    print(f"Raw SEC Data:\n{response.text[:2000]}")  # First 2000 chars
                    
                    # Process the filing
                    scan_result = scan_filing_for_redflags(trade["link"])
                    filing_details = extract_filing_details(trade["link"])
                    print(f"Parsed Data: {filing_details}")

                    # Create insider alert
                    alert = Alert(
                        ticker=trade["ticker"],
                        date=alert_date,
                        reason=f"SEC {trade['formType']}: {', '.join(scan_result['keywords'])}",
                        severity=scan_result['severity'],
                        user_id=current_user.id,
                        link=trade["link"],
                        formType=trade["formType"],
                        issuer=filing_details.get("issuer", "N/A"),
                        insider=filing_details.get("insider", "N/A"),
                        transaction=filing_details.get("transaction", "N/A"),
                        impact_score=filing_details.get("impact_score", 5)
                    )
                    
                    db.session.add(alert)
                    alerts_created += 1
                    
                    if current_user.email:
                        try:
                            send_alert_email(current_user, alert)
                        except Exception as email_error:
                            print(f"Email failed for {trade['ticker']}: {email_error}")
                            
                except requests.exceptions.RequestException as req_error:
                    print(f"Network error for {trade.get('ticker', 'unknown')}: {req_error}")
                    continue
                except Exception as processing_error:
                    print(f"Error processing {trade.get('ticker', 'unknown')}: {processing_error}")
                    continue
                    
            except Exception as outer_error:
                print(f"Critical error processing trade: {outer_error}")
                continue

        # Final commit
        try:
            db.session.commit()
            flash(f"Scan complete. Found {alerts_created} alerts for {ticker}", 'success')
        except Exception as commit_error:
            db.session.rollback()
            flash(f"Database error: {commit_error}", 'danger')
            
        return redirect(url_for('index'))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error scanning {ticker}: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                           'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"Database error: {e}")
            # Reset if needed
            db.drop_all()
            db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin')
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
