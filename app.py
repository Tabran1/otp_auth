from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymysql
import random
import string
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
# Use an environment variable for secret key in production, with a fallback for local testing
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')  

# Configure MySQL Database Connection (Reads from environment variables if available)
db_config = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', 'Tabran@007'), 
    'database': os.environ.get('DB_NAME', 'auth_demo'),
    'cursorclass': pymysql.cursors.DictCursor
}

# Email Configuration (Reads from environment variables if available)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'mohamedtabran123@gmail.com')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', 'absy vaoz lecf hbji')

def get_db_connection():
    return pymysql.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['database'],
        cursorclass=db_config['cursorclass']
    )

def send_otp_email(recipient_email, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = 'Your OTP Verification Code'

        body = f'Your verification code is: {otp}. It expires in 5 minutes.'
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/')
def home():
    return "<h1>Welcome! Database and Flask are connected.</h1> <p><a href='/register'>Register</a> | <a href='/login'>Login</a></p>"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            cursor.close()
            conn.close()
            flash('Email already registered. Please log in.')
            return redirect(url_for('login'))
        
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (email, password, is_verified) VALUES (%s, %s, FALSE)", (email, hashed_password))
        conn.commit()
        
        otp = ''.join(random.choices(string.digits, k=6))
        expires_at = datetime.now() + timedelta(minutes=5)
        
        cursor.execute("INSERT INTO otps (email, otp_code, expires_at) VALUES (%s, %s, %s)", (email, otp, expires_at))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        if send_otp_email(email, otp):
            session['email'] = email
            return redirect(url_for('verify'))
        else:
            flash('Failed to send OTP email. Please check your email configuration.')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'email' not in session:
        return redirect(url_for('register'))
        
    if request.method == 'POST':
        entered_otp = request.form['otp']
        email = session['email']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM otps WHERE email = %s ORDER BY created_at DESC LIMIT 1", (email,))
        record = cursor.fetchone()
        
        if not record or datetime.now() > record['expires_at']:
            cursor.close()
            conn.close()
            flash('OTP has expired or is invalid. Please register again.')
            return redirect(url_for('register'))
            
        if record['otp_code'] != entered_otp:
            cursor.close()
            conn.close()
            flash('Invalid OTP code. Try again.')
            return redirect(url_for('verify'))
            
        cursor.execute("UPDATE users SET is_verified = TRUE WHERE email = %s", (email,))
        conn.commit()
        
        cursor.execute("DELETE FROM otps WHERE email = %s", (email,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        session['logged_in'] = True
        return redirect(url_for('dashboard'))

    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            if not user['is_verified']:
                session['email'] = email
                flash('Please verify your email first.')
                return redirect(url_for('verify'))
                
            session['logged_in'] = True
            session['email'] = email
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return f"<h1>Welcome to your Dashboard, {session.get('email')}!</h1><br><a href='/logout'>Logout</a>"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)