from flask import Flask, render_template, request, session, redirect, url_for
import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# MongoDB connection setup
client = MongoClient('mongodb+srv://cguhan03:guhan2003@cluster0.1mgs3.mongodb.net/?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true')
db = client['Data_Security']  # Replace with your database name
users_collection = db['users']  # Collection to store user details

# Directory for storing uploaded files
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# List of allowed and blocked IP addresses for access control
ALLOWED_IPS = ['127.0.0.1', '192.168.1.100', '192.168.1.41']  # Replace with the IPs you want to allow
BLOCKED_IPS = ['103.5.112.80']  # Replace with the IPs you want to block

def get_client_ip():
    # Check for reverse proxies, then use request.remote_addr
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def is_ip_allowed():
    ip = get_client_ip()
    print(f"Client IP: {ip}")  # Log the IP for debugging purposes
    if ip in BLOCKED_IPS:
        return False
    if ALLOWED_IPS and ip not in ALLOWED_IPS:
        return False
    return True

@app.before_request
def check_ip():
    if not is_ip_allowed():
        return "Access Denied: Your IP address is not allowed.", 403

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html')  # Serves the file upload page for logged-in users
    return render_template('index.html', logged_in=False)  # Render the index page for non-logged-in users

@app.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')  # Serve the registration HTML page

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    existing_user = users_collection.find_one({"username": username})
    if existing_user:
        return "Username already exists"
    
    # Hash the password for security
    hashed_password = generate_password_hash(password)
    
    # Insert new user into the database
    users_collection.insert_one({
        "username": username,
        "password": hashed_password
    })
    
    return "Registration successful"

@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')  # Serve the login HTML page

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Find user in the database
    user = users_collection.find_one({"username": username})
    
    # Check if user exists and verify password
    if user and check_password_hash(user['password'], password):
        session['username'] = username
        return redirect(url_for('index'))
    
    return "Invalid username or password"

@app.route('/logout')
def logout():
    session.pop('username', None)
    return "You have been logged out"

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return "You must be logged in to upload files"
    
    if 'file' not in request.files:
        return "No file part"
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        return f"File uploaded successfully: {file.filename}"

if __name__ == '__main__':
    app.run(debug=True)
