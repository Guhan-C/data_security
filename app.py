from flask import Flask, render_template, request, session, redirect, url_for
import os
from pymongo import MongoClient
import gridfs
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# MongoDB connection setup
client = MongoClient('mongodb+srv://cguhan03:guhan2003@cluster0.1mgs3.mongodb.net/?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true')
db = client['Data_Security']  # Replace with your database name
users_collection = db['users']  # Collection to store user details
fs = gridfs.GridFS(db)  # GridFS instance for file storage
FT=db["FileTranfer"]
# Encryption key (you should securely store and retrieve this key)
encryption_key = Fernet.generate_key()  # You can store this securely
cipher = Fernet(encryption_key)

# Directory for storing uploaded files
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# List of allowed and blocked IP addresses for access control
BLOCKED_IPS = ['103.5.112.80']  # Replace with the IPs you want to block

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip_list = request.headers.getlist("X-Forwarded-For")[0].split(',')
        return ip_list[-1].strip()
    return request.remote_addr

def is_ip_allowed():
    ip = get_client_ip()
    if ip in BLOCKED_IPS:
        return False
    return True

@app.before_request
def check_ip():
    if not is_ip_allowed():
        return "Access Denied: Your IP address is not allowed.", 403

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html')
    return render_template('index.html', logged_in=False)

@app.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@app.route('/Transfer')
def Transfer():
    return render_template('Transfer.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    existing_user = users_collection.find_one({"username": username})
    if existing_user:
        return "Username already exists"
    
    hashed_password = generate_password_hash(password)
    users_collection.insert_one({
        "username": username,
        "password": hashed_password
    })
    
    return "Registration successful"

@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = users_collection.find_one({"username": username})
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
    username_receiver = request.form['Username']
    user = users_collection.find_one({"username": username_receiver})
    if not user:
        return "User not found"
    if 'username' not in session:
        return "You must be logged in to upload files"
    
    if 'file' not in request.files:
        return "No file part"
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    
    if file:
        # Read file data and encrypt it
        
        username_sender=session["username"]
        key=encryption_key
        file_data = file.read()
        encrypted_data = cipher.encrypt(file_data)  # Encrypt the file
        FT.insert_one({
        "username_sender": username_sender,
        "username_receiver": username_receiver,
        "key":key,
        "file_name":file.filename
    })
        # Store encrypted file in MongoDB GridFS
        file_id = fs.put(encrypted_data, filename=file.filename)

        return f"File uploaded and encrypted successfully with ID: {file.filename}"

if __name__ == '__main__':
    app.run(debug=True)