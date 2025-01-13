from flask import Flask, request, jsonify, g, render_template  
from flask_sqlalchemy import SQLAlchemy                        
from flask_bcrypt import Bcrypt                                
from flask_cors import CORS                                    
from datetime import datetime, timedelta
import secrets
import os
import base64
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# In-memory session key store
session_keys = {}

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_encrypted = db.Column(db.Text, nullable=False)

    @property
    def note(self):
        return decrypt_data(self.note_encrypted)

    @note.setter
    def note(self, value):
        self.note_encrypted = encrypt_data(value)


class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)

# Helper function to generate and manage session keys
def generate_session_key(user_id):
    key = secrets.token_hex(32)
    session_keys[key] = {
        "user_id": user_id,
        "expires_at": datetime.now() + timedelta(minutes=30),
        "last_active": datetime.now()
    }
    return key

def validate_session_key():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return False, "Invalid or missing session API key"

    key = auth_header.split("Bearer ")[1]
    print(key)  # Debug print
    if key not in session_keys:
        return False, "Invalid or missing session API key"

    session = session_keys[key]
    now = datetime.now()

    # Check if key is expired
    if session["expires_at"] < now:
        del session_keys[key]
        return False, "Session expired. Please log in again."

    # Update last active time
    session["last_active"] = now
    return True, session

def get_encryption_key():
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise ValueError("Encryption key not found in environment variables")
    return base64.urlsafe_b64decode(key)

def encrypt_data(data: str) -> str:
    fernet = Fernet(get_encryption_key())
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data: str) -> str:
    fernet = Fernet(get_encryption_key())
    return fernet.decrypt(data.encode()).decode()

# Decorator for protected routes
def require_session_key(func):
    def wrapper(*args, **kwargs):
        valid, response = validate_session_key()
        if not valid:
            return jsonify({"error": response}), 401
        g.user_id = response["user_id"]  # Store user ID for the route
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/login_page')
def login_page():
    return render_template('login.html')

@app.route('/signup_page')
def signup_page():
    return render_template('signup.html')

@app.route('/account_page')
def account_page():
    return render_template('account.html')

@app.route('/contact', methods=['POST'])
def contact():
    data = request.json
    email = data['email']
    message = data['message']
    try:
        message = Messages(email=email, message=message)
        db.session.add(message)
        db.session.commit()
        return jsonify({"succes": "Message received successfully!"}), 201
    except Exception as e:
        return jsonify({"error": f"Message not received {e}"}), 400

# Routes
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    try:
        user = User(username=data['username'], password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User created successfully!"}), 201
    except:
        return jsonify({"error": "Username already exists"}), 400

# Routes
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        key = generate_session_key(user.id)
        return jsonify({"message": "Login successful!", "session_key": key, "user_id": user.id}), 200
    return jsonify({"error": "Invalid credentials"}), 400

@app.route('/logout', methods=['POST'])
@require_session_key
def logout():
    auth_header = request.headers.get("Authorization")
    key = auth_header.split("Bearer ")[1]
    del session_keys[key]
    return jsonify({"message": "Logged out successfully!"}), 200

@app.route('/notes', methods=['GET', 'POST'])
@require_session_key
def manage_notes():
    if request.method == 'POST':
        data = request.json
        # Replace newlines with a space before saving to the database
        sanitized_note = data['note'].replace('\n', ' ')
        note = Note(user_id=g.user_id, note=sanitized_note)  # Automatically encrypts
        db.session.add(note)
        db.session.commit()
        return jsonify({"message": "Note added successfully!"}), 201
    else:
        notes = Note.query.filter_by(user_id=g.user_id).all()
        # Decrypt notes and replace newlines with a space before sending the response
        sanitized_notes = [{"id": note.id, "note": note.note.replace('\n', ' ')} for note in notes]  # Automatically decrypts
        return jsonify(sanitized_notes)


@app.route('/notes/<int:note_id>', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_note(note_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != g.user_id:
        return jsonify({"error": "Note not found"}), 404

    if request.method == 'PUT':
        data = request.json
        note.note = data['note']  # Automatically encrypts
        db.session.commit()
        return jsonify({"message": "Note updated successfully!"}), 200
    elif request.method == 'DELETE':
        db.session.delete(note)
        db.session.commit()
        return jsonify({"message": "Note deleted successfully!"}), 200
    
@app.route('/update-password', methods=['PUT'])
@require_session_key
def update_password():
    data = request.json
    user = User.query.get(g.user_id)  # Use g.user_id directly
    if not user:
        return jsonify({"error": "User not found"}), 404

    if bcrypt.check_password_hash(user.password, data['current_password']):
        hashed_password = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        return jsonify({"message": "Password updated successfully!"}), 200
    else:
        return jsonify({"error": "Current password is incorrect"}), 400

@app.route('/update-username', methods=['PUT'])
@require_session_key
def update_username():
    data = request.json
    user = User.query.get(g.user_id)  # Use g.user_id directly
    if not user:
        return jsonify({"error": "User not found"}), 404

    if User.query.filter_by(username=data['new_username']).first():
        return jsonify({"error": "Username already exists"}), 400

    user.username = data['new_username']
    db.session.commit()
    return jsonify({"message": "Username updated successfully!"}), 200

@app.route('/delete-account', methods=['DELETE'])
@require_session_key
def delete_account():
    data = request.json
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({"error": "Incorrect password"}), 400

    try:
        Note.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "Account and all related data deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')
