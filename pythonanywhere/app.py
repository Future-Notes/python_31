from flask import Flask, request, jsonify, g, render_template  
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint                        
from flask_bcrypt import Bcrypt                                 
from flask_cors import CORS                                    
from datetime import datetime, timedelta
import secrets
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
UPLOAD_FOLDER = 'static/uploads/profile_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# In-memory session key store
session_keys = {}

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_picture = db.Column(db.String(200), nullable=True)  # Allow profile picture to be None
    allows_sharing = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), nullable=False, default="user")  # Default role is "user"
    
    __table_args__ = (
        CheckConstraint(role.in_(["user", "admin"]), name="check_role_valid"),  # Restrict values
    )


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=True)
    note = db.Column(db.Text, nullable=False)
    tag = db.Column(db.String(100), nullable=True)  # Allow tag to be None

class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)

# Helper function to generate and manage session keys, aswell as allowed extensions
def generate_session_key(user_id):
    key = secrets.token_hex(32)
    session_keys[key] = {
        "user_id": user_id,
        "expires_at": datetime.now() + timedelta(minutes=120),
        "last_active": datetime.now()
    }
    return key

def validate_session_key():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return False, "Invalid or missing session API key"

    key = auth_header.split("Bearer ")[1]
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

@app.errorhandler(404)
def page_note_found(error):
    return render_template('404.html')

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

@app.route('/admin_page')
def admin_page():
    return render_template('admin.html')

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
    


@app.route('/share-note/<int:note_id>', methods=['POST'])
def share_note(note_id):
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    allows_sharing = user.allows_sharing
    if not allows_sharing:
        return jsonify({"error": "User does not allow sharing notes"}), 400

    original_note = Note.query.get(note_id)
    if not original_note:
        return jsonify({"error": "Note not found"}), 404

    try:
        new_note = Note(
            user_id=user.id,
            title=original_note.title,
            note=original_note.note,
            tag=original_note.tag
        )
        db.session.add(new_note)
        db.session.commit()
        return jsonify({"message": "Note shared successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    
@app.route('/update-profile-picture', methods=['POST', 'DELETE'])
@require_session_key
def update_profile_picture():
    if request.method == 'POST':
        user = User.query.get(g.user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        if 'profile_picture' not in request.files:
            return jsonify({"error": "No file part in the request"}), 400

        file = request.files['profile_picture']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        if file and allowed_file(file.filename):
            # Sanitize the filename for security
            filename = secure_filename(f"{user.username}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Update user record in the database
            user.profile_picture = file_path
            db.session.commit()

            return jsonify({"message": "Profile picture updated successfully", "path": file_path}), 200

        return jsonify({"error": "Invalid file format"}), 400
    elif request.method == 'DELETE':
        user = User.query.get(g.user_id)
        if not user:
            print("user not found")
            return jsonify({"error": "User not found"}), 404

        if user.profile_picture:
            os.remove(user.profile_picture)
            user.profile_picture = None
            db.session.commit()
            return jsonify({"message": "Profile picture deleted successfully!"}), 200

        return jsonify({"error": "No profile picture to delete"}), 400

@app.route('/user-info', methods=['GET'])
@require_session_key
def get_user_info():
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": user.username,
        "profile_picture": user.profile_picture,
        "allows_sharing": user.allows_sharing,
        "role": user.role
    }), 200

@app.route('/allow-sharing', methods=['PUT'])
@require_session_key
def allow_sharing():
    data = request.json
    if not data or 'allows_sharing' not in data:
        return jsonify({"error": "Invalid request"}), 400

    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        user.allows_sharing = data['allows_sharing']
        db.session.commit()
        return jsonify({"message": "Sharing preference updated successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating sharing preference: {e}")
        return jsonify({"error": "Failed to update sharing preference"}), 500


@app.route('/admin', methods=['GET', 'DELETE', 'PUT'])
@require_session_key
def admin():
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if user.role != "admin":
        return jsonify({"error": "Insufficient permissions"}), 400

    if request.method == 'GET':
        # Fetch users and messages
        users = User.query.with_entities(User.id, User.username, User.profile_picture, User.allows_sharing, User.role).all()
        messages = Messages.query.with_entities(Messages.id, Messages.email, Messages.message).all()
        return jsonify({
            "users": [user._asdict() for user in users],
            "messages": [message._asdict() for message in messages],
        })

    if request.method == 'DELETE':
        data = request.json
        target = data.get('target')
        target_type = data.get('type')

        if target_type == 'message':
            message = Messages.query.get(target)
            if not message:
                return jsonify({"error": "Message not found"}), 404
            db.session.delete(message)
            db.session.commit()
            return jsonify({"message": "Message deleted successfully"}), 200

        elif target_type == 'user':
            user_to_delete = User.query.get(target)
            if not user_to_delete:
                return jsonify({"error": "User not found"}), 404
            db.session.delete(user_to_delete)
            db.session.commit()
            return jsonify({"message": "User deleted successfully"}), 200

        return jsonify({"error": "Invalid target type"}), 400

    if request.method == 'PUT':
        data = request.json
        target_user_id = data.get('user_id')
        new_role = data.get('new_role')

        user_to_update = User.query.get(target_user_id)
        if not user_to_update:
            return jsonify({"error": "User not found"}), 404

        if new_role not in ["user", "admin"]:
            return jsonify({"error": "Invalid role value"}), 400

        user_to_update.role = new_role
        db.session.commit()
        return jsonify({"message": f"Role updated to {new_role} for user {target_user_id}"}), 200

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

@app.route('/test-session', methods=['GET'])
@require_session_key
def test_session():
    return jsonify({"message": "Session is valid!"}), 200

@app.route('/notes', methods=['GET', 'POST'])
@require_session_key
def manage_notes():
    if request.method == 'POST':
        data = request.json
        title = data.get('title')  # Get the title if provided, else None
        note = data['note']
        tag = data.get('tag')  # Get the tag if provided, else None
        new_note = Note(user_id=g.user_id, title=title, note=note, tag=tag)
        db.session.add(new_note)
        db.session.commit()
        return jsonify({"message": "Note added successfully!"}), 201
    else:
        notes = Note.query.filter_by(user_id=g.user_id).all()
        sanitized_notes = [{"id": note.id, "title": note.title, "note": note.note, "tag": note.tag} for note in notes]
        return jsonify(sanitized_notes)


@app.route('/notes/<int:note_id>', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_note(note_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != g.user_id:
        return jsonify({"error": "Note not found"}), 404

    if request.method == 'PUT':
        data = request.json
        note.title = data.get('title')  # Update the title if provided, else None
        note.note = data['note']
        note.tag = data.get('tag')  # Update the tag if provided, else None
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
    app.run(debug=True, host="0.0.0.0")
