from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # To allow cross-origin requests
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note = db.Column(db.Text, nullable=False)

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

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({"message": "Login successful!", "user_id": user.id}), 200
    return jsonify({"error": "Invalid credentials"}), 400

# Route to update password
@app.route('/update-password', methods=['PUT'])
def update_password():
    data = request.json
    user = User.query.filter_by(id=data['user_id']).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check if the current password is correct
    if bcrypt.check_password_hash(user.password, data['current_password']):
        # Hash and update the new password
        hashed_password = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        return jsonify({"message": "Password updated successfully!"}), 200
    else:
        return jsonify({"error": "Current password is incorrect"}), 400

# Route to update username
@app.route('/update-username', methods=['PUT'])
def update_username():
    data = request.json
    user = User.query.filter_by(id=data['user_id']).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Ensure the new username is unique
    if User.query.filter_by(username=data['new_username']).first():
        return jsonify({"error": "Username already exists"}), 400

    # Update the username
    user.username = data['new_username']
    db.session.commit()
    return jsonify({"message": "Username updated successfully!"}), 200


@app.route('/notes', methods=['GET', 'POST'])
def manage_notes():
    if request.method == 'POST':
        data = request.json
        note = Note(user_id=data['user_id'], note=data['note'])
        db.session.add(note)
        db.session.commit()
        return jsonify({"message": "Note added successfully!"}), 201
    else:
        user_id = request.args.get('user_id')
        notes = Note.query.filter_by(user_id=user_id).all()
        return jsonify([{"id": note.id, "note": note.note} for note in notes])

@app.route('/notes/<int:note_id>', methods=['PUT', 'DELETE'])
def update_delete_note(note_id):
    note = Note.query.get(note_id)
    if not note:
        return jsonify({"error": "Note not found"}), 404

    if request.method == 'PUT':
        data = request.json
        note.note = data['note']
        db.session.commit()
        return jsonify({"message": "Note updated successfully!"}), 200

    elif request.method == 'DELETE':
        db.session.delete(note)
        db.session.commit()
        return jsonify({"message": "Note deleted successfully!"}), 200

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensures all database tables are created
    app.run(debug=True)

