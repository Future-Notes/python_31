# ------------------------------Imports--------------------------------
from flask import Flask, request, jsonify, g, render_template, make_response, session, send_from_directory, current_app, redirect, url_for, abort
from flask.json.provider import DefaultJSONProvider
from functools import wraps
from werkzeug.exceptions import HTTPException
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, desc, event, text, MetaData, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm.attributes import get_history
from flask_bcrypt import Bcrypt                                 
from flask_cors import CORS                                    
from datetime import datetime, timedelta
import datetime as dt_module
import secrets
from werkzeug.utils import secure_filename
from git import Repo, GitCommandError
import os
import json
import uuid
import random
import string
import time
import glob
import threading
from update_DB import update_tables
from math import floor
import re
import traceback
import subprocess
import shutil
import enum

# ------------------------------Global variables--------------------------------
class CustomJSONProvider(DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        # fall back to the built‑in handlers
        return super().default(obj)
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json_provider_class = CustomJSONProvider
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
UPLOAD_FOLDER = 'static/uploads/profile_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
session_keys = {}
games = {}
BOARD_SIZE = 10
CORRECT_PIN = "1234"
app.secret_key = os.urandom(24)
_pending_mutations = {}
excluded_tables = {
    'trophy',
}
REPO_PATH = "/home/Bosbes/mysite/python_31"
PYANYWHERE_RE = re.compile(r"^[^.]+\.(pythonanywhere\.com)$$", re.IGNORECASE)
BACKUP_DIR = os.path.join(os.getcwd(), 'backups')
if not os.path.isdir(BACKUP_DIR):
    os.makedirs(BACKUP_DIR, exist_ok=True)
ERROR_MESSAGES = {
    "ERR-1001": "Something went wrong. Please try again later.",
    "DB-2002": "A database issue occurred. Please retry your request.",
}
error_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Error Occurred</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f8f8f8;
      margin: 40px;
      color: #333;
    }
    .container {
      max-width: 600px;
      margin: auto;
      background: #fff;
      padding: 20px;
      border-radius: 5px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
      text-align: center;
    }
    h1 {
      color: #cc0000;
    }
    .error-code {
      font-size: 18px;
      font-weight: bold;
      color: #555;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Error</h1>
    <p>{{ message }}</p>
    <p class="error-code">Error Code: {{ code }}</p>
  </div>
</body>
</html>
'''

# --------------------------------Models--------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    lasting_key = db.Column(db.String(200), nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True)  # Allow profile picture to be None
    allows_sharing = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), nullable=False, default="user")  # Default role is "user"
    suspended = db.Column(db.Boolean, default=False, nullable=False)
    startpage = db.Column(db.String(20), nullable=False, default="/index")
    database_dump_tag = db.Column(db.Boolean, default=False, nullable=False)
    colors = db.relationship(
        "UserColor",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
    )
    
    __table_args__ = (
        CheckConstraint(role.in_(["user", "admin"]), name="check_role_valid"),  # Restrict values
    )

class UserColor(db.Model):
    __tablename__ = "user_colors"
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id", ondelete="CASCADE"),
        primary_key=True,
    )
    background_color  = db.Column(db.String(7), nullable=False, default="#2c2c2c")
    header_color      = db.Column(db.String(7), nullable=False, default="#3a3a3a")
    contrasting_color = db.Column(db.String(7), nullable=False, default="#1e1e1e")
    button_color      = db.Column(db.String(7), nullable=False, default="#424242")

    user = db.relationship("User", back_populates="colors")

class IpAddres(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip = db.Column(db.String(30), nullable=False)

class Group(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    admin = db.Column(db.Boolean, nullable=False, default=False)

    user = db.relationship("User", backref="group_memberships")
    group = db.relationship("Group", backref="members")

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    calendar_id = db.Column(db.Integer, db.ForeignKey('calendar.id'), nullable=False)  # New field

    recurrence_rule = db.Column(db.String(255), nullable=True)
    recurrence_end_date = db.Column(db.DateTime, nullable=True)
    is_all_day = db.Column(db.Boolean, nullable=False, default=False)
    color = db.Column(db.String(7), nullable=True)

    user = db.relationship('User', backref=db.backref('appointments', lazy=True))
    calendar = db.relationship('Calendar', backref=db.backref('appointments', lazy=True))
    notes = db.relationship('Note', secondary='appointment_note', backref='appointments')

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "start_datetime": self.start_datetime.isoformat(),
            "end_datetime": self.end_datetime.isoformat(),
            "user_id": self.user_id,
            "calendar_id": self.calendar_id,  # Include calendar id
            "recurrence_rule": self.recurrence_rule,
            "recurrence_end_date": self.recurrence_end_date.isoformat() if self.recurrence_end_date else None,
            "is_all_day": self.is_all_day,
            "color": self.color,
            "notes": [note.to_dict() for note in self.notes]
        }

class Calendar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, default="My calendar")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_default = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('calendars', lazy=True))

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "user_id": self.user_id,
            "is_default": self.is_default,
        }


# Many-to-Many Association Table (Appointments <-> Notes)
appointment_note = db.Table(
    'appointment_note',
    db.Column('appointment_id', db.Integer, db.ForeignKey('appointment.id'), primary_key=True),
    db.Column('note_id', db.Integer, db.ForeignKey('note.id'), primary_key=True)
)

class Todo(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('user.id'),
                               nullable=False)
    title          = db.Column(db.String(100), nullable=False)
    text           = db.Column(db.Text, nullable=True)
    due_date       = db.Column(db.DateTime, nullable=True)
    completed      = db.Column(db.Boolean, default=False)
    
    # New columns:
    note_id        = db.Column(db.Integer, db.ForeignKey('note.id'),
                               nullable=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'),
                               nullable=True)

    # Relationships:
    note           = db.relationship("Note", backref="todos")
    appointment    = db.relationship("Appointment", backref="todos")
    user           = db.relationship("User", backref="todos")

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "text": self.text,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "completed": self.completed,
            "user_id": self.user_id,
            "note_id": self.note_id,
            "appointment_id": self.appointment_id
        }



class Trophy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    icon = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f'<Trophy level={self.level} name={self.name}>'
    
class PlayerXp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    xp = db.Column(db.Float, default=0)

    def __repr__(self):
        return f'<PlayerXp user_id={self.user_id} xp={self.xp}>'


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=True)
    title = db.Column(db.String(100), nullable=True)
    note = db.Column(db.Text, nullable=False)
    tag = db.Column(db.String(100), nullable=True)

    group = db.relationship("Group", backref="notes")

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "note": self.note,
            "tag": self.tag,
            "user_id": self.user_id,
            "group_id": self.group_id
        }


class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)

class UTMTracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    utm_source = db.Column(db.String(50))
    utm_medium = db.Column(db.String(50))
    utm_campaign = db.Column(db.String(50))
    ip = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Updated Invite model if storing the inviter's id
class Invite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    group_name = db.Column(db.String(100), nullable=False)
    invited_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# Simplified model: only string values
class Setting(db.Model):
    __tablename__ = 'settings'

    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.String, nullable=False)


class MutationLog(db.Model):
    __tablename__   = 'mutation_log'
    id              = db.Column(db.Integer, primary_key=True)
    transaction_id  = db.Column(db.String, index=True)
    table_name      = db.Column(db.String)
    pk              = db.Column(db.String)
    column_name     = db.Column(db.String, nullable=True)
    old_value       = db.Column(db.Text,   nullable=True)
    new_value       = db.Column(db.Text,   nullable=True)
    action          = db.Column(db.String)  # 'insert', 'update', 'delete'
    timestamp       = db.Column(db.DateTime, default=db.func.now())

#---------------------------------Helper functions--------------------------------
def generate_session_key(user_id):
    key = secrets.token_hex(32)
    session_keys[key] = {
        "user_id": user_id,
        "expires_at": datetime.now() + timedelta(minutes=120),
        "last_active": datetime.now()
    }
    seed_trophies()
    return key

def check(key: str, default: str) -> str:
    """
    Returns the application-wide setting for `key` as a string.

    If the setting does not exist, it will be created with the provided
    default value and returned.

    Args:
        key (str): Name of the setting to lookup or create.
        default (str): Default string value if the setting does not exist.

    Returns:
        str: The current or newly-created value of the setting.
    """
    app = current_app._get_current_object()
    with app.app_context():
        setting = Setting.query.get(key)
        if not setting:
            # Create new setting with default string
            setting = Setting(key=key, value=default)
            db.session.add(setting)
            db.session.commit()
            return default
        return setting.value


def rollback_transaction(transaction_id):
    """
    Rolls back all mutations in a transaction, in reverse order.
    Handles edge cases, errors, and ensures atomicity.
    """
    logs = (
        MutationLog.query
        .filter_by(transaction_id=transaction_id)
        .order_by(MutationLog.id.desc())  # reverse order
        .all()
    )
    if not logs:
        raise ValueError(f"No logs found for transaction {transaction_id}")

    try:
        for log in logs:
            table = log.table_name
            pk = log.pk
            col = log.column_name
            old_val = json.loads(log.old_value) if log.old_value else None

            # Skip excluded tables for safety
            if table in excluded_tables:
                continue

            if log.action == 'insert':
                # Rollback insert = delete the row
                db.session.execute(
                    text(f"DELETE FROM {table} WHERE id = :pk"),
                    {"pk": pk}
                )

            elif log.action == 'delete':
                # Rollback delete = re-insert old values
                if not old_val:
                    continue  # nothing to restore
                cols = ', '.join(old_val.keys())
                placeholders = ', '.join([f":{k}" for k in old_val.keys()])
                try:
                    db.session.execute(
                        text(f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"),
                        old_val
                    )
                except Exception as e:
                    # If row already exists, skip
                    if "UNIQUE constraint failed" in str(e):
                        continue
                    raise

            elif log.action == 'update':
                if col is None:
                    continue  # nothing to update
                db.session.execute(
                    text(f"UPDATE {table} SET {col} = :old WHERE id = :pk"),
                    {"old": old_val, "pk": pk}
                )
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise RuntimeError(f"Failed to rollback transaction {transaction_id}: {e}")

@app.before_request
def capture_utm_params():
    # Extract UTM parameters from the query string
    utm_source = request.args.get('utm_source')
    utm_medium = request.args.get('utm_medium')
    utm_campaign = request.args.get('utm_campaign')

    # Store them in the session if provided, keeping previous values if they already exist
    if utm_source:
        session['utm_source'] = utm_source
    if utm_medium:
        session['utm_medium'] = utm_medium
    if utm_campaign:
        session['utm_campaign'] = utm_campaign

    # Optionally, log the UTM data to the database on each visit that has UTM parameters.
    if utm_source or utm_medium or utm_campaign:
        tracking = UTMTracking(
            utm_source=utm_source,
            utm_medium=utm_medium,
            utm_campaign=utm_campaign,
            ip=request.remote_addr
        )
        db.session.add(tracking)
        db.session.commit()

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

    # Check if user exists in the database
    user = User.query.get(session["user_id"])
    if not user:
        del session_keys[key]
        return False, "Invalid or missing session API key"

    # Check if user is suspended
    if user.suspended:
        del session_keys[key]
        return False, "Account is suspended and cannot log in."

    # Update last active time
    session["last_active"] = now
    return True, session

def create_default_calendar(user_id):
    default_calendar = Calendar(name="My calendar", user_id=user_id, is_default=True)
    db.session.add(default_calendar)
    db.session.commit()
    return default_calendar

def _start_transaction(session):
    # assign a transaction UUID for this commit
    txid = str(uuid.uuid4())
    session.info['txid'] = txid
    _pending_mutations[txid] = []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Decorator for protected routes
def require_session_key(func):
    def wrapper(*args, **kwargs):
        valid, response = validate_session_key()
        if not valid:
            return jsonify({"error": response}), 403 if "suspended" in response else 401
        g.user_id = response["user_id"]  # Store user ID for the route
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@event.listens_for(db.session.__class__, "before_flush")
def before_flush(session, flush_context, instances):
    import datetime as dt_module  # ✅ bring in the datetime module under the alias dt_module

    txid = str(uuid.uuid4())
    session.info['txid'] = txid
    mutations = []
    _pending_mutations[txid] = mutations

    def serialize_row(obj):
        row = {}
        for c in obj.__table__.columns:
            row[c.name] = getattr(obj, c.name)
        # let json.dumps handle datetimes (and any other weird types) by converting to str
        return json.dumps(
            row,
            default=lambda o: o.isoformat() if isinstance(o, dt_module.datetime) else str(o)
        )

    # INSERTs
    for obj in session.new:
        table = obj.__tablename__
        if table in excluded_tables:
            continue
        mutations.append({
            'action': 'insert',
            'table': table,
            'pk': str(getattr(obj, 'id', None)),
            'column': None,
            'old': None,
            'new': serialize_row(obj)
        })

    # DELETEs
    for obj in session.deleted:
        table = obj.__tablename__
        if table in excluded_tables:
            continue
        mutations.append({
            'action': 'delete',
            'table': table,
            'pk': str(getattr(obj, 'id', None)),
            'column': None,
            'old': serialize_row(obj),
            'new': None
        })

    # UPDATEs
    for obj in session.dirty:
        table = obj.__tablename__
        if table in excluded_tables:
            continue
        if session.is_modified(obj, include_collections=False):
            pk = str(getattr(obj, 'id', None))
            for col in obj.__table__.columns:
                hist = get_history(obj, col.name)
                if not hist.has_changes():
                    continue
                old_val = hist.deleted[0] if hist.deleted else None
                new_val = hist.added[0] if hist.added else None
                mutations.append({
                    'action': 'update',
                    'table': table,
                    'pk': pk,
                    'column': col.name,
                    'old': json.dumps(
                        old_val,
                        default=lambda o: o.isoformat() if isinstance(o, dt_module.datetime) else str(o)
                    ),
                    'new': json.dumps(
                        new_val,
                        default=lambda o: o.isoformat() if isinstance(o, dt_module.datetime) else str(o)
                    )
                })

@event.listens_for(db.session.__class__, "after_commit")
def after_commit(session):
    txid = session.info.pop('txid', None)
    if not txid:
        return
    mutations = _pending_mutations.pop(txid, [])

    # Write logs outside the session to avoid locking issues
    with db.engine.begin() as conn:
        for m in mutations:
            conn.execute(
                MutationLog.__table__.insert().values(
                    transaction_id = txid,
                    table_name     = m['table'],
                    pk             = m['pk'],
                    column_name    = m['column'],
                    old_value      = m['old'],
                    new_value      = m['new'],
                    action         = m['action']
                )
            )


def require_login_for_templates(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        key = request.cookies.get("session_key")
        if not key:
            # no key → send to your login page
            return redirect(url_for("login_page", redirect=request.path))

        # reuse your existing validator, but pretend it came in as a header:
        # you could refactor validate_session_key to take an optional key argument;
        # for now we’ll monkey‑patch the header:
        request.headers.environ["HTTP_AUTHORIZATION"] = f"Bearer {key}"
        valid, session_or_msg = validate_session_key()
        if not valid:
            return redirect(url_for("login_page", redirect=request.path))

        # success → stash user_id for route & templates
        g.user_id = session_or_msg["user_id"]
        return func(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_user_colors():
    if getattr(g, "user_id", None):
        user = User.query.get(g.user_id)
        # if they somehow have no row yet, fall back to defaults
        cols = ensure_user_colors(user.id)
        return {
            "bg_color":  cols.background_color,
            "hdr_color": cols.header_color,
            "ctr_color": cols.contrasting_color,
            "btn_color": cols.button_color,
        }
    return {}

def ensure_user_colors(user_id):
    """
    Guarantee there is a UserColor row for this user_id.
    If missing, create one with all the default colors.
    Returns the UserColor instance.
    """
    uc = UserColor.query.filter_by(user_id=user_id).first()
    if not uc:
        uc = UserColor(user_id=user_id)  # defaults are on the model
        db.session.add(uc)
        db.session.commit()
    return uc

def run_update_script():
    # This function runs the update script in a separate thread
    try:
        # Change directory if necessary and run the update script
        result = subprocess.run(
            "python /home/Bosbes/mysite/pull.py",
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        app.logger.info("Update successful: %s", result.stdout)
    except subprocess.CalledProcessError as e:
        app.logger.error("Update failed: %s", e.stderr)

# Helper to get repo object
def get_repo(path):
    if not os.path.isdir(path):
        raise FileNotFoundError(f"Repository path not found: {path}")
    return Repo(path)

# Common admin check decorator (you already have this)
def require_admin(fn):
    def wrapper(*args, **kwargs):
        user = User.query.get(g.user_id)
        if not user or user.role != "admin":
            return jsonify({"error": "Unauthorized: only admins"}), 403
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def require_pythonanywhere_domain(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        host = request.host.split(":", 1)[0].lower()
        if not host.endswith(".pythonanywhere.com"):
            return (
                jsonify({"error": "Forbidden: this endpoint only works on pythonanywhere.com domain"}),
                403
            )
        return fn(*args, **kwargs)
    return wrapper

def delete_profile_pictures(username):
    """ Deletes all profile pictures associated with the given username. """
    profile_pictures_path = os.path.join(UPLOAD_FOLDER)
    user_pictures = glob.glob(os.path.join(profile_pictures_path, f"{username}_*"))

    for picture in user_pictures:
        try:
            os.remove(picture)
        except Exception as e:
            print(f"Failed to delete {picture}: {e}")

def sync_profile_pics_files_db():
    """ Syncs the profile pictures in the database with the actual files for all users. """
    # Get all users from the database
    users = User.query.all()

    # Get all profile pictures in the folder
    profile_pictures = os.listdir(app.config['UPLOAD_FOLDER'])
    profile_pictures = [os.path.join(app.config['UPLOAD_FOLDER'], pic).replace("\\", "/") for pic in profile_pictures]

    # Ensure usernames dont have underscores before attempting to match them with files
    cleanup_bad_usernames()

    # Ensure profile picture formats are valid before attempting to match them with files
    validate_pics_format()

    for user in users:
        # Check if the user's profile picture exists in the folder
        if user.profile_picture and user.profile_picture not in profile_pictures:
            # If the database has a record but the file doesn't exist, delete the record
            user.profile_picture = None

        # Check for files in the folder that are not in the database
        for picture in profile_pictures:
            # Extract the username from the file name (everything before the first underscore)
            filename = os.path.basename(picture)
            username = filename.split("_", 1)[0]

            # Check if a user with this username exists in the database
            user = User.query.filter_by(username=username).first()

            if user:
            # If the user exists, add the relative path to the database
                user.profile_picture = picture.replace("\\", "/")
            else:
            # If the user does not exist, delete the file
                try:
                    os.remove(picture)
                except Exception as e:
                    print(f"Failed to delete {picture}: {e}")

    # Commit all changes to the database
    db.session.commit()

def cleanup_bad_usernames():
    """ Replaces underscores in usernames with dashes. """
    users = User.query.all()
    for user in users:
        if "_" in user.username:
            user.username = user.username.replace("_", "-")
    db.session.commit()

def validate_pics_format():
    """ Validates the format of profile pictures in the database. """
    users = User.query.all()
    for user in users:
        if user.profile_picture and not allowed_file(user.profile_picture):
            db.session.delete(user.profile_picture)
            user.profile_picture = None
    db.session.commit()


def handle_group_membership(user_id):
    """ Handles removal or admin transfer for groups the user is in. """
    memberships = GroupMember.query.filter_by(user_id=user_id).all()

    for membership in memberships:
        if not membership.admin:
            db.session.delete(membership)
        else:
            group_id = membership.group_id
            group_members = GroupMember.query.filter_by(group_id=group_id).all()

            if len(group_members) == 1:
                delete_group_and_notes(group_id)
            else:
                transfer_admin_rights(group_id, user_id)

            db.session.delete(membership)

def transfer_admin_rights(group_id, admin_id):
    """ Transfers admin rights to the next available group member. """
    next_admin = GroupMember.query.filter(GroupMember.group_id == group_id, GroupMember.user_id != admin_id).first()

    if next_admin:
        next_admin.admin = True
    else:
        raise Exception("No other members found to transfer admin rights.")

def delete_group_and_notes(group_id):
    """ Deletes all notes associated with the group and removes the group. """
    Note.query.filter_by(group_id=group_id).delete()
    Group.query.filter_by(id=group_id).delete()

def delete_user_and_data(user):
    """ Deletes all notes and the user itself. """
    Note.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)

def generate_game_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_bot_ships():
    ship_sizes = [5, 4, 3, 3, 2]  # Standard Battleship sizes
    ships = []
    occupied_positions = set()

    for size in ship_sizes:
        placed = False
        
        while not placed:
            x = random.randint(0, 9)
            y = random.randint(0, 9)
            orientation = random.choice(["horizontal", "vertical"])
            
            if orientation == "horizontal":
                if x + size > 10:
                    continue  # Ship would be out of bounds
                positions = [(x + i, y) for i in range(size)]
            else:
                if y + size > 10:
                    continue  # Ship would be out of bounds
                positions = [(x, y + i) for i in range(size)]
            
            # Check for overlap
            if any(pos in occupied_positions for pos in positions):
                continue
            
            # Place ship
            occupied_positions.update(positions)
            ships.append({"positions": [list(pos) for pos in positions], "sunk": False})
            placed = True
    
    return ships

def process_fire(game, player, x, y):
    """
    Processes a fire action for the given player at (x, y).
    Returns a dict with result details: hit/miss, status, turn, winner, and sunk ship (if any).
    """
    opponent = "player1" if player == "player2" else "player2"
    opponent_ships = game["players"][opponent]["ships"]

    hit = False
    sunk_ship = None
    for ship in opponent_ships:
        if [x, y] in ship["positions"]:
            hit = True
            game["players"][player]["hits"].append([x, y])
            break

    if not hit:
        game["players"][player]["misses"].append([x, y])
        game["players"][opponent].setdefault("incoming_misses", []).append({"pos": [x, y], "timestamp": time.time()})

    all_opponent_positions = []
    for ship in opponent_ships:
        all_opponent_positions.extend(ship["positions"])
    if all(pos in game["players"][player]["hits"] for pos in all_opponent_positions):
        game["status"] = "gameover"
        game["winner"] = player

    if hit:
        for ship in opponent_ships:
            if not ship.get("sunk", False) and all(pos in game["players"][player]["hits"] for pos in ship["positions"]):
                ship["sunk"] = True
                sunk_ship = ship
                break
    else:
        game["turn"] = opponent

    return {
        "hit": hit,
        "status": game.get("status", "battle"),
        "turn": game.get("turn", opponent),
        "winner": game.get("winner"),
        "sunk": sunk_ship
    }

# Helper: check if already fired

def already_fired(bot, x, y):
    return [x, y] in bot.get("hits", []) or [x, y] in bot.get("misses", [])

# Compute probability heatmap for hunt mode
def compute_probability_map(bot, board_size):
    fired = set(tuple(cell) for cell in bot.get("hits", []) + bot.get("misses", []))
    remaining_ships = bot.get("remaining_ships", {5:1,4:1,3:2,2:1})
    heatmap = [[0]*board_size for _ in range(board_size)]
    for size, count in remaining_ships.items():
        if count <= 0:
            continue
        # horizontal placements
        for x in range(board_size):
            for y in range(board_size - size + 1):
                placement = [(x, y+i) for i in range(size)]
                if any(c in fired for c in placement):
                    continue
                for px, py in placement:
                    heatmap[px][py] += count
        # vertical placements
        for x in range(board_size - size + 1):
            for y in range(board_size):
                placement = [(x+i, y) for i in range(size)]
                if any(c in fired for c in placement):
                    continue
                for px, py in placement:
                    heatmap[px][py] += count
    return heatmap

# Cluster management helpers
def normalize_clusters(bot_state):
    """
    Ensure each cluster is a connected, collinear set. Split clusters with non-linear shapes into connected components.
    """
    new_clusters = []
    for cluster in bot_state['clusters']:
        cells = list(cluster)
        unvisited = set(cells)
        while unvisited:
            comp = []
            stack = [unvisited.pop()]
            while stack:
                cell = stack.pop()
                comp.append(cell)
                x, y = cell
                neighbors = [(x+dx, y+dy) for dx, dy in [(1,0),(-1,0),(0,1),(0,-1)]]
                for n in neighbors:
                    if n in unvisited:
                        unvisited.remove(n)
                        stack.append(n)
            new_clusters.append(comp)
    bot_state['clusters'] = new_clusters


def record_hit(bot, bot_state, x, y):
    """Add a unique hit and update clusters."""
    # prevent duplicate
    if [x, y] not in bot.setdefault('hits', []):
        bot['hits'].append([x, y])
    # add to cluster
    added = False
    for cluster in bot_state['clusters']:
        if any(abs(cx-x) + abs(cy-y) == 1 for cx, cy in cluster):
            cluster.append((x, y))
            added = True
            break
    if not added:
        bot_state['clusters'].append([(x, y)])
    normalize_clusters(bot_state)


def record_sink(bot, bot_state, length, sunk_cells):
    """Remove sunk cluster and update remaining ships."""
    # update ship count
    if length in bot.get('remaining_ships', {}):
        bot['remaining_ships'][length] = max(bot['remaining_ships'][length] - 1, 0)
    # remove matching cluster
    for cluster in list(bot_state['clusters']):
        if all(cell in cluster for cell in sunk_cells) or len(cluster) == length:
            bot_state['clusters'].remove(cluster)
            break
    normalize_clusters(bot_state)
    # remove hits of sunk ship
    bot['hits'] = [h for h in bot['hits'] if tuple(h) not in sunk_cells]


def get_next_cluster_shot(bot, bot_state, board_size):
    unknown = {(x, y) for x in range(board_size) for y in range(board_size)
               if not already_fired(bot, x, y)}
    for cluster in bot_state['clusters']:
        xs = [c[0] for c in cluster]
        ys = [c[1] for c in cluster]
        # horizontal cluster
        if len(cluster) >= 2 and len(set(xs)) == 1:
            row = xs[0]
            for col in (min(ys)-1, max(ys)+1):
                if 0 <= col < board_size and (row, col) in unknown:
                    return [row, col]
        # vertical cluster
        if len(cluster) >= 2 and len(set(ys)) == 1:
            col = ys[0]
            for row in (min(xs)-1, max(xs)+1):
                if 0 <= row < board_size and (row, col) in unknown:
                    return [row, col]
        # single or ambiguous
        for x, y in cluster:
            for dx, dy in [(1,0), (-1,0), (0,1), (0,-1)]:
                nx, ny = x+dx, y+dy
                if (nx, ny) in unknown and 0 <= nx < board_size and 0 <= ny < board_size:
                    return [nx, ny]
    return None

# Main bot move

def bot_move(game_code, skip_delays=False):
    """
    Make the bot take turns until it's the player's turn again or the game ends.
    skip_delays=True disables time.sleep() for instant moves.
    Returns the last shot result dict, including 'x' and 'y'.
    """
    game = games[game_code]
    bot  = game['players']['player2']
    state = bot.setdefault('botState', {'mode': 'search', 'clusters': []})
    bot.setdefault('remaining_ships', {5:1, 4:1, 3:2, 2:1})
    board_size = game.get('board_size', BOARD_SIZE)

    # Helper to optionally sleep
    def maybe_sleep(sec):
        if not skip_delays:
            time.sleep(sec)

    # Choose move
    if state['mode'] == 'search':
        heatmap = compute_probability_map(bot, board_size)
        candidates = []
        maxh = -1
        for x in range(board_size):
            for y in range(board_size):
                if not already_fired(bot, x, y) and (x + y) % 2 == 0:
                    h = heatmap[x][y]
                    if h > maxh:
                        maxh = h
                        candidates = [[x, y]]
                    elif h == maxh:
                        candidates.append([x, y])
        if not candidates:
            candidates = [[x, y] for x in range(board_size)
                          for y in range(board_size)
                          if not already_fired(bot, x, y)]
        move = random.choice(candidates)
    else:
        # Target mode
        move = get_next_cluster_shot(bot, state, board_size)
        if move is None:
            state['mode'] = 'search'
            return bot_move(game_code, skip_delays=skip_delays)

    x, y = move

    # Fire and record
    result = process_fire(game, 'player2', x, y)
    # Expose coords so client can render them
    result['x'] = x
    result['y'] = y

    if result.get('hit'):
        record_hit(bot, state, x, y)
        state['mode'] = 'target'
        if result.get('sunk'):
            length = result.get('ship_size')
            # Find the sunk cluster
            sunk_cells = None
            for cluster in state['clusters']:
                if (x, y) in cluster:
                    sunk_cells = list(cluster)
                    break
            if sunk_cells:
                record_sink(bot, state, length, sunk_cells)
            state['mode'] = 'target' if state['clusters'] else 'search'
    else:
        bot.setdefault('misses', []).append([x, y])

    # Continue firing if still bot's turn
    if game.get('status', 'battle') == 'battle' and game.get('turn') == 'player2':
        maybe_sleep(0.5)
        return bot_move(game_code, skip_delays=skip_delays)

    return result

def calculate_xp_gain(current_xp, result, accuracy, sunk_ships):
    """
    Computes XP gain based on current XP, win/loss result, accuracy, and enemy ships sunk.
    Uses additional conditions to buff XP gains for high performance:
      - Base win bonus: +500 XP for a win; a reduced penalty for losses.
      - Accuracy bonus: up to +100 XP (linear).
      - Nearly perfect accuracy (>=98%): +50 XP extra.
      - Sunk ships: 50 XP per sunk ship.
      - Combo bonus: if win with accuracy >=85% and at least 2 sunk ships, add +200 XP.
      - Multi-kill bonus: each sunk ship beyond 3 grants an extra +25 XP.
      - Performance multiplier: if win and accuracy >90%, total bonus is increased by 10%.
      - A quadratic scaling factor reduces gains as current XP increases.
    """
    # Ensure accuracy is within the valid range [0, 1]
    accuracy = max(0, min(accuracy, 1))

    # Determine scaling factor based on current XP
    # Updated scaling factor: easier XP gain at high levels
    if current_xp < 5000:
        scaling = 0.8
    elif current_xp < 10000:
        # Linear interpolation: scaling drops from 1 at 5000 XP to 0.5 at 10000 XP
        scaling = 1 - 0.5 * ((current_xp - 5000) / 5000)
    else:
        scaling = 0.5


    # Determine win/loss bonus
    base_win_bonus = 500
    if result == "win":
        win_loss_bonus = base_win_bonus
    else:
        # For losses, apply a gentler penalty to avoid overly punishing high-level players.
        if current_xp < 5000:
            win_loss_bonus = 0
        else:
            win_loss_bonus = -min(250, (current_xp - 5000) / 20)

    # Base bonus from accuracy (up to 100 XP)
    accuracy_bonus = accuracy * 100

    # Base bonus from sunk enemy ships (50 XP each)
    sunk_bonus = sunk_ships * 50

    # Additional bonus conditions
    extra_bonus = 0

    # Bonus for nearly perfect accuracy (≥98%)
    if accuracy >= 0.98:
        extra_bonus += 50

    # Combo bonus: winning with high accuracy and sinking at least 2 enemy ships
    if result == "win" and accuracy >= 0.85 and sunk_ships >= 2:
        extra_bonus += 200

    # Multi-kill bonus: bonus for every sunk ship beyond 3
    if sunk_ships > 3:
        extra_bonus += (sunk_ships - 3) * 25

    # Total bonus before scaling
    total_bonus = win_loss_bonus + accuracy_bonus + sunk_bonus + extra_bonus

    # Performance multiplier for exceptional wins (accuracy >90%)
    if result == "win" and accuracy > 0.9:
        total_bonus *= 1.1

    xp_gain = total_bonus * scaling
    return xp_gain

def calculate_level(xp):
    """Calculates the user level from total XP."""
    level = 1
    required_xp = 50
    remaining_xp = xp
    while remaining_xp >= required_xp:
        remaining_xp -= required_xp
        level += 1
        required_xp = floor(required_xp * 1.2)
    return level, remaining_xp, required_xp

def get_unlocked_trophies(user_level):
    """Returns trophies with a required level less than or equal to the user's level."""
    return Trophy.query.filter(Trophy.level <= user_level).order_by(Trophy.level).all()

def seed_trophies():
    # Remove all existing records
    Trophy.query.delete()
    db.session.commit()

    trophies_data = [
        {"level": 1, "name": "Beginner Badge", "icon": "🥉"},
        {"level": 3, "name": "Rookie Medal", "icon": "🥈"},
        {"level": 5, "name": "Apprentice Trophy", "icon": "🏆"},
        {"level": 8, "name": "Skilled Warrior", "icon": "⚔️"},
        {"level": 12, "name": "Master Explorer", "icon": "🗺️"},
        {"level": 15, "name": "Elite Strategist", "icon": "♟️"},
        {"level": 18, "name": "Champion Cup", "icon": "🏅"},
        {"level": 22, "name": "Grandmaster", "icon": "👑"},
        {"level": 26, "name": "Legendary Hero", "icon": "🔥"},
        {"level": 30, "name": "Immortal", "icon": "💀"},
        {"level": 35, "name": "Speedy", "icon": "⚡"},
        {"level": 40, "name": "Ultimate Conqueror", "icon": "🌟"},
        {"level": 45, "name": "Mythical Warrior", "icon": "🐉"},
        {"level": 50, "name": "Unstoppable", "icon": "🦾"},
        {"level": 55, "name": "Mastermind", "icon": "🧠"},
        {"level": 60, "name": "Dimensional Traveler", "icon": "🚀"},
        {"level": 65, "name": "Void Walker", "icon": "🌌"},
        {"level": 70, "name": "Infinity Breaker", "icon": "♾️"},
        {"level": 75, "name": "Omnipotent", "icon": "🔱"},
        {"level": 80, "name": "Beyond Reality", "icon": "🌀"},
        {"level": 85, "name": "Galactic Ruler", "icon": "🌠"},
        {"level": 90, "name": "Cosmic Guardian", "icon": "🌌"},
        {"level": 95, "name": "Eternal Champion", "icon": "🏅"},
        {"level": 100, "name": "Supreme Deity", "icon": "👑"},
        {"level": 105, "name": "Celestial Knight", "icon": "🌟"},
        {"level": 110, "name": "Astral Commander", "icon": "🚀"},
        {"level": 115, "name": "Quantum Master", "icon": "⚛️"},
        {"level": 120, "name": "Stellar Conqueror", "icon": "🌠"},
        {"level": 125, "name": "Nebula Navigator", "icon": "🌌"},
        {"level": 130, "name": "Galactic Emperor", "icon": "👑"},
        {"level": 135, "name": "Cosmic Overlord", "icon": "🌌"},
        {"level": 140, "name": "Universal Ruler", "icon": "🌌"},
        {"level": 145, "name": "Eternal Sovereign", "icon": "👑"},
        {"level": 150, "name": "Infinite Monarch", "icon": "♾️"},
        {"level": 155, "name": "Timeless Titan", "icon": "⏳"},
        {"level": 160, "name": "Immortal Legend", "icon": "🔥"},
        {"level": 165, "name": "Supreme Overlord", "icon": "👑"},
        {"level": 170, "name": "Omniscient Sage", "icon": "🧙"},
        {"level": 175, "name": "Transcendent Being", "icon": "🌌"},
        {"level": 180, "name": "Infinite Sage", "icon": "♾️"},
        {"level": 185, "name": "Eternal Guardian", "icon": "🛡️"},
        {"level": 190, "name": "Cosmic Sage", "icon": "🌌"},
        {"level": 195, "name": "Galactic Sage", "icon": "🌌"},
        {"level": 200, "name": "Supreme Sage", "icon": "👑"}
    ]
    for trophy in trophies_data:
        new_trophy = Trophy(
            level=trophy["level"],
            name=trophy["name"],
            icon=trophy["icon"]
        )
        db.session.add(new_trophy)
    db.session.commit()
    print("Trophies seeded successfully.")
#---------------------------------Error handlers---------------------------------

@app.errorhandler(OperationalError)
def handle_operational_error(e):
    error_str = str(e.orig)
    if "no such table" in error_str or "no such column" in error_str:
        # Update the schema if an expected error is encountered
        update_tables()
        # Optionally: you can either retry the request or inform the client to retry.
        return jsonify({"message": "Database schema updated. Please retry your request."}), 500
    return jsonify({"error": "Internal Server Error"}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    # Capture the full traceback
    tb = traceback.format_exc()
    # Log the traceback for your own record
    app.logger.error(tb)
    
    # Return the full traceback to the client
    return jsonify({
        "error": "An unexpected error occurred.",
        "traceback": tb
    }), 500

@app.errorhandler(404)
def page_not_found(error):
    # Check if the error is related to the profile pictures URL
    if request.path.startswith('/static/uploads/profile_pictures'):
        sync_profile_pics_files_db()
        return jsonify({"message": "Profile pictures synced successfully!"}), 200

    # Default behavior for other 404 errors
    return render_template('404.html'), 404

# Function to generate unique error codes (or use predefined ones)
def generate_error_code():
    return f"ERR-{random.randint(1000, 9999)}"

#---------------------------------Template routes--------------------------------

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/favicon.ico')
def send_favicon():
    return send_from_directory('static', 'favicon.ico')

@app.route('/index')
@require_login_for_templates
def index():
    return render_template('index.html')

@app.route('/todo_page')
@require_login_for_templates
def todo_page():
    if check("todo", "Nee") == "Ja":
        return render_template('todo.html')
    else: 
        abort(404)

@app.route('/login_page')
def login_page():
    args = request.args.to_dict()
    return render_template('login.html', **args)

@app.route('/signup_page')
def signup_page():
    args = request.args.to_dict()
    return render_template('signup.html', **args)

@app.route('/account_page')
@require_login_for_templates
def account_page():
    return render_template('account.html')

@app.route('/admin_page')
def admin_page():
    return render_template('admin.html')

@app.route('/admin-utm-tracking')
def admin_utm_tracking():
    return render_template('source_dashboard.html')

@app.route('/database')
def database_viewer():
    return render_template('database_viewer.html')

@app.route('/group-notes')
@require_login_for_templates
def group_notes():
    return render_template("group_index.html")

@app.route('/setup')
def setup():
    return render_template('setup.html')

@app.route('/pws')
def pws():
    return render_template('pws.html')

@app.route('/battle')
def battle():
    return render_template('battle.html')

@app.route('/spectate_callback')
def spectate():
    return render_template('spectate.html')

@app.route('/spectate')
def spectate_setup():
    return render_template('spectate_list.html')

@app.route('/bot-info')
def bot_info():
    return render_template('bot_info.html')

@app.route('/leaderboard')
def leaderboard():
    return render_template('leaderboard.html')

@app.route('/scheduler-page')
@require_login_for_templates
def scheduler_page():
    return render_template('scheduler.html')

@app.route('/apple-hate')
def apple_hate():
    return render_template('anti-apple.html')

@app.route('/mutations_page')
def mutations_page():
    return render_template('mutations.html')

@app.route('/checks_page')
def checks_page():
    return render_template('checks.html')

#---------------------------------API routes--------------------------------

# Only expose in non-production or over localhost for safety
@app.route('/_manager/routes', methods=['GET'])
def manager_list_routes():
    # Block if not coming from localhost
    if request.remote_addr not in ('127.0.0.1', '::1', 'localhost'):
        abort(403)

    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            "endpoint": rule.endpoint,
            "rule": str(rule),
            "methods": sorted(rule.methods - {'HEAD', 'OPTIONS'})  # filter out boilerplate
        })
    return jsonify(routes)


# Homepage

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
    

# User info

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
        "role": user.role,
        "startpage": user.startpage
    }), 200

# Routes for managing settings
@app.route('/checks', methods=['GET'])
@require_session_key
@require_admin
def list_settings():
    """Returns all settings as JSON."""
    settings = Setting.query.all()
    return jsonify([
        {'key': s.key, 'value': s.value}
        for s in settings
    ])

@app.route('/checks', methods=['POST'])
@require_session_key
@require_admin
def create_setting():
    data = request.get_json() or {}
    key = data.get('key')
    value = data.get('value')

    if not key or value is None:
        abort(400, 'Key and value are required')
    if Setting.query.get(key):
        abort(400, 'Key exists')

    setting = Setting(key=key, value=str(value))
    db.session.add(setting)
    db.session.commit()
    return jsonify({'status': 'created'}), 201

@app.route('/checks/<string:key>', methods=['PUT'])
@require_session_key
@require_admin
def update_setting(key):
    data = request.get_json() or {}
    if 'value' not in data:
        abort(400, 'Value is required')

    setting = Setting.query.get_or_404(key)
    setting.value = str(data['value'])
    db.session.commit()
    return jsonify({'status': 'updated'})

@app.route('/checks/<string:key>', methods=['DELETE'])
@require_session_key
@require_admin
def delete_setting(key):
    """Deletes a setting by key."""
    setting = Setting.query.get_or_404(key)
    db.session.delete(setting)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# Appointments

# 1. Fetch all appointments for the current user
@app.route('/appointments', methods=['GET'])
@require_session_key
def get_appointments():
    user_id = g.user_id
    calendar_id = request.args.get('calendar_id', type=int)
    query = Appointment.query.filter_by(user_id=user_id)
    
    # Ensure the user has a default calendar
    user_calendars = Calendar.query.filter_by(user_id=user_id).all()
    default_calendar = next((cal for cal in user_calendars if cal.is_default), None)
    if not default_calendar:
        default_calendar = create_default_calendar(user_id)
    
    # Assign appointments without a calendar ID to the default calendar
    appointments_without_calendar = query.filter_by(calendar_id=None).all()
    for appt in appointments_without_calendar:
        appt.calendar_id = default_calendar.id
    db.session.commit()
    
    if calendar_id:
        query = query.filter_by(calendar_id=calendar_id)
    appointments = query.all()
    appointments_data = [appt.to_dict() for appt in appointments]
    return jsonify({"appointments": appointments_data}), 200

# 2. Create a new appointment with start and end times
@app.route('/appointments', methods=['POST'])
@require_session_key
def create_appointment():
    data = request.get_json() or {}
    title = data.get('title')
    description = data.get('description', '')
    start_datetime_str = data.get('start_datetime')
    end_datetime_str = data.get('end_datetime')
    recurrence_rule = data.get('recurrence_rule')  # Optional recurrence rule (e.g., "FREQ=WEEKLY;BYDAY=MO,WE,FR")
    recurrence_end_date_str = data.get('recurrence_end_date')  # Optional recurrence end date
    note_ids = data.get('note_ids', [])  # List of note IDs to attach
    is_all_day = data.get('is_all_day', False)  # Optional all-day flag
    color = data.get('color', None)  # Optional color for the appointment
    calendar_id = data.get('calendar_id')  # New field

    # Validate required fields
    if not title or not start_datetime_str or not end_datetime_str:
        return jsonify({"error": "Missing required fields: title, start_datetime, and end_datetime"}), 400
    
    # Retrieve the calendar: either the one provided or the default calendar for the user
    if calendar_id:
        calendar = Calendar.query.filter_by(id=calendar_id, user_id=g.user_id).first()
        if not calendar:
            return jsonify({"error": "Calendar not found or not owned by user."}), 404
    else:
        # Fetch default calendar
        calendar = Calendar.query.filter_by(user_id=g.user_id, is_default=True).first()
        if not calendar:
            return jsonify({"error": "Default calendar not found for user."}), 404

    # Validate datetime formats
    try:
        start_datetime = datetime.fromisoformat(start_datetime_str)
        end_datetime = datetime.fromisoformat(end_datetime_str)
    except ValueError:
        return jsonify({"error": "Invalid datetime format. Use ISO 8601 format."}), 400

    # Validate datetime logic
    if end_datetime <= start_datetime:
        return jsonify({"error": "end_datetime must be after start_datetime."}), 400

    if end_datetime.date() != start_datetime.date():
        return jsonify({"error": "Appointments cannot span multiple days."}), 400

    # Validate optional recurrence_end_date
    recurrence_end_date = None
    if recurrence_end_date_str:
        try:
            recurrence_end_date = datetime.fromisoformat(recurrence_end_date_str)
            if recurrence_end_date <= end_datetime:
                return jsonify({"error": "recurrence_end_date must be after end_datetime."}), 400
        except ValueError:
            return jsonify({"error": "Invalid recurrence_end_date format. Use ISO 8601 format."}), 400

    # Validate note IDs
    if note_ids:
        if not isinstance(note_ids, list) or not all(isinstance(note_id, int) for note_id in note_ids):
            return jsonify({"error": "note_ids must be a list of integers."}), 400

        notes = Note.query.filter(Note.id.in_(note_ids), Note.user_id == g.user_id).all()
        if len(notes) != len(note_ids):
            return jsonify({"error": "One or more note IDs are invalid or do not belong to the user."}), 400

    # Ensure title length is reasonable
    if len(title) > 120:
        return jsonify({"error": "Title exceeds the maximum allowed length of 120 characters."}), 400

    # Ensure description length is reasonable
    if len(description) > 1000:
        return jsonify({"error": "Description exceeds the maximum allowed length of 1000 characters."}), 400
    
    #validate color to be a valid hex color code
    if color and not re.match(r'^#[0-9A-Fa-f]{6}$', color):
        return jsonify({"error": "Invalid color format. Use hex color code (e.g., #RRGGBB)."}), 400

    # Create the appointment
    new_appointment = Appointment(
        title=title.strip(),
        description=description.strip(),
        start_datetime=start_datetime,
        end_datetime=end_datetime,
        calendar_id=calendar.id,  # Set calendar id
        user_id=g.user_id,
        recurrence_rule=recurrence_rule.strip() if recurrence_rule else None,
        recurrence_end_date=recurrence_end_date,
        is_all_day=bool(is_all_day),  # Ensure it's a boolean
        color=color.strip() if color else None,  # Ensure it's a string or None
    )

    # Attach notes if provided
    if note_ids:
        new_appointment.notes.extend(notes)

    try:
        db.session.add(new_appointment)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred while creating the appointment: {str(e)}"}), 500

    return jsonify({
        "message": "Appointment created successfully",
        "appointment": new_appointment.to_dict()
    }), 201

# 3. Update an existing appointment
@app.route('/appointments/<int:appointment_id>', methods=['PUT'])
@require_session_key
def update_appointment(appointment_id):
    data = request.get_json() or {}
    appointment = Appointment.query.get(appointment_id)

    if not appointment or appointment.user_id != g.user_id:
        return jsonify({"error": "Appointment not found"}), 404

    title = data.get('title')
    description = data.get('description')
    start_datetime_str = data.get('start_datetime')
    end_datetime_str = data.get('end_datetime')
    recurrence_rule = data.get('recurrence_rule')  # Optional update for recurrence rule
    recurrence_end_date_str = data.get('recurrence_end_date')  # Optional update for recurrence end date
    note_ids = data.get('note_ids')  # Optional update to attached notes
    color = data.get('color')  # Optional update to color
    calendar_id = data.get('calendar_id')  # New field

    if title:
        appointment.title = title
    if description is not None:
        appointment.description = description

    if 'is_all_day' in data:
        appointment.is_all_day = bool(data['is_all_day'])

    # Retrieve the calendar: either the one provided or the default calendar for the user
    if calendar_id:
        calendar = Calendar.query.filter_by(id=calendar_id, user_id=g.user_id).first()
        if not calendar:
            return jsonify({"error": "Calendar not found or not owned by user."}), 404
    else:
        # Fetch default calendar
        calendar = Calendar.query.filter_by(user_id=g.user_id, is_default=True).first()
        if not calendar:
            return jsonify({"error": "Default calendar not found for user."}), 404

    # Update the appointment's calendar_id
    appointment.calendar_id = calendar.id

    if start_datetime_str:
        try:
            new_start = datetime.fromisoformat(start_datetime_str)
            appointment.start_datetime = new_start
        except ValueError:
            return jsonify({"error": "Invalid start_datetime format. Use ISO 8601 format."}), 400

    if end_datetime_str:
        try:
            new_end = datetime.fromisoformat(end_datetime_str)
            appointment.end_datetime = new_end
        except ValueError:
            return jsonify({"error": "Invalid end_datetime format. Use ISO 8601 format."}), 400

    # Ensure the updated times are valid
    if appointment.end_datetime <= appointment.start_datetime:
        return jsonify({"error": "end_datetime must be after start_datetime."}), 400

    if appointment.end_datetime.date() != appointment.start_datetime.date():
        return jsonify({"error": "Appointments cannot span multiple days."}), 400

    # Update recurrence rule if provided (can be set to None to remove recurrence)
    if 'recurrence_rule' in data:
        appointment.recurrence_rule = recurrence_rule

    if 'recurrence_end_date' in data:
        if recurrence_end_date_str:
            try:
                appointment.recurrence_end_date = datetime.fromisoformat(recurrence_end_date_str)
            except ValueError:
                return jsonify({"error": "Invalid recurrence_end_date format. Use ISO 8601 format."}), 400
        else:
            appointment.recurrence_end_date = None

    # Validate color to be a valid hex color code if provided
    if color is not None:
        if color and not re.match(r'^#[0-9A-Fa-f]{6}$', color):
            return jsonify({"error": "Invalid color format. Use hex color code (e.g., #RRGGBB)."}), 400
        appointment.color = color.strip() if color else None

    # Update attached notes if provided
    if note_ids is not None:
        notes = Note.query.filter(Note.id.in_(note_ids)).all()
        appointment.notes = notes

    db.session.commit()

    return jsonify({
        "message": "Appointment updated successfully",
        "appointment": appointment.to_dict()
    }), 200

# 4. Delete an appointment
@app.route('/appointments/<int:appointment_id>', methods=['DELETE'])
@require_session_key
def delete_appointment(appointment_id):
    appointment = Appointment.query.get(appointment_id)

    if not appointment or appointment.user_id != g.user_id:
        return jsonify({"error": "Appointment not found"}), 404

    db.session.delete(appointment)
    db.session.commit()

    return jsonify({"message": "Appointment deleted successfully"}), 200

@app.route('/calendars', methods=['POST'])
@require_session_key
def create_calendar():
    data = request.get_json() or {}
    name = data.get('name', "My calendar").strip()

    if not name:
        return jsonify({"error": "Calendar name is required."}), 400

    # Optionally, enforce uniqueness per user if desired
    new_calendar = Calendar(name=name, user_id=g.user_id)
    db.session.add(new_calendar)
    db.session.commit()

    return jsonify({
        "message": "Calendar created successfully",
        "calendar": new_calendar.to_dict()
    }), 201

@app.route('/calendars', methods=['GET'])
@require_session_key
def get_calendars():
    calendars = Calendar.query.filter_by(user_id=g.user_id).all()
    calendars_data = [cal.to_dict() for cal in calendars]
    return jsonify({"calendars": calendars_data}), 200

@app.route('/calendars/<int:calendar_id>', methods=['PUT'])
@require_session_key
def update_calendar(calendar_id):
    data = request.get_json() or {}
    calendar = Calendar.query.filter_by(id=calendar_id, user_id=g.user_id).first()
    if not calendar:
        return jsonify({"error": "Calendar not found"}), 404

    new_name = data.get('name', '').strip()
    if not new_name:
        return jsonify({"error": "Calendar name is required."}), 400

    calendar.name = new_name
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to update calendar: {str(e)}"}), 500

    return jsonify({
        "message": "Calendar updated successfully",
        "calendar": calendar.to_dict()
    }), 200

@app.route('/calendars/<int:calendar_id>', methods=['DELETE'])
@require_session_key
def delete_calendar(calendar_id):
    calendar = Calendar.query.filter_by(id=calendar_id, user_id=g.user_id).first()
    if not calendar:
        return jsonify({"error": "Calendar not found"}), 404

    if calendar.is_default:
        return jsonify({"error": "Default calendar cannot be deleted."}), 400

    # Optional: reassign appointments from this calendar to the user's default calendar
    default_calendar = Calendar.query.filter_by(user_id=g.user_id, is_default=True).first()
    if default_calendar:
        Appointment.query.filter_by(calendar_id=calendar.id, user_id=g.user_id).update({"calendar_id": default_calendar.id})
    
    try:
        db.session.delete(calendar)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to delete calendar: {str(e)}"}), 500

    return jsonify({"message": "Calendar deleted successfully"}), 200



# 5. Get all user notes for attaching

# Fetch all notes for the current user
@app.route('/notes-all', methods=['GET'])
@require_session_key
def get_all_notes():
    user_id = g.user_id
    notes = Note.query.filter_by(user_id=user_id).all()
    notes_data = [note.to_dict() for note in notes]
    return jsonify({"notes": notes_data}), 200

# Todos

# 1. fetch all todos for the current user
@app.route('/todos', methods=['GET'])
@require_session_key
def get_todos():
    user_id = g.user_id
    todos = Todo.query.filter_by(user_id=user_id).all()
    todos_data = [todo.to_dict() for todo in todos]
    return jsonify({"todos": todos_data}), 200

# 2. create a new todo
@app.route('/todos', methods=['POST'])
@require_session_key
def create_todo():
    user_id = g.user_id
    data = request.get_json() or {}
    current_app.logger.info(f"[create_todo] Received data: {data} for user_id: {user_id}")

    # --- Basic fields ---
    title   = (data.get('title') or "").strip()
    text    = (data.get('description') or "").strip()
    due_str = data.get('due_date')
    current_app.logger.debug(f"[create_todo] Parsed fields - title: '{title}', text: '{text}', due_date: '{due_str}'")

    # --- Attachment IDs ---
    note_id        = data.get('note_id')
    appointment_id = data.get('appointment_id')
    current_app.logger.debug(f"[create_todo] Attachments - note_id: {note_id}, appointment_id: {appointment_id}")

    # --- Validation: title & due date ---
    if not title:
        current_app.logger.warning("[create_todo] Title is missing")
        return jsonify(error="Title is required"), 400
    if len(title) > 120:
        current_app.logger.warning("[create_todo] Title exceeds 120 characters")
        return jsonify(error="Title exceeds 120 characters"), 400

    if not due_str:
        current_app.logger.warning("[create_todo] Due date is missing")
        return jsonify(error="Due date is required"), 400
    try:
        due_date = datetime.fromisoformat(due_str)
    except ValueError:
        current_app.logger.warning(f"[create_todo] Invalid due date format: {due_str}")
        return jsonify(error="Invalid due date format; use ISO 8601"), 400
    if due_date < datetime.now():
        current_app.logger.warning(f"[create_todo] Due date is in the past: {due_date}")
        return jsonify(error="Due date cannot be in the past"), 400

    # --- Attachments lookup & ownership check ---
    note        = None
    appointment = None

    if note_id is not None:
        note = Note.query.filter_by(id=note_id, user_id=user_id).first()
        if note is None:
            current_app.logger.warning(f"[create_todo] Note not found or not owned by user: note_id={note_id}, user_id={user_id}")
            return jsonify(error="Note not found or not yours"), 404
        current_app.logger.info(f"[create_todo] Linked note: {note_id}")

    if appointment_id is not None:
        appointment = Appointment.query.\
            filter_by(id=appointment_id, user_id=user_id).first()
        if appointment is None:
            current_app.logger.warning(f"[create_todo] Appointment not found or not owned by user: appointment_id={appointment_id}, user_id={user_id}")
            return jsonify(error="Appointment not found or not yours"), 404
        current_app.logger.info(f"[create_todo] Linked appointment: {appointment_id}")

    # --- Create & commit ---
    new_todo = Todo(
        user_id        = user_id,
        title          = title,
        text           = text,
        due_date       = due_date,
        completed      = False,
        note           = note,
        appointment    = appointment
    )
    current_app.logger.info(f"[create_todo] Creating Todo: {new_todo}")

    try:
        db.session.add(new_todo)
        db.session.commit()
        current_app.logger.info(f"[create_todo] Todo created successfully with id: {new_todo.id}")

        # Build the response dict manually, stringifying due_date
        todo_data = new_todo.to_dict()
        if new_todo.due_date:
            todo_data['due_date'] = new_todo.due_date.isoformat()

        current_app.logger.debug(f"[create_todo] Response data: {todo_data}")

        return jsonify(
            message="Todo created successfully!",
            todo=todo_data
        ), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"[create_todo] Error creating todo: {str(e)}", exc_info=True)
        return jsonify(error=f"Error creating todo: {str(e)}"), 500
    
@app.route('/todos/<int:todo_id>', methods=['PUT'])
@require_session_key
def update_todo(todo_id):
    import datetime as dt

    user_id = g.user_id

    # 1️⃣ Fetch and ownership check
    todo = Todo.query.get(todo_id)
    if not todo or todo.user_id != user_id:
        return jsonify(error="Todo not found"), 404

    data = request.get_json() or {}

    # 2️⃣ Simple scalar fields
    title   = data.get('title')
    text    = data.get('description')
    due_str = data.get('due_date')
    done    = data.get('completed')

    # 3️⃣ Attachment IDs
    new_note_id        = data.get('note_id')
    new_appointment_id = data.get('appointment_id')

    # — Validate & apply title
    if title is not None:
        title = title.strip()
        if not title:
            return jsonify(error="Title cannot be empty"), 400
        if len(title) > 120:
            return jsonify(error="Title exceeds 120 characters"), 400
        todo.title = title

    # — Validate & apply description
    if text is not None:
        text = text.strip()
        if len(text) > 1000:
            return jsonify(error="Description exceeds 1000 characters"), 400
        todo.text = text

    # — Validate & apply due date
    if due_str is not None:
        if due_str == "":
            todo.due_date = None
        else:
            try:
                due_date = dt.datetime.fromisoformat(due_str)
            except ValueError:
                return jsonify(error="Invalid due date format; use ISO 8601"), 400
            if due_date < dt.datetime.now():
                return jsonify(error="Due date cannot be in the past"), 400
            todo.due_date = due_date

    # — Validate & apply completed flag
    if done is not None:
        todo.completed = bool(done)

    # 4️⃣ Validate & apply note linkage
    if 'note_id' in data:
        if new_note_id is None:
            todo.note = None
        else:
            note = Note.query.filter_by(id=new_note_id, user_id=user_id).first()
            if note is None:
                return jsonify(error="Note not found or not yours"), 404
            todo.note = note

    # 5️⃣ Validate & apply appointment linkage
    if 'appointment_id' in data:
        if new_appointment_id is None:
            todo.appointment = None
        else:
            appt = Appointment.query.\
                filter_by(id=new_appointment_id, user_id=user_id).first()
            if appt is None:
                return jsonify(error="Appointment not found or not yours"), 404
            todo.appointment = appt

    # 6️⃣ Commit and respond
    try:
        db.session.commit()
        return jsonify(
            message="Todo updated successfully!",
            todo=todo.to_dict()
        ), 200
    except Exception as e:
        db.session.rollback()
        return jsonify(error=f"Error updating todo: {str(e)}"), 500

# 4. delete a todo
@app.route('/todos/<int:todo_id>', methods=['DELETE'])
@require_session_key
def delete_todo(todo_id):
    user_id = g.user_id
    todo = Todo.query.get(todo_id)
    if not todo or todo.user_id != user_id:
        return jsonify({"error": "Todo not found"}), 404

    db.session.delete(todo)
    db.session.commit()
    return jsonify({"message": "Todo deleted successfully!"}), 200
    
@app.route('/notes_fetch', methods=['GET'])
@require_session_key
def get_notes_fetch():
    user_id = g.user_id
    notes = Note.query.filter_by(user_id=user_id, group_id=None).all()
    notes_data = [note.to_dict() for note in notes]
    return jsonify({"notes": notes_data}), 200


@app.route('/appointments_fetch', methods=['GET'])
@require_session_key
def get_appointments_fetch():
    user_id = g.user_id
    appointments = Appointment.query.filter_by(user_id=user_id).all()
    appts_data = [appt.to_dict() for appt in appointments]
    return jsonify({"appointments": appts_data}), 200


# Groups   

@app.route('/group-invite', methods=['POST'])
@require_session_key
def group_invite():
    data = request.json
    username = data.get('username')
    group_id = data.get('group_id')
    
    # Corrected query using 'id' instead of 'user_id'
    invited_by_user = User.query.filter_by(id=g.user_id).first()
    if not invited_by_user:
        return jsonify({"error": "Inviting user not found"}), 404
    
    if not username or not group_id:
        return jsonify({"error": "Username and group ID are required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if user.suspended:
        return jsonify({"error": "This user is suspended from Future Notes!"}), 403

    group = Group.query.get(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404

    new_invite = Invite(
        user_id=user.id,
        group_id=group.id,
        group_name=group.name,
        invited_by=invited_by_user.id  # using id for foreign key
    )
    db.session.add(new_invite)
    db.session.commit()

    return jsonify({"message": "Invite sent successfully"}), 201

@app.route('/check-invite', methods=['GET'])
@require_session_key
def check_invites():
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    invites = Invite.query.filter_by(user_id=user.id).all()
    invites_data = []
    for invite in invites:
        inviter = User.query.get(invite.invited_by)
        invites_data.append({
            "group_id": invite.group_id,
            "group_name": invite.group_name,
            "invited_by": inviter.username if inviter else "Unknown"
        })

    return jsonify({"invites": invites_data}), 200

@app.route('/group-invite-result', methods=['POST'])
@require_session_key
def group_invite_result():
    data = request.json
    group_id = data.get('group_id')
    result = data.get('result')

    if not group_id or result not in ['accepted', 'declined']:
        return jsonify({"error": "Invalid request data"}), 400

    invite = Invite.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    if not invite:
        return jsonify({"error": "Invite not found"}), 404

    # Delete the invite
    db.session.delete(invite)
    db.session.commit()

    return jsonify({"message": "Invite processed successfully"}), 200


@app.route('/check-group')
@require_session_key
def group_info_lol():
    print("Entering group_info route")
    user_id = User.query.get(g.user_id)
    print(f"Queried user_id: {user_id}")

    if not user_id:
        print("User not found")
        return jsonify({"error": "User not found"}), 400
    
    group_membership = GroupMember.query.filter_by(user_id=user_id.id).first()
    print(f"Queried group_membership: {group_membership}")

    if not group_membership:
        print("User is not in any group")
        return jsonify({"error": "User is not in any group"}), 404

    print("User is in a group")
    return jsonify({
        "message": "User is in a group",
        "group_id": group_membership.group_id,
        "is_admin": group_membership.admin
    }), 200

@app.route('/group-info/<group_id>')
@require_session_key
def group_info(group_id):
    # Get the group
    group = Group.query.get(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404

    # Get the current user's membership (to check if they are admin)
    current_membership = GroupMember.query.filter_by(group_id=group_id, user_id=g.user_id).first()
    if not current_membership:
        return jsonify({"error": "User is not in this group"}), 403

    # Query all members of the group
    memberships = GroupMember.query.filter_by(group_id=group_id).all()
    members_list = []
    for membership in memberships:
        user = User.query.get(membership.user_id)
        # If the profile picture exists, clean it; otherwise, set it to None.
        if user.profile_picture:
            cleaned_profile_pic = user.profile_picture.replace("\\", "/")
        else:
            cleaned_profile_pic = None

        members_list.append({
            "user_id": user.id,
            "username": user.username,
            "profile_pic": cleaned_profile_pic,
            "is_admin": membership.admin
        })
        print(members_list)

    return jsonify({
        "group_name": group.name,
        "group_members": members_list,
        "current_user_admin": current_membership.admin
    }), 200
    
@app.route('/groups', methods=['POST'])
@require_session_key
def create_group():
    print("Entering create_group route")
    data = request.json
    print(f"Received data: {data}")
    name = data.get('name')
    print(f"Group name: {name}")

    if not name:
        print("Group name is required")
        return jsonify({"error": "Group name is required"}), 400

    new_group = Group(name=name)
    db.session.add(new_group)
    db.session.commit()
    print(f"Created new group: {new_group}")

    # Automatically add the creator as a member
    membership = GroupMember(user_id=g.user_id, group_id=new_group.id, admin=True)
    db.session.add(membership)
    db.session.commit()
    print(f"Added creator as member: {membership}")

    return jsonify({"message": "Group created successfully!", "group_id": new_group.id}), 201

@app.route('/groups/join', methods=['POST'])
@require_session_key
def join_group():
    print("Entering join_group route")
    data = request.json
    print(f"Received data: {data}")
    group_id = data.get('group_id')
    print(f"Group ID: {group_id}")

    group = Group.query.get(group_id)
    print(f"Queried group: {group}")
    if not group:
        print("Group not found")
        return jsonify({"error": "Group not found"}), 404

    # Check if user is already in the group
    existing_member = GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    print(f"Queried existing_member: {existing_member}")
    if existing_member:
        print("Already a member of this group")
        return jsonify({"message": "Already a member of this group"}), 200

    # Check if the group has no members
    has_members = GroupMember.query.filter_by(group_id=group_id).first()
    is_admin = not has_members  # If no members, the joining user becomes admin
    print(f"Is first member (admin): {is_admin}")

    membership = GroupMember(user_id=g.user_id, group_id=group_id, admin=is_admin)
    db.session.add(membership)
    db.session.commit()
    print(f"Joined group successfully: {membership}")

    return jsonify({"message": "Joined group successfully!"}), 200

@app.route('/groups/leave', methods=['POST'])
@require_session_key
def leave_group():
    print("Entering leave_group route")
    data = request.json
    print(f"Received data: {data}")
    group_id = data.get('group_id')
    print(f"Group ID: {group_id}")

    group = Group.query.get(group_id)
    print(f"Queried group: {group}")
    if not group:
        print("Group not found")
        return jsonify({"error": "Group not found"}), 404

    # Check if user is already in the group
    existing_member = GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    print(f"Queried existing_member: {existing_member}")
    
    if not existing_member:
        print("Not a member of this group")
        return jsonify({"message": "Not a member of this group!"}), 403

    # Delete the existing membership from the database
    db.session.delete(existing_member)
    db.session.commit()  # Commit the transaction

    print("Left group successfully: Membership deleted")
    return jsonify({"message": "Left group successfully!"}), 200

@app.route('/groups/remove-user', methods=['POST'])
@require_session_key
def remove_user_from_group():
    data = request.get_json()
    group_id = data.get("group_id")
    user_id_to_remove = data.get("user_id")

    # Verify that the current user is an admin of the group
    admin_membership = GroupMember.query.filter_by(group_id=group_id, user_id=g.user_id).first()
    if not admin_membership or not admin_membership.admin:
        return jsonify({"error": "Unauthorized: only admins can remove users."}), 403

    # Find the membership for the user to remove
    member_to_remove = GroupMember.query.filter_by(group_id=group_id, user_id=user_id_to_remove).first()
    if not member_to_remove:
        return jsonify({"error": "User not found in the group."}), 404

    db.session.delete(member_to_remove)
    db.session.commit()
    return jsonify({"message": "User removed successfully."}), 200

@app.route('/groups/delete', methods=['POST'])
@require_session_key
def delete_group():
    data = request.get_json()
    group_id = data.get("group_id")

    # Verify that the current user is an admin of the group
    admin_membership = GroupMember.query.filter_by(group_id=group_id, user_id=g.user_id).first()
    if not admin_membership or not admin_membership.admin:
        return jsonify({"error": "Unauthorized: only admins can delete the group."}), 403

    # Remove all group memberships
    GroupMember.query.filter_by(group_id=group_id).delete()
    # Remove all notes belonging to the group
    Note.query.filter_by(group_id=group_id).delete()
    # Remove the group itself
    group = Group.query.get(group_id)
    if group:
        db.session.delete(group)

    db.session.commit()
    return jsonify({"message": "Group deleted successfully."}), 200

# Group notes

@app.route('/groups/<string:group_id>/notes', methods=['GET'])
@require_session_key
def get_group_notes(group_id):
    print("Entering get_group_notes route")
    print(f"Group ID: {group_id}")

    # Ensure the user is part of the group
    membership = GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    print(f"Queried membership: {membership}")
    if not membership:
        print("Not a member of this group")
        return jsonify({"error": "Not a member of this group"}), 403

    notes = Note.query.filter_by(group_id=group_id).all()
    print(f"Queried notes: {notes}")
    sanitized_notes = [{"id": note.id, "title": note.title, "note": note.note, "tag": note.tag} for note in notes]
    print(f"Sanitized notes: {sanitized_notes}")

    return jsonify(sanitized_notes)

@app.route('/groups/<string:group_id>/notes', methods=['POST'])
@require_session_key
def add_group_note(group_id):
    print("Entering add_group_note route")
    data = request.json
    print(f"Received data: {data}")
    title = data.get('title')
    note_text = data['note']
    tag = data.get('tag')
    print(f"Title: {title}, Note: {note_text}, Tag: {tag}")

    # Ensure user is in the group
    membership = GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    print(f"Queried membership: {membership}")
    if not membership:
        print("Not a member of this group")
        return jsonify({"error": "Not a member of this group"}), 403

    new_note = Note(group_id=group_id, title=title, note=note_text, tag=tag)
    db.session.add(new_note)
    db.session.commit()
    print(f"Added new note: {new_note}")

    return jsonify({"message": "Group note added successfully!"}), 201

@app.route('/groups/<string:group_id>/notes', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_group_note(group_id):
    print("Entering update_delete_group_note route")
    print(f"Group ID: {group_id}")

    # Use filter_by to query by group_id
    note = Note.query.filter_by(group_id=group_id).first()
    print(f"Queried note: {note}")

    if not note or note.group_id != group_id:
        print("Note not found")
        return jsonify({"error": "Note not found"}), 404

    # Ensure user is part of the group
    membership = GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    print(f"Queried membership: {membership}")
    if not membership:
        print("Not a member of this group")
        return jsonify({"error": "Not a member of this group"}), 403

    if request.method == 'PUT':
        data = request.json
        print(f"Received data: {data}")
        note.title = data.get('title')
        note.note = data['note']
        note.tag = data.get('tag')
        db.session.commit()
        print("Note updated successfully")
        return jsonify({"message": "Note updated successfully!"}), 200

    elif request.method == 'DELETE':
        db.session.delete(note)
        db.session.commit()
        print("Note deleted successfully")
        return jsonify({"message": "Note deleted successfully!"}), 200

# Sharing notes

@app.route('/share-note/<int:note_id>', methods=['POST'])
@require_session_key
def share_note(note_id):
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.id == g.user_id:
        return jsonify({"error": "You cannot share a note with yourself"}), 400
    
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

# Profile

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
        delete_profile_pictures(user.username)
        handle_group_membership(user.id)
        delete_user_and_data(user)
        
        db.session.commit()
        return jsonify({"message": "Account and all related data deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    
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
    
@app.route('/update-set-startpage', methods=['POST'])
@require_session_key
def update_set_startpage():
    data = request.json
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if 'startpage' not in data:
        return jsonify({"error": "Missing startpage data"}), 400

    user.startpage = data['startpage']
    db.session.commit()
    return jsonify({"message": "Startpage updated successfully!"}), 200

@app.route("/api/set-colors", methods=["POST"])
@require_session_key
def set_colors():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400

    # Extract color values
    background = data.get("background")
    header = data.get("header")
    contrast = data.get("contrast")
    buttons = data.get("buttons")

    # Validate color format (must be hex, 7 characters, starts with '#')
    def is_valid_hex(color):
        return isinstance(color, str) and len(color) == 7 and color.startswith("#") and all(c in "0123456789abcdefABCDEF" for c in color[1:])

    if not all(map(is_valid_hex, [background, header, contrast, buttons])):
        return jsonify({"error": "One or more colors are invalid. Must be valid hex codes like #123456"}), 400

    # Check if user already has a color entry
    user_colors = UserColor.query.filter_by(user_id=g.user_id).first()
    if not user_colors:
        user_colors = UserColor(
            user_id=g.user_id,
            background_color=background,
            header_color=header,
            contrast_color=contrast,
            button_color=buttons
        )
        db.session.add(user_colors)
    else:
        user_colors.background_color = background
        user_colors.header_color = header
        user_colors.contrasting_color = contrast
        user_colors.button_color = buttons

    db.session.commit()
    return jsonify({"message": "Color configuration updated successfully."}), 200

@app.route("/api/user/colors", methods=["GET"])
@require_session_key
def get_user_colors():
    """
    Fetch the current user's color settings.
    """
    # Try to load an existing row
    uc = UserColor.query.filter_by(user_id=g.user_id).first()

    ensure_user_colors(g.user_id)

    return jsonify({
        "backgroundColor":  uc.background_color,
        "headerColor":      uc.header_color,
        "contrastingColor": uc.contrasting_color,
        "buttonColor":      uc.button_color
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
    
# Admin

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
    
@app.route('/admin/dump', methods=['POST'])
@require_session_key
def admin_dump():
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.role != "admin" or not user.database_dump_tag:
        return jsonify({"error": "Insufficient permissions"}), 403

    data = request.json or {}
    password = data.get("password")
    if not password or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Incorrect password"}), 400

    # Reflect all tables automatically
    metadata = MetaData()
    metadata.reflect(bind=db.engine)

    dump_data = {}
    # Loop through each table and fetch all rows
    for table in metadata.sorted_tables:
        stmt = select(table)
        rows = db.session.execute(stmt).all()
        dump_data[table.name] = [dict(row._mapping) for row in rows]

    # Return as downloadable JSON file, auto-converting non-serializable types
    response = make_response(
        json.dumps(dump_data, indent=4, default=lambda o: o.isoformat() if hasattr(o, 'isoformat') else str(o))
    )
    response.headers["Content-Disposition"] = "attachment; filename=database_dump.json"
    response.headers["Content-Type"] = "application/json"
    return response

@app.route('/create_backup', methods=['POST'])
@require_session_key
@require_admin
def create_backup():
    """
    Create a timestamped copy of the live database file in the backups directory.
    """
    # Path to the live database configured in Flask app
    db_path = current_app.config.get('SQLALCHEMY_DATABASE_URI')
    # Assuming SQLite: URI like 'sqlite:////absolute/path/to/db.sqlite'
    if not db_path.startswith('sqlite:///'):
        return jsonify({'error': 'Backup creation only implemented for SQLite databases.'}), 400

    # Extract local path
    # strip prefix 'sqlite:///'
    local_path = "/home/Bosbes/mysite/python_31/pythonanywhere/instance/data.db"
    if not os.path.exists(local_path):
        return jsonify({'error': 'Live database file not found'}), 404

    # Create timestamped filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"backup_{timestamp}.db"
    dest_path = os.path.join(BACKUP_DIR, filename)

    try:
        # Copy the database file
        shutil.copy(local_path, dest_path)
    except Exception as e:
        current_app.logger.error(f"Backup failed: {e}")
        return jsonify({'error': 'Backup creation failed'}), 500

    return jsonify({'message': 'Backup created', 'file': filename}), 201

@app.route('/list', methods=['GET'])
@require_session_key
@require_admin
def list_backups():
    """
    List available backup files in the backups directory.
    """
    files = sorted(os.listdir(BACKUP_DIR))
    return jsonify({'backups': files}), 200

@app.route('/download/<filename>', methods=['GET'])
@require_session_key
@require_admin
def download_backup(filename):
    """
    Send a specific backup file to the client for download.
    """
    from flask import send_from_directory

    if filename not in os.listdir(BACKUP_DIR):
        return jsonify({'error': 'Backup file not found'}), 404

    return send_from_directory(BACKUP_DIR, filename, as_attachment=True)

@app.route('/admin/ban', methods=['POST'])
@require_session_key
def toggle_ban_user():
    data = request.json
    user_id = data.get("user_id")

    # Verify that the requester has admin privileges
    admin_user = User.query.get(g.user_id)
    if not admin_user or admin_user.role != "admin":
        return jsonify({"error": "Unauthorized: only admins can toggle user ban status."}), 403

    # Find the user to toggle ban status
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Toggle the user's suspended status
    user.suspended = not user.suspended
    db.session.commit()

    status = "banned" if user.suspended else "unbanned"
    return jsonify({"message": f"User {status} successfully."}), 200

@app.route('/admin/user-status', methods=['GET'])
@require_session_key
def user_status():
    user = User.query.get(g.user_id)
    if not user or user.role != "admin":
        return jsonify({"error": "Unauthorized: only admins can access user status."}), 403

    users = User.query.with_entities(
        User.id, User.username, User.suspended, User.role
    ).all()

    user_status_data = [
        {"id": u.id, "username": u.username, "suspended": u.suspended, "role": u.role}
        for u in users
    ]

    return jsonify({"users": user_status_data}), 200

@app.route('/admin/update', methods=['POST'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def update_code():
    thread = threading.Thread(target=run_update_script)
    thread.start()

    return jsonify({"status": "Update initiated"})

@app.route('/admin/scan-updates', methods=['GET'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def scan_updates():
    try:
        repo = get_repo(REPO_PATH)
        # Fetch only origin/master (or origin/main)
        remote = repo.remote("origin")
        remote.fetch()

        # Determine default branch name
        default_branch = repo.remotes.origin.refs.master if "master" in repo.remotes.origin.refs else repo.remotes.origin.refs.main
        local = repo.heads[default_branch.remote_head]
        remote_ref = default_branch

        # Count how many commits local is behind remote
        commits_behind = sum(1 for _ in repo.iter_commits(f"{local.commit.hexsha}..{remote_ref.commit.hexsha}"))
        up_to_date = (commits_behind == 0)

        return jsonify({
            "update_available": not up_to_date,
            "commits_behind": commits_behind,
            "message": ("Already up-to-date" if up_to_date else f"{commits_behind} commit(s) behind")
        })

    except (GitCommandError, FileNotFoundError) as e:
        app.logger.error("Error in scan_updates: %s", str(e))
        return jsonify({"error": "Failed to scan for updates", "details": str(e)}), 500


@app.route('/admin/scan-dev-vs-master', methods=['GET'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def scan_dev_vs_master():
    try:
        repo = get_repo(REPO_PATH)
        remote = repo.remote("origin")
        remote.fetch("dev")
        remote.fetch("master")

        # Count commits where origin/dev is ahead of origin/master
        dev_ref = repo.remotes.origin.refs.dev
        master_ref = repo.remotes.origin.refs.master if "master" in repo.remotes.origin.refs else repo.remotes.origin.refs.main

        commits_ahead = sum(1 for _ in repo.iter_commits(f"{master_ref.commit.hexsha}..{dev_ref.commit.hexsha}"))
        ahead = (commits_ahead > 0)

        return jsonify({
            "dev_ahead_of_master": ahead,
            "commits_ahead": commits_ahead,
            "message": ("Dev branch is not ahead of master"
                        if not ahead
                        else f"Dev branch is ahead by {commits_ahead} commit(s)")
        })

    except (GitCommandError, IndexError) as e:
        app.logger.error("Error in scan_dev_vs_master: %s", str(e))
        return jsonify({"error": "Failed to scan dev vs master", "details": str(e)}), 500


@app.route('/admin/merge-dev-into-master', methods=['POST'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def merge_dev_into_master():
    try:
        repo = get_repo(REPO_PATH)
        # Ensure origin info is up‑to‑date
        origin = repo.remote("origin")
        origin.fetch()

        # Checkout master (or main)
        target_branch = "master" if "master" in repo.heads else "main"
        repo.git.checkout(target_branch)
        # Merge origin/dev
        merge_index = repo.git.merge("origin/dev", m="Auto-merged dev into master")

        return jsonify({
            "status": "Merge completed successfully",
            "merge_output": merge_index
        })

    except GitCommandError as e:
        app.logger.error("Merge failed: %s", e.stderr)
        return jsonify({"error": "Merge failed", "details": e.stderr}), 500
    except Exception as e:
        app.logger.error("Unexpected error: %s", str(e))
        return jsonify({"error": "Unexpected failure", "details": str(e)}), 500


@app.route('/admin/database', methods=['GET', 'POST', 'PUT', 'DELETE'])
@require_session_key
def manage_database():
    # Authorization check
    user = User.query.get(g.user_id)
    if not user or user.role != "admin":
        return jsonify({"error": "Unauthorized: only admins can manage the database."}), 403

    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    # ------------------------
    # GET: Fetch schema or table data
    # ------------------------
    if request.method == 'GET':
        table = request.args.get('table')
        column = request.args.get('column')

        if not table:
            # Return schema information
            try:
                tables = {t: [col['name'] for col in inspector.get_columns(t)] for t in inspector.get_table_names()}
                return jsonify({"tables": tables}), 200
            except Exception as e:
                return jsonify({"error": f"Failed to fetch database schema: {str(e)}"}), 500
        else:
            try:
                query = text(f"SELECT {column} FROM {table}") if column else text(f"SELECT * FROM {table}")

                # ...
                with db.engine.connect() as connection:
                    result = connection.execute(query)
                    rows = [dict(row) for row in result.mappings().all()]

                return jsonify({"data": rows}), 200

            except Exception as e:
                return jsonify({"error": f"Failed to fetch data from table '{table}': {str(e)}"}), 500

    # ------------------------
    # POST, PUT, DELETE: Require JSON payload
    # ------------------------
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    data_operation = data.get('data_operation')

    # ------------------------
    # Data Operations: Insert, Update, Delete rows
    # ------------------------
    if data_operation:
        table_name = data.get('table_name')
        if not table_name:
            return jsonify({"error": "Table name is required for data operations"}), 400

        try:
            with db.engine.connect() as connection:
                if request.method == 'POST' and data_operation == 'insert':
                    row_data = data.get('row')
                    if not row_data or not isinstance(row_data, dict):
                        return jsonify({"error": "Row data must be provided as a dictionary"}), 400

                    # Insert row
                    columns = ', '.join(row_data.keys())
                    placeholders = ', '.join([f":{key}" for key in row_data.keys()])
                    stmt = text(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})")
                    
                    connection.execute(stmt, row_data)
                    connection.commit()
                    return jsonify({"message": f"Row inserted successfully into '{table_name}'"}), 201

                elif request.method == 'PUT' and data_operation == 'update':
                    row_data = data.get('row')
                    row_id = data.get('row_id')
                    if not row_data or row_id is None:
                        return jsonify({"error": "Row id and row data are required for update"}), 400

                    # Update row
                    set_clause = ', '.join([f"{k} = :{k}" for k in row_data.keys()])
                    stmt = text(f"UPDATE {table_name} SET {set_clause} WHERE id = :id")

                    connection.execute(stmt, {**row_data, "id": row_id})
                    connection.commit()
                    return jsonify({"message": f"Row with id {row_id} updated in '{table_name}'"}), 200

                elif request.method == 'DELETE' and data_operation == 'delete':
                    row_id = data.get('row_id')
                    if row_id is None:
                        return jsonify({"error": "Row id is required for deletion"}), 400

                    # Delete row
                    stmt = text(f"DELETE FROM {table_name} WHERE id = :id")
                    connection.execute(stmt, {"id": row_id})
                    connection.commit()
                    return jsonify({"message": f"Row with id {row_id} deleted from '{table_name}'"}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to modify data: {str(e)}"}), 500

    # ------------------------
    # Schema Operations: Creating, Modifying, Dropping Tables or Columns
    # ------------------------
    try:
        with db.engine.connect() as connection:
            if request.method == 'POST':
                # Add a new table
                table_name = data.get('table_name')
                columns = data.get('columns')  # List of column definitions
                if not table_name or not columns:
                    return jsonify({"error": "Table name and columns are required"}), 400

                column_definitions = ", ".join([f"{col['name']} {col['type']}" for col in columns])
                stmt = text(f"CREATE TABLE {table_name} ({column_definitions})")
                connection.execute(stmt)
                connection.commit()
                return jsonify({"message": f"Table '{table_name}' created successfully"}), 201

            elif request.method == 'PUT':
                # Modify a table (add/drop columns)
                table_name = data.get('table_name')
                action = data.get('action')  # 'add' or 'drop'
                column = data.get('column')  # Column definition for 'add', column name for 'drop'

                if not table_name or not action or not column:
                    return jsonify({"error": "Table name, action, and column are required"}), 400

                if action == 'add':
                    stmt = text(f"ALTER TABLE {table_name} ADD COLUMN {column['name']} {column['type']}")
                elif action == 'drop':
                    stmt = text(f"ALTER TABLE {table_name} DROP COLUMN {column}")
                else:
                    return jsonify({"error": "Invalid action. Use 'add' or 'drop'"}), 400

                connection.execute(stmt)
                connection.commit()
                return jsonify({"message": f"Column '{column}' {('added to' if action == 'add' else 'dropped from')} table '{table_name}'"}), 200

            elif request.method == 'DELETE':
                # Drop a table
                table_name = data.get('table_name')
                if not table_name:
                    return jsonify({"error": "Table name is required"}), 400

                stmt = text(f"DROP TABLE {table_name}")
                connection.execute(stmt)
                connection.commit()
                return jsonify({"message": f"Table '{table_name}' dropped successfully"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to modify schema: {str(e)}"}), 500

    return jsonify({"error": "Invalid request"}), 400

@app.route('/admin/login-as-user', methods=['POST'])
@require_session_key
def login_as_user():
    admin_user = User.query.get(g.user_id)
    if not admin_user or admin_user.role != "admin":
        return jsonify({"error": "Unauthorized: only admins can log in as another user."}), 403

    data = request.json
    target_user_id = data.get("user_id")
    if not target_user_id:
        return jsonify({"error": "User ID is required"}), 400

    target_user = User.query.get(target_user_id)
    if not target_user:
        return jsonify({"error": "Target user not found"}), 404

    if target_user.suspended:
        return jsonify({"error": "Cannot log in as a suspended user"}), 403

    # Generate a session key for the target user
    key = generate_session_key(target_user.id)

    return jsonify({
        "message": f"{target_user.username}",
        "session_key": key,
        "user_id": target_user.id,
        "startpage": target_user.startpage,
        "lasting_key": target_user.lasting_key if target_user.lasting_key else ""
    }), 200

@app.route('/api/source-tracking', methods=['GET'])
@require_session_key
def source_tracking():
    # Use g.user_id to retrieve the current user
    user = User.query.get(g.user_id)
    if not user or user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    # Fetch all UTM tracking records
    records = UTMTracking.query.all()
    result = [{
        'id': record.id,
        'utm_source': record.utm_source,
        'utm_medium': record.utm_medium,
        'utm_campaign': record.utm_campaign,
        'ip': record.ip,
        'timestamp': record.timestamp.isoformat()
    } for record in records]
    return jsonify(result)

@app.route('/api/user/<int:user_id>')
def get_username(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": user.username}), 200

# Authentication

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user_ip = request.remote_addr  # Get the user's IP address

    # Check if the IP address is linked to a banned user
    banned_ip = IpAddres.query.join(User).filter(IpAddres.ip == user_ip, User.suspended.is_(True)).first()
    if banned_ip:
        return jsonify({"error": "Cannot sign up from this IP address. It is linked to a banned account."}), 403

    try:
        # Create the user and automatically generate a lasting key for "remember me"
        user = User(username=data['username'], password=hashed_password)
        user.lasting_key = secrets.token_hex(32)  # Always set a lasting key
        db.session.add(user)
        db.session.commit()

        # Add the IP address to the IpAddres table
        ip_entry = IpAddres(user_id=user.id, ip=user_ip)
        db.session.add(ip_entry)
        db.session.commit()

        # Generate a session key for immediate login
        key = generate_session_key(user.id)

        create_default_calendar(user.id)

        ensure_user_colors(user.id)
        
        return jsonify({
            "message": "User created and logged in successfully!",
            "session_key": key,
            "user_id": user.id,
            "lasting_key": user.lasting_key
        }), 201

    except Exception as e:
        return jsonify({"error": "Username already exists"}), 400


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid request data"}), 400

        # helper to wrap JSON + Set‑Cookie
        def success(payload, status=200):
            resp = make_response(jsonify(payload), status)
            resp.set_cookie(
                "session_key",
                payload["session_key"],
                httponly=True,
                samesite="Lax",
                # secure=True    # enable in production
            )
            return resp

        # 1) Auto‑login via lasting_key
        lasting_key = data.get('lasting_key')
        if lasting_key:
            user = User.query.filter_by(lasting_key=lasting_key).first()
            if user:
                if user.suspended:
                    return jsonify({"error": "Account is suspended"}), 403

                key = generate_session_key(user.id)

                # Add or verify the IP address
                user_ip = request.remote_addr
                ip_entry = IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first()
                if not ip_entry:
                    ip_entry = IpAddres(user_id=user.id, ip=user_ip)
                    db.session.add(ip_entry)
                    db.session.commit()

                return success({
                    "message":     "Login successful!",
                    "session_key": key,
                    "user_id":     user.id,
                    "lasting_key": user.lasting_key,
                    "startpage":   user.startpage
                })

            return jsonify({"error": "Invalid lasting key"}), 400

        # 2) Username/password
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return jsonify({"error": "Invalid credentials"}), 400

        if user.suspended:
            return jsonify({"error": "Account is suspended"}), 403

        # Generate a new session key for this login
        key = generate_session_key(user.id)

        # Add or verify the IP address
        user_ip = request.remote_addr
        ip_entry = IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first()
        if not ip_entry:
            ip_entry = IpAddres(user_id=user.id, ip=user_ip)
            db.session.add(ip_entry)
            db.session.commit()

        # Build standard payload
        payload = {
            "message":     "Login successful!",
            "session_key": key,
            "user_id":     user.id,
            "startpage":   user.startpage
        }

        # 3) If the user wants to stay logged in, include lasting_key
        if data.get('keep_login'):
            if not user.lasting_key:
                user.lasting_key = secrets.token_hex(32)
                db.session.commit()
            payload["lasting_key"] = user.lasting_key

        return success(payload)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

# Personal notes

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
    
#---------------------------------Mutations--------------------------------
    
@app.route('/mutations', methods=['GET'])
@require_session_key
def list_transactions():
    user = User.query.get(g.user_id)
    if user.role != "admin":
        return jsonify({"error": "Insufficient permissions"}), 400
    rows = (
        db.session.query(
            MutationLog.transaction_id,
            db.func.count(MutationLog.id).label('count'),
            db.func.min(MutationLog.timestamp).label('timestamp')
        )
        .group_by(MutationLog.transaction_id)
        .all()
    )
    data = [
        {
            "txid": tx,
            "count": cnt,
            "timestamp": ts.isoformat()
        }
        for tx, cnt, ts in rows
    ]
    return jsonify(data)

@app.route('/mutations/<txid>/rollback', methods=['POST'])
@require_session_key
def rollback_tx(txid):
    user = User.query.get(g.user_id)
    if user.role != "admin":
        return jsonify({"error": "Insufficient permissions"}), 400
    try:
        rollback_transaction(txid)
        return jsonify({"status": "ok", "message": f"Rolled back {txid}"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    
@app.route('/logs', methods=['GET'])
@require_session_key
def list_logs():
    user = User.query.get(g.user_id)
    if user.role != "admin":
        return jsonify({"error": "Insufficient permissions"}), 400
    
    # return all logs, newest first
    logs = (MutationLog.query
               .order_by(MutationLog.timestamp.desc())
               .all())
    data = [{
        "id": log.id,
        "txid": log.transaction_id,
        "table": log.table_name,
        "column": log.column_name,
        "old": log.old_value,
        "new": log.new_value,
        "timestamp": log.timestamp.isoformat()
    } for log in logs]
    return jsonify(data)

    
#---------------------------------Battleship routes--------------------------------

# --- Create Game ---
@app.route('/create', methods=['POST'])
def create_game():
    data = request.json
    player_name = data.get('playerName')
    play_bot = data.get('playAgainstBot', False)
    if not player_name:
        return jsonify({"error": "Ik mis de spelersnaam!"}), 400
    
    if player_name == "Bot":
        return jsonify({"error": "Die naam mag je niet kiezen!"}), 400

    game_code = generate_game_code()
    game = {
        "players": {
            "player1": {
                "name": player_name,
                "ships": None,
                "hits": [],
                "misses": [],
                "incoming_misses": []
            },
            "player2": None  # To be filled either by join or by bot creation.
        },
        "status": "waiting",  # waiting -> placing -> battle -> gameover
        "turn": None,
        "winner": None
    }

    if play_bot:
        # Create bot player with pre-generated random ship placements.
        bot_ships = generate_bot_ships()
        game["players"]["player2"] = {
            "name": "Bot",
            "ships": bot_ships,
            "hits": [],
            "misses": [],
            "incoming_misses": []
        }
        # With a bot, both players are present from the start.
        game["status"] = "placing"
    games[game_code] = game
    return jsonify({"gameCode": game_code})

# --- Join Game ---
@app.route('/join', methods=['POST'])
def join_game():
    data = request.json
    player_name = data.get('playerName')
    game_code = data.get('gameCode')
    if not player_name or not game_code:
        return jsonify({"error": "Missing player name or game code"}), 400
    
    if player_name == "Bot":
        return jsonify({"error": "You cannot choose that name!"}), 400

    # Ensure the game code letters are uppercase.
    game_code = game_code.upper()

    if game_code not in games:
        return jsonify({"error": "Invalid game code"}), 400

    game = games[game_code]
    if game["players"]["player2"] is not None:
        # If playing against a bot, joining is not allowed.
        if game["players"]["player2"]["name"] == "Bot":
            return jsonify({"error": "Cannot join a bot game"}), 400
        return jsonify({"error": "Game already has 2 players"}), 400

    game["players"]["player2"] = {
        "name": player_name,
        "ships": None,
        "hits": [],
        "misses": [],
        "incoming_misses": []
    }
    game["status"] = "placing"
    return jsonify({"message": "Joined game", "gameCode": game_code})

# --- Place Ships ---
@app.route('/place_ships', methods=['POST'])
def place_ships():
    data = request.json
    game_code = data.get("gameCode")
    player = data.get("player")  # Expected: "player1" or "player2"
    ships = data.get("ships")    # List of ship objects with positions
    if not game_code or not player or ships is None:
        return jsonify({"error": "Missing data"}), 400
    if game_code not in games:
        return jsonify({"error": "Invalid game code"}), 400

    # Ensure each ship has a "sunk" flag.
    for ship in ships:
        if "sunk" not in ship:
            ship["sunk"] = False

    game = games[game_code]
    if player not in game["players"]:
        return jsonify({"error": "Invalid player"}), 400

    game["players"][player]["ships"] = ships

    # Check if both players have placed their ships.
    p1_ships = game["players"]["player1"]["ships"]
    p2_ships = game["players"]["player2"]["ships"] if game["players"]["player2"] else None

    if p1_ships and p2_ships:
        game["status"] = "battle"
        # Randomly choose who starts.
        game["turn"] = "player1" if random.random() < 0.5 else "player2"
        # If the bot gets the first turn, have it move.
        if game["turn"] == "player2" and game["players"]["player2"]["name"] == "Bot":
            time.sleep(0.5)
            bot_move(game_code)
    return jsonify({"message": "Ships placed", "status": game["status"]})

# --- Fire (Make a Move) ---
@app.route('/fire', methods=['POST'])
def fire():
    data = request.json
    game_code = data.get("gameCode")
    player = data.get("player")  # "player1" or "player2"
    x = data.get("x")
    y = data.get("y")

    if not game_code or not player or x is None or y is None:
        return jsonify({"error": "Missing data"}), 400
    if game_code not in games:
        return jsonify({"error": "Invalid game code"}), 400

    game = games[game_code]
    if game["status"] != "battle":
        return jsonify({"error": "Game is niet in gevechtsfase!"}), 400

    if game["turn"] != player:
        return jsonify({"error": "Niet jouw beurt!"}), 400

    result = process_fire(game, player, x, y)

    # Return the result immediately
    response = jsonify(result)

    # If it's the bot's turn, execute bot_move in a separate thread
    if (game["status"] == "battle" and game["turn"] == "player2" and
            game["players"]["player2"]["name"] == "Bot"):
        bot_move(game_code)

    return response

# --- Helper route to make the first user xp record ---
@app.route('/first-xp-record', methods=['POST'])
@require_session_key
def first_user_record():
    try:
        xp_entry = PlayerXp(user_id=g.user_id, xp=0)
        db.session.add(xp_entry)
        db.session.commit()
        seed_trophies()
    except IntegrityError:
        db.session.rollback()
        xp_entry = PlayerXp.query.filter_by(user_id=g.user_id).first()

    return jsonify({"message":"Succesfully made a new record"}), 200

# --- Get Game State (for polling) ---
@app.route('/game_state', methods=['GET'])
def game_state():
    game_code = request.args.get("gameCode")
    if not game_code or game_code not in games:
        return jsonify({"error": "Invalid game code"}), 400

    game = games[game_code]

    # If it's the bot's turn, let it move ONCE immediately (no delays)
    if (game["status"] == "battle"
        and game["turn"]  == "player2"
        and game["players"]["player2"]["name"] == "Bot"):
        
        # This updates game["status"], game["turn"], hits/misses, etc.
        bot_move(game_code, skip_delays=True)

    # Now return the fresh state
    response = {
        "players":       game["players"],
        "status":        game["status"],
        "turn":          game["turn"],
        "winner":        game.get("winner"),
        "opponentJoined": game["players"].get("player2") is not None
    }
    return jsonify(response)

# --- Stop Game ---
@app.route('/leave-game', methods=['POST'])
def stop():
    data = request.json
    game_code = data.get("gameCode")
    player = data.get("player")

    if not game_code or game_code not in games:
        return jsonify({"error": "Invalid game code"}), 400

    game = games[game_code]
    if game["status"] == "gameover":
        return jsonify({"error": "Game is already over"}), 400

    opponent = "player1" if player == "player2" else "player2"
    if game["players"][opponent] is None:
        # If the opponent has not joined, cancel the game and remove the game code
        del games[game_code]
        return jsonify({"message": "Game canceled as the opponent has not joined."}), 200

    game["status"] = "gameover"
    game["winner"] = opponent

    return jsonify({"message": f"Player {player} has left the game. Player {opponent} wins."}), 200

# --- Game Result ---   
@app.route('/game_result', methods=['GET'])
def game_result():
    game_code = request.args.get("gameCode")
    player = request.args.get("player")
    if not game_code or not player:
        return jsonify({"error": "Missing game code or player identifier"}), 400

    if game_code not in games:
        return jsonify({"error": "Invalid game code"}), 400

    game = games[game_code]
    
    # Only reveal results after the game is over.
    if game["status"] != "gameover":
        return jsonify({"error": "Game is not over yet"}), 400

    # Validate the requesting player exists.
    if player not in game["players"] or game["players"][player] is None:
        return jsonify({"error": "Invalid player"}), 400

    # Determine the opponent.
    opponent = "player1" if player == "player2" else "player2"
    if game["players"][opponent] is None:
        return jsonify({"error": "Opponent has not joined"}), 400

    enemy_ships = game["players"][opponent].get("ships", [])
    my_misses = game["players"][player].get("misses", [])
    my_hits = game["players"][player].get("hits", [])
    
    return jsonify({
        "enemyShips": enemy_ships,
        "myMisses": my_misses,
        "myHits": my_hits,
        "winner": game["winner"]
    })

@app.route('/game-stats', methods=['POST'])
@require_session_key
def game_stats():
    # Parse the JSON payload
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Expected fields: result ("win" or "lose"), bot_game (boolean), accuracy (0 to 1),
    # and sunk_ships (number of enemy ships sunk)
    try:
        result = data["result"]
        bot_game = data.get("bot_game", False)
        accuracy = float(data.get("accuracy", 0))
        sunk_ships = int(data.get("sunk_ships", 0))
    except (KeyError, ValueError) as e:
        return jsonify({"error": "Invalid data format"}), 400

    # Retrieve the player's XP record, or create one if it doesn't exist.
    xp_entry = PlayerXp.query.filter_by(user_id=g.user_id).first()
    if not xp_entry:
        try:
            xp_entry = PlayerXp(user_id=g.user_id, xp=0)
            db.session.add(xp_entry)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            xp_entry = PlayerXp.query.filter_by(user_id=g.user_id).first()

    current_xp = xp_entry.xp

    # Calculate XP gain using the enhanced logic.
    xp_gain = calculate_xp_gain(current_xp, result, accuracy, sunk_ships)
    
    # If played against a bot, reduce the XP gain.
    if bot_game:
        xp_gain *= 0.8

    # Update the player's XP.
    xp_entry.xp += xp_gain
    db.session.commit()

    return jsonify({
        "message": "XP updated",
        "xp_gained": xp_gain,
        "total_xp": xp_entry.xp
    }), 200

@app.route('/game-stats-return', methods=['GET'])
@require_session_key
def game_stats_return():
    xp_entry = PlayerXp.query.filter_by(user_id=g.user_id).first()
    xp = xp_entry.xp if xp_entry else 0
    level, progress, next_level_xp = calculate_level(xp)
    seed_trophies()
    trophies = get_unlocked_trophies(level)
    trophies_data = [{
        "level": trophy.level,
        "name": trophy.name,
        "icon": trophy.icon
    } for trophy in trophies]

    return jsonify({
        "xp": xp,
        "level": level,
        "progress": progress,
        "next_level_xp": next_level_xp,
        "trophies": trophies_data
    })


@app.route('/leaderboard-info', methods=['GET'])
def leaderboard_info():
    try:
        rows = (
            db.session.query(
                User.username,
                PlayerXp.xp,
                User.profile_picture
            )
            .join(User, User.id == PlayerXp.user_id)
            .order_by(desc(PlayerXp.xp))
            .limit(10)
            .all()
        )

        leaderboard = [
            {
                "username": username,
                "xp": xp,
                "profile_picture": pic
            }
            for username, xp, pic in rows
        ]

        return jsonify(leaderboard)

    except Exception:
        current_app.logger.exception("Error in /leaderboard-info")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/leaderboard-info-players', methods=['GET', 'POST'])
def leaderboard_info_players():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided!"}), 400

    username = data.get("username")
    if not username:
        return jsonify({"error": "Username is required!"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found!"}), 404

    xp_entry = PlayerXp.query.filter_by(user_id=user.id).first()
    if not xp_entry:
        return jsonify({"error": "XP entry not found for user!"}), 404

    xp = xp_entry.xp
    level, _, _ = calculate_level(xp)
    trophies = get_unlocked_trophies(level)
    trophies_data = [{"name": trophy.name, "icon": trophy.icon} for trophy in trophies]

    return jsonify({
        "xp": xp,
        "level": level,
        "trophies": trophies_data
    }), 200

# --- Spectate State ---
@app.route('/spectate_state', methods=['GET'])
def spectate_state():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 403
    game_code = request.args.get("gameCode")
    if not game_code or game_code not in games:
        return jsonify({"error": "Invalid game code"}), 400

    game = games[game_code]
    filtered_players = {}
    for player, pdata in game["players"].items():
        if pdata is None:
            filtered_players[player] = None
        else:
            # Only show sunk ships.
            sunk_ships = []
            if pdata.get("ships"):
                for ship in pdata["ships"]:
                    if ship.get("sunk"):
                        sunk_ships.append(ship)
            filtered_players[player] = {
                "name": pdata["name"],
                "hits": pdata.get("hits", []),
                "misses": pdata.get("misses", []),
                "sunk_ships": sunk_ships
            }

    winner_name = None
    if game["winner"]:
        winning_player = game["players"].get(game["winner"])
        if winning_player:
            winner_name = winning_player["name"]

    response = {
        "players": filtered_players,
        "status": game["status"],
        "turn": game["turn"],
        "winner": winner_name,
        "opponentJoined": game["players"]["player2"] is not None
    }
    return jsonify(response)

# --- List Games ---
@app.route('/list_games', methods=['GET'])
def list_games():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 403
    ongoing_games = []
    for game_code, game in games.items():
        if game.get("status") != "gameover":
            ongoing_games.append({
                "gameCode": game_code,
                "status": game.get("status"),
                "opponentJoined": game["players"]["player2"] is not None
            })
    return jsonify({"games": ongoing_games})

# --- Validate Pin ---
@app.route("/validate_pin", methods=["POST"])
def validate_pin():
    data = request.get_json()
    entered_pin = data.get("pin")

    if entered_pin == CORRECT_PIN:
        session["authenticated"] = True
        return jsonify({"success": True})
    else:
        return jsonify({"success": False}), 401

# ---------------------------------Run the app--------------------------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
