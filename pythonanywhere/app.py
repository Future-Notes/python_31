# ------------------------------Imports--------------------------------
from operator import is_not
from flask import Flask, request, jsonify, g, render_template, make_response, session, send_from_directory, current_app, abort, redirect, Blueprint
from flask.json.provider import DefaultJSONProvider
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, desc, event, text, MetaData, select
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.orm.attributes import get_history
from sqlalchemy.pool import NullPool
from sqlalchemy import JSON, create_engine, inspect
from pywebpush import webpush, WebPushException
from flask_bcrypt import Bcrypt                                 
from flask_cors import CORS                                    
from datetime import datetime, timedelta
import secrets
from werkzeug.utils import secure_filename
from git import Repo, GitCommandError
import os
import json
import uuid
import random
import string
import time
from datetime import timezone
import glob
import threading
from update_DB import update_tables
from math import floor
import re
import traceback
import subprocess
import shutil
import hashlib
import smtplib
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader, select_autoescape
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.mime.image import MIMEImage
import mimetypes
import urllib
from PIL import Image
import bleach
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import requests


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
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': NullPool
}
app.config['VAPID_PRIVATE_KEY'] = '9AJRZillMA-nZfyUdM2SrldUrXp8eGEDteL_yvbJGjk'
app.config['VAPID_PUBLIC_KEY'] = 'BGcLDjMs3BA--QdukrxV24URwXLHYyptr6TZLR-j79YUfDDlN8nohDeErLxX08i86khPPCz153Ygc3DrC7w1ZJk'
app.config['VAPID_CLAIMS'] = {
    'sub': 'https://bosbes.eu.pythonanywhere.com'
}
# Jinja setup (point at your templates/)
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_PATH),
    autoescape=select_autoescape(['html', 'xml'])
)
app.config['LOGO_URL'] = 'https://bosbes.eu.pythonanywhere.com/static/android-chrome-512x512.png'
app.config['GMAIL_USER'] = 'noreplyfuturenotes@gmail.com'
app.config['GMAIL_APP_PASSWORD'] = 'iklaaawvfggxxoep'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Disables HTTPS check
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
DB_PATH = os.path.join(os.getcwd(), 'instance', 'data.db')
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

class AppSecret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(256), nullable=False)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=True)
    lasting_key = db.Column(db.String(200), nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True)
    allows_sharing = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), nullable=False, default="user")
    suspended = db.Column(db.Boolean, default=False, nullable=False)
    startpage = db.Column(db.String(20), nullable=False, default="/index")
    database_dump_tag = db.Column(db.Boolean, default=False, nullable=False)
    
    # existing relationships
    colors = db.relationship(
        "UserColor",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
    )
    notifications = db.relationship('Notification', back_populates='user')
    push_subscriptions = db.relationship('PushSubscription', back_populates='user', lazy='dynamic')
    
    # new relationship to FingerPrint
    fingerprints = db.relationship(
        "FingerPrint",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )

    __table_args__ = (
        CheckConstraint(role.in_(["user", "admin"]), name="check_role_valid"),
    )

# models.py
class SignupSession(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(80), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    hashed_password = db.Column(db.String(120), nullable=True)
    user_ip = db.Column(db.String(45), nullable=True)
    email = db.Column(db.String(120))
    verification_code = db.Column(db.String(6))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class PushSubscription(db.Model):
    __tablename__ = 'push_subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    endpoint = db.Column(db.Text, nullable=False)
    keys = db.Column(JSON, nullable=False)
    device_id = db.Column(db.String(64), nullable=False, index=True)  # New device ID field
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship('User', back_populates='push_subscriptions')
    
    # Add unique constraint per user-device
    __table_args__ = (
        db.UniqueConstraint('user_id', 'device_id', name='uix_user_device'),
    )


class FingerPrint(db.Model):
    __tablename__ = 'fingerprint'
    # surrogate PK
    id = db.Column(db.Integer, primary_key=True)
    
    # the browser‑generated visitor ID (e.g. from FingerprintJS)
    visitor_id = db.Column(db.String(128), unique=True, nullable=False)
    
    # metadata for security/tracking
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_ip    = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    
    # link back to the user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)
    user    = db.relationship("User", back_populates="fingerprints")

    def __repr__(self):
        return f'<FingerPrint visitor_id={self.visitor_id!r} user_id={self.user_id}>'

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
    calendar_id = db.Column(db.Integer, db.ForeignKey('calendar.id'), nullable=False)

    recurrence_rule = db.Column(db.String(255), nullable=True)
    recurrence_end_date = db.Column(db.DateTime, nullable=True)
    is_all_day = db.Column(db.Boolean, nullable=False, default=False)
    color = db.Column(db.String(7), nullable=True)
    google_event_id = db.Column(db.String(255))  # Add this field
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
            "notes": [note.to_dict() for note in self.notes],
            "google_event_id": self.google_event_id,
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

class GoogleCalendarCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    access_token = db.Column(db.String(255), nullable=False)
    refresh_token = db.Column(db.String(255), nullable=False)
    token_expiry = db.Column(db.DateTime, nullable=False)
    calendar_id = db.Column(db.String(255))  # Default Google Calendar ID
    last_sync = db.Column(db.DateTime)
    sync_token = db.Column(db.String(500))  # For incremental syncs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CalendarSync(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    local_calendar_id = db.Column(db.Integer, db.ForeignKey('calendar.id'))
    google_calendar_id = db.Column(db.String(255))  # Specific Google Calendar ID
    sync_enabled = db.Column(db.Boolean, default=True)
    last_synced = db.Column(db.DateTime)

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
    
class Draft(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_uuid = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=True)
    title = db.Column(db.String(100), nullable=True)
    content = db.Column(db.Text, nullable=False)
    tag = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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

class Notification(db.Model):
    __tablename__ = 'notifications'

    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title     = db.Column(db.String(120), nullable=False)
    text      = db.Column(db.Text, nullable=False)
    module    = db.Column(db.String(50), nullable=False)
    seen      = db.Column(db.Boolean, default=False, nullable=False)
    # NEW: track whether we've delivered the toast/push
    notified  = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship('User', back_populates='notifications')

# models.py
class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))

    def __init__(self, user_id):
        self.user_id = user_id
        self.token = secrets.token_urlsafe(64)
        self.expires_at = datetime.utcnow() + timedelta(minutes=30)  # 30-minute expiration

class ResetUndoToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False)
    old_password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

# Flow

class FlowProject(db.Model):
    __tablename__ = 'flow_projects'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    total_impact = db.Column(db.Integer, nullable=False, default=100)
    status = db.Column(db.String(20), default='active')  # active, completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    branches = db.relationship('FlowBranch', backref='project', lazy=True)
    
    @property
    def progress(self):
        return sum(commit.impact for branch in self.branches for commit in branch.commits)
    
    @property
    def progress_percent(self):
        return min(100, int((self.progress / self.total_impact) * 100))
    
    def mark_completed(self):
        """Mark project as completed by setting progress to total impact"""
        # Create a completion step in the main branch
        main_branch = FlowBranch.query.filter_by(
            project_id=self.id, 
            name='main'
        ).first()
        
        if main_branch:
            # Calculate remaining impact needed
            remaining = max(0, self.total_impact - self.progress)
            
            if remaining > 0:
                completion_step = FlowCommit(
                    branch_id=main_branch.id,
                    title="Project Completion",
                    description="Project marked as completed",
                    impact=remaining
                )
                db.session.add(completion_step)
        
        self.status = 'completed'
        db.session.commit()

class FlowBranch(db.Model):
    __tablename__ = 'flow_branches'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('flow_projects.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    base_branch_id = db.Column(db.Integer, db.ForeignKey('flow_branches.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    commits = db.relationship('FlowCommit', backref='branch', lazy=True)
    parent = db.relationship('FlowBranch', remote_side=[id], backref='children')

class FlowCommit(db.Model):
    __tablename__ = 'flow_commits'
    id = db.Column(db.Integer, primary_key=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('flow_branches.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    impact = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    prev_commit_id = db.Column(db.Integer, db.ForeignKey('flow_commits.id'), nullable=True)
    next_commits = db.relationship('FlowCommit', backref=db.backref('prev_commit', remote_side=[id]))

#---------------------------------Helper functions--------------------------------
def generate_session_key(user_id):
    key = secrets.token_hex(32)
    session_keys[key] = {
        "user_id": user_id,
        "expires_at": datetime.now() + timedelta(minutes=120),
        "last_active": datetime.now()
    }
    return key

def load_secrets():
    with app.app_context():
        secrets = AppSecret.query.all()
        for secret in secrets:
            app.config[secret.key] = secret.value

@app.before_request
def ensure_secrets_loaded():
    load_secrets()

def get_google_oauth_flow(state=None):

    redirect_uri = f"{request.scheme}://{request.host}/google/callback"
    return Flow.from_client_config(
        client_config={
            'web': {
                'client_id': current_app.config['GOOGLE_CLIENT_ID'],
                'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [redirect_uri]
            }
        },
        scopes=['https://www.googleapis.com/auth/calendar'],
        redirect_uri=redirect_uri,
        state=state  # Pass the state parameter if provided
    )

def save_google_credentials(user_id, credentials):
    existing = GoogleCalendarCredentials.query.filter_by(user_id=user_id).first()
    
    creds_data = {
        'access_token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_expiry': credentials.expiry,
        'calendar_id': 'primary'  # Default to primary calendar
    }
    
    if existing:
        for key, value in creds_data.items():
            setattr(existing, key, value)
    else:
        creds = GoogleCalendarCredentials(user_id=user_id, **creds_data)
        db.session.add(creds)
    
    # ADD THIS: Automatically create default sync mapping
    default_calendar = Calendar.query.filter_by(user_id=user_id, is_default=True).first()
    if default_calendar:
        # Create sync mapping if it doesn't exist
        if not CalendarSync.query.filter_by(
            user_id=user_id,
            local_calendar_id=default_calendar.id
        ).first():
            sync = CalendarSync(
                user_id=user_id,
                local_calendar_id=default_calendar.id,
                google_calendar_id='primary'
            )
            db.session.add(sync)
    
    db.session.commit()

def get_valid_google_credentials(user_id):
    creds_record = GoogleCalendarCredentials.query.filter_by(user_id=user_id).first()
    if not creds_record:
        return None
    
    creds = Credentials(
        token=creds_record.access_token,
        refresh_token=creds_record.refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=current_app.config['GOOGLE_CLIENT_ID'],
        client_secret=current_app.config['GOOGLE_CLIENT_SECRET'],
        scopes=['https://www.googleapis.com/auth/calendar']
    )
    
    if creds.expired:
        try:
            creds.refresh(Request())
            # Update credentials in DB
            creds_record.access_token = creds.token
            creds_record.token_expiry = creds.expiry
            db.session.commit()
        except Exception as e:
            app.logger.error(f"Token refresh failed: {str(e)}")
            return None
    
    return creds


# sync.py
def sync_calendars(user_id, full_sync=False):
    creds = get_valid_google_credentials(user_id)
    if not creds:
        return False, "Google credentials invalid"
    
    sync_mappings = CalendarSync.query.filter_by(user_id=user_id, sync_enabled=True).all()
    if not sync_mappings:
        return False, "No calendars linked"
    
    service = build('calendar', 'v3', credentials=creds)
    results = []
    
    # Update the overall last sync time for the credentials
    creds_record = GoogleCalendarCredentials.query.filter_by(user_id=user_id).first()
    if creds_record:
        creds_record.last_sync = datetime.utcnow()
    
    # Check if any mapping requires full sync
    if not full_sync:
        for mapping in sync_mappings:
            if not mapping.sync_token:
                full_sync = True
                break
    
    # Process all mappings
    for mapping in sync_mappings:
        try:
            # Push local changes to Google
            push_to_google(service, mapping)
            
            # Pull changes from Google
            pull_from_google(service, mapping, full_sync)
            
            mapping.last_synced = datetime.utcnow()
            results.append(f"Calendar {mapping.local_calendar_id} synced")
        except Exception as e:
            results.append(f"Sync failed for calendar {mapping.local_calendar_id}: {str(e)}")
    
    db.session.commit()
    return True, "\n".join(results)

def push_to_google(service, mapping):
    # Record sync start time to avoid processing updates during sync
    sync_start = datetime.utcnow()
    
    # Get modified appointments since last sync
    last_sync = mapping.last_synced or datetime.min
    appointments = Appointment.query.filter(
        Appointment.calendar_id == mapping.local_calendar_id,
        Appointment.updated_at > last_sync,
        Appointment.updated_at < sync_start  # Exclude updates during sync
    ).all()
    
    if not appointments:
        return
    
    current_app.logger.info(f"Pushing {len(appointments)} appointment(s) to Google calendar")
    
    for appt in appointments:
        event = convert_appointment_to_event(appt)
        if not event:
            continue
            
        google_calendar_id = mapping.google_calendar_id
        
        try:
            if appt.google_event_id:
                # Update existing event
                current_app.logger.info(f"Updating event {appt.google_event_id} for appointment {appt.id}")
                updated_event = service.events().update(
                    calendarId=google_calendar_id,
                    eventId=appt.google_event_id,
                    body=event
                ).execute()
            else:
                # Create new event
                current_app.logger.info(f"Creating new event for appointment {appt.id}")
                result = service.events().insert(
                    calendarId=google_calendar_id,
                    body=event
                ).execute()
                appt.google_event_id = result['id']
                current_app.logger.info(f"Created event {result['id']}")
        except Exception as e:
            # Handle specific Google API errors
            if 'deleted' in str(e).lower():
                current_app.logger.warning(f"Event {appt.google_event_id} was deleted on Google. Removing local Google event ID.")
                appt.google_event_id = None
            else:
                current_app.logger.error(f"Failed to push appointment {appt.id} to Google: {str(e)}")
    
    # Commit any changes made to appointments (google_event_id set or cleared)
    db.session.commit()

def pull_from_google(service, mapping, full_sync=False):
    # Determine if we need to do a full sync
    if full_sync or not mapping.sync_token:
        sync_token = None
    else:
        sync_token = mapping.sync_token

    events = []
    next_sync_token = None
    page_token = None

    while True:
        try:
            # Prepare parameters
            params = {
                'calendarId': mapping.google_calendar_id,
                'timeMin': (datetime.utcnow() - timedelta(days=365)).isoformat() + 'Z',
                'maxResults': 250,
                'singleEvents': True,
                'showDeleted': True,
            }
            
            # Add sync token if available
            if sync_token and not full_sync:
                params['syncToken'] = sync_token
            else:
                # For full syncs, use time range instead of sync token
                params['timeMin'] = (datetime.utcnow() - timedelta(days=365)).isoformat() + 'Z'
            
            # Add page token if available
            if page_token:
                params['pageToken'] = page_token
                
            # Execute API call
            events_result = service.events().list(**params).execute()
            
            events.extend(events_result.get('items', []))
            page_token = events_result.get('nextPageToken')
            
            # Get next sync token on last page
            if not page_token:
                next_sync_token = events_result.get('nextSyncToken')
                break
                
        except Exception as e:
            # Handle invalid sync token (410 error)
            if hasattr(e, 'resp') and e.resp.status == 410:
                # Reset sync token and retry as full sync
                mapping.sync_token = None
                db.session.commit()
                return pull_from_google(service, mapping, True)
            else:
                current_app.logger.error(f"Google API error: {str(e)}")
                raise e
    
    # Process events
    for event in events:
        process_google_event(event, mapping.local_calendar_id, mapping.user_id)
    
    # Update sync token if we got a new one
    if next_sync_token:
        mapping.sync_token = next_sync_token

def process_google_event(event, local_calendar_id, user_id):
    try: 
        # Handle deleted events
        if event.get('status') == 'cancelled':
            Appointment.query.filter_by(
                google_event_id=event['id'],
                user_id=user_id
            ).delete()
            return
        
        # Convert Google event to appointment
        appt_data = {
            'title': event.get('summary', 'No Title'),
            'description': event.get('description', ''),
            'start_datetime': parse_google_datetime(event['start']),
            'end_datetime': parse_google_datetime(event['end']),
            'google_event_id': event['id'],
            'calendar_id': local_calendar_id,
            'user_id': user_id,
            'color': event.get('colorId'),
            'is_all_day': 'date' in event['start'],  # Detect all-day events
            'recurrence_rule': event.get('recurrence', [None])[0]  # Handle recurrence
        }
        
        # Find existing or create new
        appointment = Appointment.query.filter_by(
            google_event_id=event['id'],
            user_id=user_id
        ).first()
        
        if appointment:
            # Update existing appointment
            for key, value in appt_data.items():
                setattr(appointment, key, value)
        else:
            # Create new appointment
            appointment = Appointment(**appt_data)
            db.session.add(appointment)
    except Exception as e:
        current_app.logger.error(f"Error processing Google event {event.get('id')}: {str(e)}")

def parse_google_datetime(time_dict):
    try:
        if 'dateTime' in time_dict:
            dt_str = time_dict['dateTime']
            # Parse as timezone-aware datetime
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            # Convert to UTC and remove timezone info
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        else:  # All-day event
            return datetime.strptime(time_dict['date'], '%Y-%m-%d')
    except Exception as e:
        current_app.logger.error(f"Error parsing datetime: {time_dict} - {str(e)}")
        return datetime.utcnow()

# In create_appointment and update_appointment endpoints
# Add this conversion for incoming datetimes:
def to_utc_naive(dt_str):
    """Convert ISO string to UTC naive datetime"""
    dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt

    
# In convert_appointment_to_event function
def convert_appointment_to_event(appointment):
    try:
        event = {
            'summary': appointment.title,
            'description': appointment.description or "",
        }

        if appointment.google_event_id:
            event['id'] = appointment.google_event_id

        # Handle all-day events
        if appointment.is_all_day:
            # Google requires end date to be exclusive (next day after event)
            end_date = appointment.end_datetime.date() + timedelta(days=1)
            event.update({
                'start': {'date': appointment.start_datetime.date().isoformat()},
                'end': {'date': end_date.isoformat()}
            })
        else:
            # Time-based events with UTC timezone
            event.update({
                'start': {'dateTime': appointment.start_datetime.isoformat() + 'Z',
                          'timeZone': 'UTC'},
                'end': {'dateTime': appointment.end_datetime.isoformat() + 'Z',
                        'timeZone': 'UTC'}
            })
        
        # Handle recurrence if exists
        if appointment.recurrence_rule:
            event['recurrence'] = [appointment.recurrence_rule]
        
        return event
    except Exception as e:
        current_app.logger.error(f"Error converting appointment {appointment.id} to event: {str(e)}")
        return None

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

@app.route('/api/setting', methods=['POST'])
def handle_setting():
    data = request.get_json()
    key = data.get('key')
    default = data.get('default')
    
    if key is None or default is None:
        return jsonify({"error": "Both key and default are required"}), 400
    
    value = check(key, default)
    return jsonify({"key": key, "value": value})


# Generate device ID in frontend
def send_notification(user_id, title, text, module):
    notif = Notification(user_id=user_id, title=title, text=text, module=module)
    db.session.add(notif)
    db.session.commit()
    
    subs = PushSubscription.query.filter_by(user_id=user_id).all()
    payload = json.dumps({
        'id': notif.id,
        'title': title,
        'body': text,
        'url': module
    })
    
    for sub in subs:
        try:
            webpush(
                subscription_info={'endpoint': sub.endpoint, 'keys': sub.keys},
                data=payload,
                vapid_private_key=current_app.config['VAPID_PRIVATE_KEY'],
                vapid_claims=current_app.config['VAPID_CLAIMS']
            )
        except WebPushException as e:
            code = getattr(e.response, 'status_code', None)
            if code in (404, 410):
                db.session.delete(sub)
                db.session.commit()
            else:
                current_app.logger.error('Push error: %s', e)
    return notif


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

def validate_session_key(key=None):
    # 1) if no key passed, pull from cookie
    if key is None:
        key = request.cookies.get("session_key")

    # 2) missing or not in our store?
    if not key or key not in session_keys:
        return False, "Invalid or missing session API key"

    sess = session_keys[key]
    now = datetime.utcnow()

    # 3) expired?
    if sess["expires_at"] < now:
        # auto‑clean up
        del session_keys[key]
        return False, "Session expired. Please log in again."

    # 4) user still exists?
    user = User.query.get(sess["user_id"])
    if not user:
        del session_keys[key]
        return False, "Invalid or missing session API key"

    # 5) suspended?
    if user.suspended:
        del session_keys[key]
        return False, "Account is suspended and cannot log in."

    # 6) update last‑active timestamp
    sess["last_active"] = now

    # 7) success → return payload dict just like before
    return True, sess

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
    @wraps(func)
    def wrapper(*args, **kwargs):
        # if they still sent an Authorization header, ignore it
        valid, resp = validate_session_key()
        if not valid:
            # exactly the same error behavior as before
            code = 403 if "suspended" in resp else 401
            return jsonify({"error": resp}), code
        g.user_id = resp["user_id"]
        return func(*args, **kwargs)
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

def send_email(
    to_address,
    subject,
    *,
    title=None,
    content_html,
    content_text=None,
    buttons=None,
    logo_url,
    unsubscribe_url,
    cc=None,
    bcc=None,
    reply_to=None,
    attachments=None,     # list of filepaths
    inline_images=None,   # list of (cid, filepath)
    headers=None          # dict of additional headers
):
    """
    Send a multi-part email via Gmail SMTP.
    - content_html: HTML snippet
    - content_text: plain-text fallback (auto-generated if None)
    - buttons: list of {'text','href','color'}
    - attachments: paths to attach
    - inline_images: [(cid, path)] for embedding images
    - cc, bcc: lists of addresses
    - reply_to: single address
    - headers: extra headers dict
    """
    gmail_user = app.config['GMAIL_USER']
    gmail_pass = app.config['GMAIL_APP_PASSWORD']
    if not gmail_user or not gmail_pass:
        raise ValueError("GMAIL_USER and GMAIL_APP_PASSWORD must be set")

    # Render HTML
    tpl = jinja_env.get_template('email_templates/base.html')
    html_body = tpl.render(
        title=title or subject,
        content=content_html,
        buttons=buttons or [],
        logo_url=logo_url,
        unsubscribe_url=unsubscribe_url
    )

    # Build message
    msg = MIMEMultipart('related')
    msg['Subject'] = subject
    msg['From'] = gmail_user
    msg['To'] = to_address
    if cc:
        msg['Cc'] = ', '.join(cc)
    if bcc:
        # BCC isn’t in headers—passed to sendmail only
        pass
    if reply_to:
        msg.add_header('Reply-To', reply_to)
    if headers:
        for k, v in headers.items():
            msg.add_header(k, v)

    # Alternative part (text + HTML)
    alt = MIMEMultipart('alternative')
    text = content_text or "Please view this email in an HTML-capable client."
    alt.attach(MIMEText(text, 'plain'))
    alt.attach(MIMEText(html_body, 'html'))
    msg.attach(alt)

    # Inline images
    for cid, path in inline_images or []:
        with open(path, 'rb') as f:
            img = MIMEImage(f.read())
            img.add_header('Content-ID', f'<{cid}>')
            msg.attach(img)

    # Attachments
    for fp in attachments or []:
        ctype, encoding = mimetypes.guess_type(fp)
        maintype, subtype = (ctype or 'application/octet-stream').split('/', 1)
        with open(fp, 'rb') as f:
            part = MIMEBase(maintype, subtype)
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(fp))
            msg.attach(part)

    # Send
    all_recipients = [to_address] + (cc or []) + (bcc or [])
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(gmail_user, gmail_pass)
        server.sendmail(gmail_user, all_recipients, msg.as_string())

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
    """ Deletes all user-related data and the user itself. """
    user_to_delete = user if isinstance(user, User) else User.query.get(user)
    if not user_to_delete:
        return False

    try:
        # Delete push subscriptions
        PushSubscription.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete fingerprints
        FingerPrint.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete IP addresses
        IpAddres.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete group memberships
        GroupMember.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete invites (both sent and received)
        Invite.query.filter(
            (Invite.user_id == user_to_delete.id) | 
            (Invite.invited_by == user_to_delete.id)
        ).delete()
        
        # Delete todos
        Todo.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete XP records
        PlayerXp.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete notifications
        Notification.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete notes and their associations
        note_ids = [n.id for n in Note.query.filter_by(user_id=user_to_delete.id).all()]
        if note_ids:
            # Remove note-appointment associations
            stmt = appointment_note.delete().where(
                appointment_note.c.note_id.in_(note_ids)
            )
            db.session.execute(stmt)
        Note.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete appointments and their associations
        appointment_ids = [a.id for a in Appointment.query.filter_by(user_id=user_to_delete.id).all()]
        if appointment_ids:
            # Remove appointment-note associations
            stmt = appointment_note.delete().where(
                appointment_note.c.appointment_id.in_(appointment_ids)
            )
            db.session.execute(stmt)
        Appointment.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete calendars
        Calendar.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Delete user colors
        UserColor.query.filter_by(user_id=user_to_delete.id).delete()
        
        # Finally, delete the user
        db.session.delete(user_to_delete)
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user data: {str(e)}")
        return False
    

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

def get_schema_fingerprint_via_sqlalchemy(db_path):
    """
    Uses SQLAlchemy alone to:
      1. Connect (read-only) to the SQLite file at db_path
      2. SELECT type, name, sql FROM sqlite_master WHERE … ORDER BY type,name
      3. Serialize into JSON and MD5-hash it
    Returns an MD5 hex digest.
    """
    # Build a one-off engine for the file
    url = f"sqlite:///{db_path}"
    engine = create_engine(url)

    try:
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT type, name, sql
                  FROM sqlite_master
                 WHERE type IN ('table','index','view','trigger')
                   AND sql IS NOT NULL
                 ORDER BY type, name;
            """)).fetchall()
    except SQLAlchemyError as e:
        engine.dispose()
        raise
    finally:
        engine.dispose()

    # Turn rows into a JSON blob
    definitions = [
        {'type': r[0], 'name': r[1], 'sql': r[2]}
        for r in rows
    ]
    blob = json.dumps(definitions, separators=(",", ":"), ensure_ascii=False)
    return hashlib.md5(blob.encode("utf-8")).hexdigest()

def reflect_metadata(db_path):
    md = MetaData()
    eng = create_engine(f"sqlite:///{db_path}")
    md.reflect(bind=eng)
    return md, eng

def cleanup_expired_signup_sessions():
    """Clean up expired sessions during request processing"""
    try:
        # Delete sessions older than 1 hour using efficient bulk operation
        deleted_count = SignupSession.query.filter(
            SignupSession.created_at < datetime.utcnow() - timedelta(hours=1)
        ).delete()
        
        db.session.commit()
        app.logger.info(f"Cleaned up {deleted_count} expired signup sessions")
        return deleted_count
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Cleanup failed: {str(e)}")
        return 0
    
# tasks.py (or in your main app)
def cleanup_reset_tokens():
    """Remove expired password reset tokens"""
    try:
        expired = PasswordResetToken.query.filter(
            PasswordResetToken.expires_at < datetime.utcnow()
        ).all()
        
        for token in expired:
            db.session.delete(token)
        
        db.session.commit()
        app.logger.info(f"Cleaned up {len(expired)} expired reset tokens")
    except Exception as e:
        app.logger.error(f"Reset token cleanup failed: {str(e)}")

# Step 5: Add token cleanup function (run periodically)
def cleanup_expired_tokens():
    """Delete expired tokens (run daily via cron or scheduler)"""
    try:
        # Delete expired password reset tokens
        PasswordResetToken.query.filter(
            PasswordResetToken.expires_at < datetime.utcnow()
        ).delete()
        
        # Delete expired undo tokens
        ResetUndoToken.query.filter(
            ResetUndoToken.expires_at < datetime.utcnow()
        ).delete()
        
        # Commit changes
        db.session.commit()
        app.logger.info("Expired tokens cleaned up successfully")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Token cleanup failed: {str(e)}")
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

@app.errorhandler(405)
def method_not_allowed(e):
    # Return a JSON error for API routes, otherwise render a simple error page
    if request.path.startswith('/api') or request.is_json:
        return jsonify({"error": "Method Not Allowed"}), 405
    return render_template('405.html'), 405

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
    # Try to detect language from Accept-Language header
    lang = request.accept_languages.best_match(['nl', 'en'])
    if lang == 'nl':
        return render_template('home_dutch.html')
    return render_template('home.html')

@app.route('/favicon.ico')
def send_favicon():
    return send_from_directory('static', 'favicon.ico')

@app.route('/android-chrome-512x512.png')
def send_android_chrome_512():
    return send_from_directory('static', 'android-chrome-512x512.png')

@app.route('/android-chrome-192x192.png')
def send_android_chrome_192():
    return send_from_directory('static', 'android-chrome-192x192.png')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('static', 'sitemap.xml')

@app.route('/robots.txt')
def robots():
    return send_from_directory('static', 'robots.txt')


@app.route('/sw.js')
def serve_sw():
    return send_from_directory('static', 'sw.js')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/todo_page')
def todo_page():
    if check("todo", "Nee") == "Ja":
        return render_template('todo.html')
    else: 
        abort(404)

@app.route('/flow_page')
def flow_page():
    if check("flow", "Nee") == "Ja":
        return render_template("flow.html")
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

@app.route('/guide_page')
def guide_page():
    return render_template('guide.html')

# app.py
@app.route('/signup/email')
def signup_email_page():
    
    # Render the email verification page
    return render_template('signup_email.html')

@app.route('/reset-password')
def reset_password_page():
    return render_template('passwordreset.html')

@app.route('/tos')
def tos():
    return render_template("tos.html")

@app.route('/privacy')
def privacy_policy():
    return render_template("privacy-policy.html")

#---------------------------------API routes--------------------------------

# Flow routes:

@app.route('/flow/projects', methods=['GET'])
@require_session_key
def get_projects():
    projects = FlowProject.query.filter_by(user_id=g.user_id).all()
    return jsonify([{
        'id': p.id,
        'title': p.title,
        'description': p.description,
        'total_impact': p.total_impact,
        'progress': p.progress,
        'progress_percent': p.progress_percent,
        'status': p.status,
        'branch_count': len(p.branches),
        'commit_count': sum(len(b.commits) for b in p.branches),
        'created_at': p.created_at.isoformat()
    } for p in projects])

@app.route('/flow/projects', methods=['POST'])
@require_session_key
def create_project():
    data = request.get_json()
    new_project = FlowProject(
        user_id=g.user_id,
        title=data['title'],
        description=data.get('description', ''),
        total_impact=data.get('total_impact', 100)
    )
    db.session.add(new_project)
    db.session.commit()
    
    # Create main branch
    main_branch = FlowBranch(
        project_id=new_project.id,
        name='main'
    )
    db.session.add(main_branch)
    db.session.commit()
    
    return jsonify({
        'id': new_project.id,
        'message': 'Project created with main branch'
    }), 201

@app.route('/flow/projects/<int:project_id>', methods=['PUT'])
@require_session_key
def update_project(project_id):
    project = FlowProject.query.filter_by(id=project_id, user_id=g.user_id).first_or_404()
    data = request.get_json()
    project.title = data.get('title', project.title)
    project.description = data.get('description', project.description)
    project.total_impact = data.get('total_impact', project.total_impact)
    project.status = data.get('status', project.status)
    db.session.commit()
    return jsonify({'message': 'Project updated'})

@app.route('/flow/projects/<int:project_id>', methods=['DELETE'])
@require_session_key
def delete_project(project_id):
    project = FlowProject.query.filter_by(id=project_id, user_id=g.user_id).first_or_404()
    
    # Delete all branches and commits first
    for branch in project.branches:
        # Delete all commits in this branch
        FlowCommit.query.filter_by(branch_id=branch.id).delete()
        db.session.delete(branch)
    
    db.session.delete(project)
    db.session.commit()
    return jsonify({'message': 'Project deleted'})

@app.route('/flow/projects/<int:project_id>/branches', methods=['GET'])
@require_session_key
def get_branches(project_id):
    project = FlowProject.query.filter_by(id=project_id, user_id=g.user_id).first_or_404()
    branches = FlowBranch.query.filter_by(project_id=project_id).all()
    return jsonify([{
        'id': b.id,
        'name': b.name,
        'commit_count': len(b.commits),
        'created_at': b.created_at.isoformat(),
        'base_branch_id': b.base_branch_id
    } for b in branches])

@app.route('/flow/projects/<int:project_id>/branches', methods=['POST'])
@require_session_key
def create_branch(project_id):
    project = FlowProject.query.filter_by(id=project_id, user_id=g.user_id).first_or_404()
    data = request.get_json()
    
    # Check if branch name exists
    existing = FlowBranch.query.filter_by(project_id=project_id, name=data['name']).first()
    if existing:
        return jsonify({'error': 'Branch name already exists'}), 400
    
    new_branch = FlowBranch(
        project_id=project_id,
        name=data['name'],
        base_branch_id=data.get('base_branch_id')
    )
    db.session.add(new_branch)
    db.session.commit()
    
    return jsonify({
        'id': new_branch.id,
        'name': new_branch.name
    }), 201

@app.route('/flow/branches/<int:branch_id>', methods=['PUT'])
@require_session_key
def update_branch(branch_id):
    branch = FlowBranch.query.get_or_404(branch_id)
    project = FlowProject.query.get(branch.project_id)
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    if 'name' in data:
        # Check if new name exists
        existing = FlowBranch.query.filter_by(project_id=branch.project_id, name=data['name']).first()
        if existing and existing.id != branch_id:
            return jsonify({'error': 'Branch name already exists'}), 400
        branch.name = data['name']
    
    db.session.commit()
    return jsonify({'message': 'Branch updated'})

@app.route('/flow/branches/<int:branch_id>', methods=['DELETE'])
@require_session_key
def delete_branch(branch_id):
    branch = FlowBranch.query.get_or_404(branch_id)
    project = FlowProject.query.get(branch.project_id)
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if branch.name == 'main':
        return jsonify({'error': 'Cannot delete main branch'}), 400
    
    # Delete all commits in this branch first
    FlowCommit.query.filter_by(branch_id=branch_id).delete()
    
    db.session.delete(branch)
    db.session.commit()
    return jsonify({'message': 'Branch deleted'})

@app.route('/flow/sub-projects/<int:source_id>/merge/<int:target_id>', methods=['POST'])
@require_session_key
def merge_subprojects(source_id, target_id):
    source = FlowBranch.query.get_or_404(source_id)
    target = FlowBranch.query.get_or_404(target_id)
    
    if source.project_id != target.project_id:
        return jsonify({'error': 'Sub-projects must be in the same project'}), 400
    
    project = FlowProject.query.get(source.project_id)
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Merge steps
    for step in source.commits:
        new_step = FlowCommit(
            branch_id=target.id,
            title=step.title,
            description=step.description,
            impact=step.impact
        )
        db.session.add(new_step)
    
    # Delete source if requested
    delete_source = request.json.get('delete_source', False)
    if delete_source and source.name != 'main':
        FlowCommit.query.filter_by(branch_id=source.id).delete()
        db.session.delete(source)
    
    db.session.commit()
    
    message = f'Sub-project {source.name} merged into {target.name}'
    if delete_source:
        message += f' and source deleted'
    
    return jsonify({'message': message})

@app.route('/flow/branches/<int:branch_id>/steps', methods=['GET'])
@require_session_key
def get_steps(branch_id):
    branch = FlowBranch.query.get_or_404(branch_id)
    project = FlowProject.query.get(branch.project_id)
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Get steps in reverse chronological order (newest first)
    steps = FlowCommit.query.filter_by(branch_id=branch_id).order_by(FlowCommit.created_at.desc()).all()
    return jsonify([{
        'id': c.id,
        'title': c.title,
        'description': c.description,
        'impact': c.impact,
        'created_at': c.created_at.isoformat()
    } for c in steps])

@app.route('/flow/branches/<int:branch_id>/steps', methods=['POST'])
@require_session_key
def create_step(branch_id):
    branch = FlowBranch.query.get_or_404(branch_id)
    project = FlowProject.query.get(branch.project_id)
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    new_step = FlowCommit(
        branch_id=branch_id,
        title=data['title'],
        description=data['description'],
        impact=data['impact']
    )
    db.session.add(new_step)
    db.session.commit()
    
    # Check if project should be automatically completed
    project = FlowProject.query.get(branch.project_id)
    if project.progress >= project.total_impact and project.status != 'completed':
        project.status = 'completed'
        db.session.commit()
    
    return jsonify({
        'id': new_step.id,
        'message': 'Step created'
    }), 201

@app.route('/flow/commits/<int:commit_id>/revert', methods=['POST'])
@require_session_key
def revert_commit(commit_id):
    commit = FlowCommit.query.get_or_404(commit_id)
    branch = FlowBranch.query.get(commit.branch_id)
    project = FlowProject.query.get(branch.project_id)
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Get all subsequent commits
    subsequent_commits = FlowCommit.query.filter(
        FlowCommit.branch_id == branch.id,
        FlowCommit.created_at >= commit.created_at
    ).all()
    
    # Delete the commits
    for c in subsequent_commits:
        db.session.delete(c)
    
    db.session.commit()
    return jsonify({'message': f'{len(subsequent_commits)} commits reverted'})

# New endpoint to get project details including progress
@app.route('/flow/projects/<int:project_id>/details', methods=['GET'])
@require_session_key
def get_project_details(project_id):
    project = FlowProject.query.filter_by(id=project_id, user_id=g.user_id).first_or_404()
    return jsonify({
        'id': project.id,
        'title': project.title,
        'description': project.description,
        'total_impact': project.total_impact,
        'progress': project.progress,
        'progress_percent': project.progress_percent,
        'status': project.status,
        'branch_count': len(project.branches),
        'commit_count': sum(len(b.commits) for b in project.branches),
        'created_at': project.created_at.isoformat()
    })

@app.route('/flow/projects/<int:project_id>/all-branches', methods=['GET'])
@require_session_key
def get_all_branches(project_id):
    project = FlowProject.query.filter_by(id=project_id, user_id=g.user_id).first_or_404()
    branches = FlowBranch.query.filter_by(project_id=project_id).all()
    return jsonify([{
        'id': b.id,
        'name': b.name
    } for b in branches])

@app.route('/flow/projects/<int:project_id>/complete', methods=['POST'])
@require_session_key
def complete_project(project_id):
    project = FlowProject.query.filter_by(id=project_id, user_id=g.user_id).first_or_404()
    project.mark_completed()
    return jsonify({'message': 'Project marked as completed'})

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

@app.route('/google/connect')
@require_session_key
def google_connect():
    flow = get_google_oauth_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        include_granted_scopes='true'
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/google/callback')
def google_callback():
    # Extract OAuth parameters
    state = request.args.get('state', '')
    code = request.args.get('code', '')
    
    # Render template with JS that will finalize the connection
    return render_template('google_callback.html', state=state, code=code)

@app.route('/google/callback/finalize', methods=['POST'])
@require_session_key
def google_callback_finalize():
    try:
        data = request.get_json()
        state = data.get('state', '')
        code = data.get('code', '')
        
        # Verify state matches session
        if 'oauth_state' not in session or session['oauth_state'] != state:
            return jsonify({
                'success': False,
                'error': 'Invalid state parameter'
            }), 400

        # Exchange code for tokens
        flow = get_google_oauth_flow()
        flow.fetch_token(
            authorization_response=f"?code={code}&state={state}",
            code=code
        )
        
        # Save credentials
        credentials = flow.credentials
        save_google_credentials(g.user_id, credentials)
        
        return jsonify({
            'success': True,
            'redirect_url': '/scheduler-page?google_connected=1',
            'auto_mapped': True
        })
        
    except Exception as e:
        current_app.logger.error(f"OAuth finalization failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/google/disconnect', methods=['POST'])
@require_session_key
def google_disconnect():
    try:
        # Delete Google credentials
        creds = GoogleCalendarCredentials.query.filter_by(user_id=g.user_id).first()
        if creds:
            db.session.delete(creds)
        
        # Delete sync mappings
        mappings = CalendarSync.query.filter_by(user_id=g.user_id).all()
        for mapping in mappings:
            db.session.delete(mapping)
        
        db.session.commit()
        return jsonify({
            "success": True,
            "message": "Google account disconnected"
        })
    except Exception as e:
        current_app.logger.error(f"Disconnect failed: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Failed to disconnect Google account"
        }), 500

@app.route('/google/sync', methods=['POST'])
@require_session_key
def trigger_sync():
    # Allow forcing full sync
    full_sync = request.json.get('full_sync', False) if request.json else False
    
    success, message = sync_calendars(g.user_id, full_sync)
    status = 200 if success else 400
    return jsonify({"status": "success" if success else "error", "message": message}), status

@app.route('/sync/status', methods=['GET'])
@require_session_key
def sync_status():
    syncs = CalendarSync.query.filter_by(user_id=g.user_id).all()
    creds = GoogleCalendarCredentials.query.filter_by(user_id=g.user_id).first()
    
    data = {
        'google_connected': bool(creds),
        'calendars': [{
            'local_calendar_id': s.local_calendar_id,
            'google_calendar_id': s.google_calendar_id,
            'last_synced': s.last_synced.isoformat() if s.last_synced else None
        } for s in syncs]
    }
    return jsonify(data), 200

@app.route('/user-colors', methods=['GET'])
@require_session_key
def get_user_colors_fetch():
    """
    Returns the color settings for the currently authenticated user.
    Expects require_session_key to have set g.user_id.
    """
    # 1) Try to fetch existing row
    colors = UserColor.query.filter_by(user_id=g.user_id).first()

    # 2) If missing, create defaults and re‑fetch
    if not colors:
        ensure_user_colors(g.user_id)
        colors = UserColor.query.filter_by(user_id=g.user_id).first()

    # 3) Now colors is guaranteed to exist
    return jsonify({
        "background_color":  colors.background_color,
        "header_color":      colors.header_color,
        "contrasting_color": colors.contrasting_color,
        "button_color":      colors.button_color,
    }), 200


@app.route('/notifications', methods=['GET'])
@require_session_key
def get_unseen_notifications():
    """
    Fetch all unseen notifications for the current user,
    including whether we've already notified them.
    """
    notifs = (
        Notification.query
        .filter_by(user_id=g.user_id, seen=False)
        .order_by(Notification.timestamp.desc())
        .all()
    )
    result = [{
        'id':        n.id,
        'title':     n.title,
        'text':      n.text,
        'module':    n.module,
        'seen':      n.seen,
        'notified':  n.notified,
        'timestamp': n.timestamp.isoformat()
    } for n in notifs]
    return jsonify({'notifications': result})


@app.route('/api/save-subscription', methods=['POST'])
@require_session_key
def save_subscription():
    sub_data = request.get_json()
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({'error': 'unauthorized'}), 401

    # Generate device ID from browser fingerprint
    device_id = generate_device_id(request)
    
    # Upsert by user+device instead of endpoint
    sub = PushSubscription.query.filter_by(
        user_id=user.id,
        device_id=device_id
    ).first()

    if sub:
        # Update existing subscription
        sub.endpoint = sub_data['endpoint']
        sub.keys = sub_data['keys']
    else:
        # Create new subscription
        sub = PushSubscription(
            user_id=user.id,
            endpoint=sub_data['endpoint'],
            keys=sub_data['keys'],
            device_id=device_id
        )
        db.session.add(sub)
    
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/update-subscription', methods=['POST'])
@require_session_key
def update_subscription():
    data = request.get_json()
    
    # Handle service worker direct updates
    if request.headers.get('X-Device-Id') == 'direct-from-sw':
        old_sub = data['old']
        new_sub = data['new']
        
        # Find by endpoint
        subscription = PushSubscription.query.filter_by(
            endpoint=old_sub['endpoint']
        ).first()
        
        if subscription:
            subscription.endpoint = new_sub['endpoint']
            subscription.keys = new_sub['keys']
            db.session.commit()
        
        return jsonify({'success': True}), 200
    
    # Normal client updates
    sub_data = request.get_json()
    user = User.query.get(g.user_id)
    device_id = generate_device_id(request)
    
    sub = PushSubscription.query.filter_by(
        user_id=user.id,
        device_id=device_id
    ).first()
    
    if sub:
        sub.endpoint = sub_data.endpoint
        sub.keys = sub_data.keys
        db.session.commit()
    
    return jsonify({'success': True}), 200

def generate_device_id(request):
    """Generate persistent device ID using browser fingerprint"""
    fingerprint = ''.join([
        request.headers.get('User-Agent', ''),
        request.headers.get('Accept-Language', ''),
        request.remote_addr
    ])
    return hashlib.sha256(fingerprint.encode()).hexdigest()

@app.route('/api/vapid_public_key')
def get_vapid_key():
    # assume you store public key in your DB or env
    public_key = app.config.get('VAPID_PUBLIC_KEY')
    return jsonify({ "publicKey": public_key })

@app.route('/notifications/<int:notif_id>', methods=['POST'])
@require_session_key
def mark_notification_seen(notif_id):
    """
    Mark a single notification as seen.
    """
    notif = Notification.query.filter_by(
        id=notif_id,
        user_id=g.user_id
    ).first_or_404()

    notif.seen = True
    db.session.commit()

    return jsonify({'success': True, 'id': notif_id})


@app.route('/notifications/seen', methods=['POST'])
@require_session_key
def mark_notifications_seen_bulk():
    """
    Mark multiple notifications as seen (expects JSON body {"ids": [1,2,3]}).
    Optionally, accept {"all": true} to mark every unseen for the user.
    """
    payload = request.get_json(force=True)

    # Determine which IDs to mark
    if payload.get('all'):
        # Mark *all* unseen notifications for this user
        query = Notification.query.filter_by(
            user_id=g.user_id,
            seen=False
        )
    else:
        ids = payload.get('ids')
        if not isinstance(ids, list) or not ids:
            return jsonify({'success': False, 'error': 'Provide non-empty list of ids or {"all": true}'}), 400

        query = Notification.query.filter(
            Notification.user_id == g.user_id,
            Notification.id.in_(ids),
            Notification.seen == False
        )

    # Bulk update: set seen=True in one SQL statement
    updated_count = query.update({'seen': True}, synchronize_session=False)
    db.session.commit()

    return jsonify({
        'success': True,
        'updated': updated_count,
        # optionally echo back the IDs you just marked
        'ids': payload.get('all') and 'all_unseen' or ids
    })

@app.route('/notifications/notified/<int:notif_id>', methods=['POST'])
@require_session_key
def mark_notification_notified(notif_id):
    """
    Mark a single notification as having been delivered (toast/push).
    """
    notif = Notification.query.filter_by(
        id=notif_id,
        user_id=g.user_id
    ).first_or_404()

    # only toggle if unseen and un‑notified
    if not notif.notified:
        notif.notified = True
        db.session.commit()

    return jsonify({'success': True, 'id': notif_id})


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
        "startpage": user.startpage,
        "email": user.email if user.email else None
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

@app.route('/account/update_email', methods=['POST'])
@require_session_key
def update_email_request():
    user = User.query.get(g.user_id)
    new_email = request.json.get('email', '').strip()

    if new_email == "":
        user.email = None
        db.session.commit()
        return jsonify({"message": "Email removed successfully"}), 200

    # Validate email
    if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
        return jsonify({"error": "Invalid email format"}), 400
    
    # Check if email exists
    if User.query.filter(User.email == new_email, User.id != user.id).first():
        return jsonify({"error": "Email already in use"}), 400

    # Create verification session (reuse SignupSession model)
    session_id = str(uuid.uuid4())
    update_session = SignupSession(
        id=session_id,
        user_id=user.id,  # Link to existing user
        email=new_email,
        verification_code=''.join(random.choices('0123456789', k=6))
    )
    db.session.add(update_session)
    db.session.commit()

    # Build verification URL
    site_url = f"{request.scheme}://{request.host}"
    verify_url = f"{site_url}/account/verify_email_update?code={update_session.verification_code}&email={urllib.parse.quote(new_email)}"
    
    # Send verification email
    try:
        send_email(
            to_address=new_email,
            subject="Future Notes - Verify Your New Email",
            content_html=f"""
                <p>Please verify your new email address.</p>
                <p><a href="{verify_url}">Click here to verify</a></p>
            """,
            buttons=[{
                'text': 'Verify Email',
                'href': verify_url,
                'color': '#424242'
            }],
            logo_url=app.config['LOGO_URL'],
            unsubscribe_url="#"
        )
        return jsonify({"message": "Verification email sent"}), 200
    except Exception as e:
        app.logger.error(f"Email update failed: {str(e)}")
        return jsonify({"error": "Failed to send verification email"}), 500
    
@app.route('/account/verify_email_update')
def verify_email_update():
    code = request.args.get('code')
    email = request.args.get('email')
    
    if not code or not email:
        return render_template('email_error.html', 
                              message="Missing verification parameters"), 400

    # Find verification session
    update_session = SignupSession.query.filter(
        SignupSession.email == email,
        SignupSession.verification_code == code,
        SignupSession.user_id != None  # Ensure it's an update request
    ).first()

    if not update_session:
        return render_template('email_error.html',
                              message="Invalid or expired link"), 400

    # Update user email
    user = User.query.get(update_session.user_id)
    if not user:
        return render_template('email_error.html',
                              message="User not found"), 404

    user.email = email
    db.session.delete(update_session)
    db.session.commit()

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Verified</title>
        <meta http-equiv="refresh" content="3;url=/account_page">
        <style>
            body {{ font-family: Arial, sans-serif; text-align: center; padding: 40px; background-color:#2c2c2c;}}
            .success {{ color: #2ecc71; font-size: 24px; }}
            .loader {{ 
                width: 50px; 
                height: 50px;
                border: 5px solid #f3f3f3;
                border-top: 5px solid #3498db;
                border-radius: 50%;
                margin: 20px auto;
                animation: spin 1s linear infinite;
            }}
            p {{
                color: white;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
        </style>
    </head>
    <body>
        <div class="success">✓ Email verified successfully!</div>
        <div class="loader"></div>
        <p>Redirecting to your account...</p>
        <p><a href="/account_page">Click here if not redirected</a></p>
    </body>
    </html>
    """


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
        start_datetime = to_utc_naive(start_datetime_str)
        end_datetime = to_utc_naive(end_datetime_str)
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
            new_start = to_utc_naive(start_datetime_str)
            appointment.start_datetime = new_start
        except ValueError:
            return jsonify({"error": "Invalid start_datetime format. Use ISO 8601 format."}), 400

    if end_datetime_str:
        try:
            new_end = to_utc_naive(end_datetime_str)
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

# calendars.py
@app.route('/google/calendars', methods=['GET'])
@require_session_key
def get_google_calendars():
    creds = get_valid_google_credentials(g.user_id)
    if not creds:
        return jsonify({"error": "Google not connected"}), 401
        
    service = build('calendar', 'v3', credentials=creds)
    calendars = []
    page_token = None
    while True:
        calendar_list = service.calendarList().list(
            pageToken=page_token,
            minAccessRole='writer'  # Only calendars user can write to
        ).execute()
        for cal in calendar_list.get('items', []):
            calendars.append({
                'id': cal['id'],
                'name': cal['summary'],
                'primary': cal.get('primary', False)
            })
        page_token = calendar_list.get('nextPageToken')
        if not page_token:
            break
            
    return jsonify({"calendars": calendars}), 200

@app.route('/calendars/link', methods=['POST'])
@require_session_key
def link_calendar():
    data = request.get_json()
    local_calendar_id = data.get('local_calendar_id')
    google_calendar_id = data.get('google_calendar_id', 'primary')
    
    # Validate local calendar
    calendar = Calendar.query.filter_by(id=local_calendar_id, user_id=g.user_id).first()
    if not calendar:
        return jsonify({"error": "Local calendar not found"}), 404
    
    # Create or update sync mapping
    sync = CalendarSync.query.filter_by(
        user_id=g.user_id,
        local_calendar_id=local_calendar_id
    ).first()
    
    if sync:
        sync.google_calendar_id = google_calendar_id
        sync.sync_enabled = True
    else:
        sync = CalendarSync(
            user_id=g.user_id,
            local_calendar_id=local_calendar_id,
            google_calendar_id=google_calendar_id,
            sync_token=None  # Initialize as null
        )
        db.session.add(sync)
    
    db.session.commit()
    return jsonify({"message": "Calendar linked successfully"}), 200

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
    changed = False

    for todo in todos:
        # Clean up broken note links
        if todo.note_id is not None:
            note = Note.query.get(todo.note_id)
            if note is None:
                todo.note_id = None
                todo.note = None
                changed = True
        # Clean up broken appointment links
        if todo.appointment_id is not None:
            appt = Appointment.query.get(todo.appointment_id)
            if appt is None:
                todo.appointment_id = None
                todo.appointment = None
                changed = True

    if changed:
        db.session.commit()

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
    if check("todo_due_date_allow_past", "Ja") == "Nee":
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
            if check("todo_due_date_allow_past", "Ja") == "Nee":
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
    
# 4. mark a todo as completed
@app.route('/todos/<int:todo_id>/toggle-completed', methods=['POST'])
@require_session_key
def toggle_todo_completed(todo_id):
    user_id = g.user_id
    todo = Todo.query.get(todo_id)
    if not todo or todo.user_id != user_id:
        return jsonify({"error": "Todo not found"}), 404

    todo.completed = not todo.completed
    db.session.commit()
    return jsonify({
        "message": f"Todo marked as {'completed' if todo.completed else 'uncompleted'}!",
        "completed": todo.completed
    }), 200

# 5. delete a todo
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
    if user.id == g.user_id:
        return jsonify({"error": "You cannot invite yourself!"}), 403
    existing_invites = Invite.query.filter_by(user_id=user.id, group_id=group_id).all()
    if existing_invites:
        return jsonify({"error": "User already invited to this group"}), 400

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

@app.route('/groups', methods=['GET'])
@require_session_key
def list_user_groups():
    # fetch all memberships for the current user
    memberships = GroupMember.query.filter_by(user_id=g.user_id).all()
    # pull in the Group object for each membership
    groups = [{
        "group_id": m.group.id,
        "group_name": m.group.name,
        "joined_at": m.joined_at.isoformat(),
        "is_admin": m.admin
    } for m in memberships]
    return jsonify(groups), 200

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
    user_id = User.query.get(g.user_id)

    if not user_id:
        print("User not found")
        return jsonify({"error": "User not found"}), 400
    
    group_membership = GroupMember.query.filter_by(user_id=user_id.id).first()

    if not group_membership:
        return jsonify({"error": "User is not in any group"}), 404

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

    return jsonify({
        "group_name": group.name,
        "group_members": members_list,
        "current_user_admin": current_membership.admin
    }), 200
    
@app.route('/groups', methods=['POST'])
@require_session_key
def create_group():
    data = request.json 
    name = data.get('name')

    if not name:
        print("Group name is required")
        return jsonify({"error": "Group name is required"}), 400

    new_group = Group(name=name)
    db.session.add(new_group)
    db.session.commit()

    # Automatically add the creator as a member
    membership = GroupMember(user_id=g.user_id, group_id=new_group.id, admin=True)
    db.session.add(membership)
    db.session.commit()

    return jsonify({"message": "Group created successfully!", "group_id": new_group.id}), 201

@app.route('/groups/join', methods=['POST'])
@require_session_key
def join_group():
    data = request.json
    group_id = data.get('group_id')

    if not isinstance(group_id, (int, str, uuid.UUID)):
        # Handle invalid type (log/return error)
        return jsonify(error="Invalid group ID format"), 400

    group = Group.query.get(group_id)
    if not group:
        print("Group not found")
        return jsonify({"error": "Group not found"}), 404

    # Check if user is already in the group
    existing_member = GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    if existing_member:
        print("Already a member of this group")
        return jsonify({"message": "Already a member of this group"}), 200

    # Check if the group has no members
    has_members = GroupMember.query.filter_by(group_id=group_id).first()
    is_admin = not has_members  # If no members, the joining user becomes admin

    membership = GroupMember(user_id=g.user_id, group_id=group_id, admin=is_admin)

    # Notify other users in the group that a new member has joined
    if check("notify_users_join_group", "Nee") == "Ja":
        other_members = GroupMember.query.filter(
            GroupMember.group_id == group_id,
            GroupMember.user_id != g.user_id
        ).all()

        for member in other_members:
            send_notification(
                member.user_id,
                "New member joined",
                f"{g.username} has joined the group '{group.name}'",
                "/group-notes"
            )
    db.session.add(membership)
    db.session.commit()

    return jsonify({"message": "Joined group successfully!"}), 200

@app.route('/groups/leave', methods=['POST'])
@require_session_key
def leave_group():
    data = request.json
    group_id = data.get('group_id')

    group = Group.query.get(group_id)
    user = User.query.get(g.user_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404

    existing_member = GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    if not existing_member:
        return jsonify({"message": "Not a member of this group!"}), 403

    is_admin_leaving = existing_member.admin
    member_count = GroupMember.query.filter_by(group_id=group_id).count()

    # Remove user from group first to avoid FK constraint errors
    db.session.delete(existing_member)
    db.session.commit()

    if member_count == 1:
        # Last member left: delete notes and group
        Note.query.filter_by(group_id=group_id).delete()
        db.session.delete(group)
        db.session.commit()

        send_notification(
            g.user_id,
            "Group deleted",
            "You were the last member, so the group and all its notes were deleted.",
            "/group-notes"
        )
        return jsonify({"message": "Group deleted since you were the last member."}), 200

    # If the leaving user was the admin, transfer admin rights
    if is_admin_leaving:
        next_admin = GroupMember.query.filter_by(group_id=group_id).first()
        if next_admin:
            next_admin.admin = True
            db.session.commit()

            # Notify new admin
            send_notification(
                next_admin.user_id,
                "You are now the admin",
                f"You are now the admin of '{group.name}' because {user.username} left.",
                "/group-notes"
            )
            # Notify the leaving user
            send_notification(
                g.user_id,
                "Admin transfer",
                f"{next_admin.user.username} is now the admin of '{group.name}' after you left.",
                "/group-notes"
            )

            # Optionally notify other members about admin change
            if check("notify_users_admin_transfer", "Nee") == "Ja":
                other_members = GroupMember.query.filter(
                    GroupMember.group_id == group_id,
                    GroupMember.user_id.notin_([g.user_id, next_admin.user_id])
                ).all()

                for member in other_members:
                    send_notification(
                        member.user_id,
                        "Admin changed",
                        f"{next_admin.user.username} is now the admin of the group: '{group.name}' after {user.username} left.",
                        "/group-notes"
                    )

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
    
    current_user = User.query.get(g.user_id)
    # Notify the user being removed
    user_to_remove = User.query.get(user_id_to_remove)
    if user_to_remove:
        send_notification(
            user_id_to_remove,
            "Removed from group",
            f"You have been removed from the group '{member_to_remove.group.name}' by {current_user.username}.",
            "/group-notes"
        )

    db.session.delete(member_to_remove)
    db.session.commit()
    return jsonify({"message": "User removed successfully."}), 200

@app.route('/groups/delete', methods=['POST'])
@require_session_key
def delete_group():
    data = request.get_json()
    group_id = data.get("group_id")

    user = User.query.get(g.user_id)

    # Verify that the current user is an admin of the group
    admin_membership = GroupMember.query.filter_by(group_id=group_id, user_id=g.user_id).first()
    if not admin_membership or not admin_membership.admin:
        return jsonify({"error": "Unauthorized: only admins can delete the group."}), 403

    # Get the group early to access its name
    group = Group.query.get(group_id)
    if not group:
        return jsonify({"error": "Group not found."}), 404

    # Notify all members
    memberships = GroupMember.query.filter_by(group_id=group_id).all()
    for membership in memberships:
        user = User.query.get(membership.user_id)
        if user:
            send_notification(
                user.id,
                "Group deleted",
                f"The group '{group.name}' has been deleted by {user.username}. Notes cannot be recovered.",
                "/group-notes"
            )

    # Remove all group memberships
    GroupMember.query.filter_by(group_id=group_id).delete()
    # Remove all notes belonging to the group
    Note.query.filter_by(group_id=group_id).delete()
    # Remove the group itself
    db.session.delete(group)

    db.session.commit()
    return jsonify({"message": "Group deleted successfully."}), 200

# Group notes

@app.route('/groups/<string:group_id>/notes', methods=['GET'])
@require_session_key
def get_group_notes(group_id):
    # Authorization check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    notes = Note.query.filter_by(group_id=group_id).all()
    return jsonify([{
        "id": note.id,
        "title": note.title,
        "note": note.note,  # Already sanitized when stored
        "tag": note.tag
    } for note in notes])

@app.route('/groups/<string:group_id>/notes', methods=['POST'])
@require_session_key
def add_group_note(group_id):
    # Authorization check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    data = request.json
    # Sanitize HTML input
    sanitized_note = sanitize_html(data['note'])
    
    new_note = Note(
        group_id=group_id,
        title=data.get('title'),
        note=sanitized_note,  # Store sanitized HTML
        tag=data.get('tag')
    )
    db.session.add(new_note)
    db.session.commit()
    return jsonify({"message": "Group note added successfully!"}), 201

# Updated route with note_id parameter
@app.route('/groups/<string:group_id>/notes/<int:note_id>', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_group_note(group_id, note_id):  # Added note_id parameter
    # Find note and verify group ownership
    note = Note.query.filter_by(id=note_id, group_id=group_id).first()
    if not note:
        return jsonify({"error": "Note not found"}), 404

    # Authorization check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    if request.method == 'PUT':
        data = request.json
        # Sanitize updated HTML
        note.title = data.get('title')
        note.note = sanitize_html(data['note'])  # Sanitize before update
        note.tag = data.get('tag')
        db.session.commit()
        return jsonify({"message": "Note updated successfully!"}), 200

    elif request.method == 'DELETE':
        db.session.delete(note)
        db.session.commit()
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
        if delete_user_and_data(user):  # Pass the User object
            db.session.commit()  # Single commit point
            return jsonify({"message": "Account deleted successfully!"}), 200
        else:
            return jsonify({"error": "Failed to delete account"}), 500
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
            # Generate unique filename with .jpg extension
            filename = secure_filename(f"{user.username}_{uuid.uuid4().hex}.jpg")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{filename}")

            try:
                # Save temporarily for processing
                file.save(temp_path)
                
                # Open and process image
                with Image.open(temp_path) as img:
                    # Convert to RGB if needed (removes transparency)
                    if img.mode in ('RGBA', 'LA', 'P'):
                        img = img.convert('RGB')
                    
                    # Downscale image (max dimensions: 500x500)
                    img.thumbnail((500, 500), Image.LANCZOS)
                    
                    # Save compressed version with quality=85
                    img.save(file_path, 'JPEG', quality=45, optimize=True)
                
                # Remove temporary file
                os.remove(temp_path)
                
            except Exception as e:
                app.logger.error(f"Image processing failed: {e}")
                # Clean up any partial files
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
                return jsonify({"error": "Failed to process image"}), 500

            # Delete old profile picture after successful processing
            old_picture = user.profile_picture
            if old_picture and os.path.isfile(old_picture):
                try:
                    os.remove(old_picture)
                except Exception as e:
                    app.logger.warning(f"Failed to delete old profile picture: {e}")

            # Update database record
            user.profile_picture = file_path
            db.session.commit()

            return jsonify({"message": "Profile picture updated successfully", "path": file_path}), 200

    elif request.method == 'DELETE':
        user = User.query.get(g.user_id)
        if not user:
            print("User not found")
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

@app.route('/api/identify', methods=['POST'])
def identify():
    data = request.get_json() or {}
    visitor_id = data.get('visitorId')
    if not visitor_id:
        return jsonify({'error': 'visitorId missing'}), 400

    # Save in session for later linking
    session['visitor_id'] = visitor_id

    # Upsert fingerprint record
    fp = FingerPrint.query.filter_by(visitor_id=visitor_id).first()
    if not fp:
        fp = FingerPrint(
            visitor_id=visitor_id,
            last_ip=request.remote_addr
        )
        db.session.add(fp)
    else:
        fp.last_ip = request.remote_addr
    db.session.commit()

    return jsonify({'status': 'ok'})

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
            
            if delete_user_and_data(user_to_delete):  # Pass the User object
                db.session.commit()  # Explicit commit
                return jsonify({"message": "User deleted successfully"}), 200
            else:
                return jsonify({"error": "Failed to delete user"}), 500

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

@app.route('/admin/notification', methods=['POST'])
@require_session_key
@require_admin
def send_notification_to_all():
    data = request.json
    title = data.get("title")
    message = data.get("message")
    module = data.get("module")

    if not message or not title or not module:
        return jsonify({"error": "All fields are required."}), 400
    
    if not module.startswith("/"):
        return jsonify({"error": "Module must start with a slash (/)"}), 400

    # Fetch all users
    users = User.query.all()
    for user in users:
        # Send notification to each user
        send_notification(user.id, title, message, module)

    return jsonify({"message": "Notification sent to all users."}), 200

@app.route('/admin/notification/user', methods=['POST'])
@require_session_key
@require_admin
def send_notification_to_user():
    data = request.json
    user_id = data.user_id

    
    title = data.get("title")
    message = data.get("message")
    module = data.get("module")

    user = User.query.get(user_id)

    if not user_id or not message or not title or not module:
        return jsonify({"error": "All fields are required."}), 400
    
    if not module.startswith("/"):
        return jsonify({"error": "Module must start with a slash (/)"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found!"}), 404
    
    send_notification(user_id, title, message, module)

    return jsonify({"message": f"Notification sent to {user.username} ({user_id})"}), 200

@app.route('/create_backup', methods=['POST'])
@require_session_key
@require_admin
def create_backup():
    """
    Create a timestamped copy of the live database file in the backups directory.
    """
    # Get the path to the current active SQLite database file
    engine = db.get_engine()
    if not hasattr(engine, 'url') or engine.url.drivername != 'sqlite':
        return jsonify({'error': 'Backup creation only implemented for SQLite databases.'}), 400

    # Get the actual file path from the SQLAlchemy engine
    db_path = engine.url.database
    if not db_path or not os.path.exists(db_path):
        return jsonify({'error': 'Live database file not found'}), 404

    # Create timestamped filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"backup_{timestamp}.db"
    dest_path = os.path.join(BACKUP_DIR, filename)

    try:
        shutil.copy(db_path, dest_path)
    except Exception as e:
        current_app.logger.error(f"Backup failed: {e}")
        return jsonify({'error': 'Backup creation failed'}), 500

    return jsonify({'message': 'Backup created', 'file': filename}), 201

@app.route('/list', methods=['GET'])
@require_session_key
@require_admin
def list_backups():
    engine = db.get_engine()
    live_path = engine.url.database
    if not live_path or not os.path.exists(live_path):
        return jsonify({'error': 'Live database file not found'}), 404

    # fingerprint live
    try:
        live_fp = get_schema_fingerprint_via_sqlalchemy(live_path)
    except Exception as e:
        current_app.logger.error(f"Live-DB schema read failed: {e}")
        return jsonify({'error': 'Could not inspect live schema'}), 500

    backups = []
    for fname in sorted(os.listdir(BACKUP_DIR)):
        full = os.path.join(BACKUP_DIR, fname)
        ts = os.path.getctime(full)
        entry = {
            'filename': fname,
            'created_at': datetime.fromtimestamp(ts).isoformat()
        }

        try:
            fp = get_schema_fingerprint_via_sqlalchemy(full)
            entry['outdated_schema'] = (fp != live_fp)
        except Exception as e:
            current_app.logger.warning(f"Schema read failed for {fname}: {e}")
            entry['outdated_schema'] = True

        backups.append(entry)

    return jsonify({'backups': backups}), 200


@app.route('/restore', methods=['POST'])
@require_session_key
@require_admin
def restore_backup():
    """
    Restore a given backup file to become the new data.db,
    with rollback on failure. Uses SQLAlchemy under the hood,
    and disposes all connections before touching the file.
    Expects JSON: { "filename": "mybackup-2025-06-15.db" }
    """
    data = request.get_json() or {}
    fname = data.get('filename')
    if not fname:
        return jsonify({"error": "Missing filename"}), 400

    src = os.path.join(BACKUP_DIR, fname)
    if not os.path.isfile(src):
        return jsonify({"error": f"Backup {fname} not found"}), 404

    # ── STEP 0 ──
    # Close all active sessions/connections so the file is no longer locked.
    try:
        db.session.remove()
        db.engine.dispose()
    except Exception as e:
        # usually non‑fatal, but log or return if you want stricter guarantees
        app.logger.warning(f"Failed to fully dispose engine before archive: {e}")

    # ── STEP 1 ── Archive current DB ──
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    old_db = DB_PATH + f".old-{timestamp}"
    try:
        if os.path.exists(DB_PATH):
            os.rename(DB_PATH, old_db)
    except Exception as e:
        return jsonify({"error": f"Failed to archive old DB: {e}"}), 500

    # ── STEP 2 ── Copy the chosen backup into place ──
    try:
        shutil.copy(src, DB_PATH)
    except Exception as e:
        # rollback archive
        if os.path.exists(old_db):
            os.rename(old_db, DB_PATH)
        return jsonify({"error": f"Failed to install backup: {e}"}), 500

    # ── STEP 3 ── Refresh SQLAlchemy again ──
    try:
        db.session.remove()
        db.engine.dispose()
    except:
        pass

    # ── STEP 4 ── Sanity‑check via SQLAlchemy ──
    try:
        res = db.session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1;")
            )
        if res.first() is None:
            raise RuntimeError("No tables found in DB")
    except (SQLAlchemyError, RuntimeError) as e:
        # rollback to original DB
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        if os.path.exists(old_db):
            os.rename(old_db, DB_PATH)
        return jsonify({"error": f"Backup test query failed: {e}"}), 500

    # ── STEP 5 ── Clean up archive ──
    try:
        if os.path.exists(old_db):
            os.remove(old_db)
    except Exception:
        app.logger.warning("Could not delete old DB archive; manual cleanup may be required.")

    # -- STEP 6 -- Clean up the restored backup from the backup directory --
    try:
        if os.path.exists(src):
            os.remove(src)
    except Exception as e:
        app.logger.warning(f"Could not delete restored backup file {src}: {e}")

    return jsonify({"status": f"Successfully restored {fname}"}), 200

@app.route('/restore/repair', methods=['POST'])
@require_session_key
@require_admin
def repair_backup():
    data = request.get_json() or {}
    fname = data.get('filename')
    if not fname:
        return jsonify({"error": "Missing filename"}), 400

    src = os.path.join(BACKUP_DIR, fname)
    if not os.path.isfile(src):
        return jsonify({"error": f"Backup {fname} not found"}), 404

    live_path = db.get_engine().url.database

    # 1. Reflect both schemas
    live_md, live_eng = reflect_metadata(live_path)
    old_md,  old_eng  = reflect_metadata(src)

    # 2. Open a real Connection + Transaction on the backup DB
    try:
        with old_eng.connect() as conn:
            trans = conn.begin()
            try:
                # 2a. Create missing tables in the backup
                missing_tables = set(live_md.tables) - set(old_md.tables)
                for tblname in missing_tables:
                    live_tbl = live_md.tables[tblname]
                    # attach a copy of the Table to old_md
                    live_tbl.to_metadata(old_md)
                    old_tbl = old_md.tables[tblname]
                    old_tbl.create(bind=conn)

                # 2b. Add missing columns in existing tables
                common_tables = set(live_md.tables) & set(old_md.tables)
                inspector = inspect(conn)
                for tblname in common_tables:
                    live_tbl = live_md.tables[tblname]
                    existing_cols = {c["name"] for c in inspector.get_columns(tblname)}

                    for col in live_tbl.columns:
                        if col.name not in existing_cols:
                            colname = col.name
                            coltype = col.type.compile(dialect=live_eng.dialect)
                            ddl = f'ALTER TABLE "{tblname}" ADD COLUMN "{colname}" {coltype}'
                            conn.execute(text(ddl))

                # commit just the schema changes on the backup file
                trans.commit()

            except Exception:
                trans.rollback()
                raise

    except Exception as e:
        app.logger.error(f"Schema repair failed for {src}: {e}")
        return jsonify({"error": f"Schema repair failed: {e}"}), 500

    return jsonify({"status": f"Repaired schema of backup {fname}"}), 200


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

@app.route('/backup/delete', methods=['DELETE'])
@require_session_key
@require_admin
def delete_backup():
    data = request.get_json() or {}
    filename = data.get('filename')

    if not filename:
        return jsonify({'error': 'Missing filename'}), 400

    # Sanitize: remove path traversal risk
    if '/' in filename or '\\' in filename:
        return jsonify({'error': 'Invalid filename'}), 400

    full_path = os.path.join(BACKUP_DIR, filename)

    if not os.path.isfile(full_path):
        return jsonify({'error': 'Backup file not found'}), 404

    try:
        os.remove(full_path)
    except Exception as e:
        return jsonify({'error': f'Failed to delete file: {e}'}), 500

    return jsonify({'message': 'Backup deleted successfully'}), 200


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
    # GitHub API configuration
    GITHUB_REPO_OWNER = "BosbesplaysYT" 
    GITHUB_REPO_NAME = "python_31"
    try:
        load_secrets()
    except Exception as e:
        app.logger.error("Failed to load secrets: %s", str(e))
        return jsonify({"error": "Failed to load GitHub secrets", "details": str(e)}), 500
    GITHUB_TOKEN = app.config["GITHUB_PERSONAL_ACCESS_TOKEN"]
    HEADERS = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Step 1: Get default branch
    try:
        repo_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}"
        response = requests.get(repo_url, headers=HEADERS)
        if response.status_code != 200:
            app.logger.error("Failed to get repo info: %s", response.text)
            return jsonify({"error": "Failed to get repository information", 
                           "details": response.text}), 500
        default_branch = response.json()["default_branch"]
    except Exception as e:
        app.logger.error("Error getting default branch: %s", str(e))
        return jsonify({"error": "Error getting default branch", 
                       "details": str(e)}), 500

    # Step 2: Create pull request
    try:
        pr_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls"
        pr_data = {
            "title": "Automatic PR: Merge dev into production",
            "head": "dev",
            "base": default_branch,
            "body": "Automatically generated PR to merge development changes"
        }
        response = requests.post(pr_url, headers=HEADERS, json=pr_data)
        if response.status_code != 201:
            app.logger.error("PR creation failed: %s", response.text)
            return jsonify({"error": "PR creation failed", 
                           "details": response.text}), 500
        pr_number = response.json()["number"]
    except Exception as e:
        app.logger.error("Error creating PR: %s", str(e))
        return jsonify({"error": "PR creation error", 
                       "details": str(e)}), 500

    # Step 3: Merge the pull request
    try:
        merge_url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls/{pr_number}/merge"
        response = requests.put(merge_url, headers=HEADERS)
        if response.status_code != 200:
            app.logger.error("Merge failed: %s", response.text)
            return jsonify({"error": "Merge failed", 
                           "details": response.text}), 500
    except Exception as e:
        app.logger.error("Error merging PR: %s", str(e))
        return jsonify({"error": "Merge error", 
                       "details": str(e)}), 500

    return jsonify({
        "status": "Pull request created and merged successfully",
        "pr_number": pr_number,
        "merge_sha": response.json().get("sha")
    })


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

    data = request.get_json() or {}
    target_user_id = data.get("user_id")
    if not target_user_id:
        return jsonify({"error": "User ID is required"}), 400

    target_user = User.query.get(target_user_id)
    if not target_user:
        return jsonify({"error": "Target user not found"}), 404
    if target_user.suspended:
        return jsonify({"error": "Cannot log in as a suspended user"}), 403

    # Generate a fresh session_key for the impersonated user
    new_key = generate_session_key(target_user.id)

    payload = {
        "message":   target_user.username,
        "user_id":   target_user.id,
        "startpage": target_user.startpage,
        # lasting_key remains unchanged in the cookie, so no need to reissue here
    }
    resp = make_response(jsonify(payload), 200)
    # set the new session_key cookie
    resp.set_cookie(
        "session_key", new_key,
        httponly=True, secure=True, samesite="Strict",
        max_age=60*60*24
    )
    return resp

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

# app.py
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user_ip = request.remote_addr

    cleanup_expired_signup_sessions()

    # IP-ban check remains unchanged
    banned_ip = IpAddres.query.join(User)\
        .filter(IpAddres.ip == user_ip, User.suspended.is_(True))\
        .first()
    if banned_ip:
        return jsonify({"error": "Please get unbanned first!"}), 403

    # Check username availability
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already exists"}), 400

    # Create signup session
    session_id = str(uuid.uuid4())
    signup_session = SignupSession(
        id=session_id,
        username=data['username'],
        hashed_password=hashed_password,
        user_ip=user_ip
    )
    db.session.add(signup_session)
    db.session.commit()

    resp = jsonify({"redirect": "/signup/email"})
    resp.set_cookie(
        "signup_session", session_id,
        httponly=True, secure=True, samesite="Strict",
        max_age=60*60  # 1 hour expiration
    )
    return resp

# Helper function to create user from signup session
def create_user_from_signup_session(signup_session, skip_email=False):
    """Core logic to create user from signup session"""
    try:
        # Create user
        user = User(
            username=signup_session.username,
            password=signup_session.hashed_password,
            email=None if skip_email else signup_session.email
        )
        user.lasting_key = secrets.token_hex(32)
        db.session.add(user)
        db.session.commit()

        # Record IP
        ip_record = IpAddres(user_id=user.id, ip=signup_session.user_ip)
        db.session.add(ip_record)
        db.session.commit()

        # Create session key
        session_key = generate_session_key(user.id)
        
        # Initialize user resources
        create_default_calendar(user.id)
        ensure_user_colors(user.id)
        
        # Send welcome notification
        send_notification(
            user.id, "Welcome!",
            "Thank you for creating an account on Future Notes! Click for a quick guide.",
            "/guide_page"
        )
        
        return {
            "session_key": session_key,
            "lasting_key": user.lasting_key,
            "user_id": user.id
        }
    except IntegrityError:
        db.session.rollback()
        raise Exception("Account creation failed (username might be taken)")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Signup error: {str(e)}")
        raise Exception("Account creation failed")

# Email verification endpoint
@app.route('/signup/verify_email')
def verify_email_via_link():
    """Endpoint for email verification link"""
    code = request.args.get('code')
    email = request.args.get('email')
    
    if not code or not email:
        # Render error page for missing parameters
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Missing Verification Parameters</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 40px; background-color:#2c2c2c; }}
                .error {{ color: #e67e22; font-size: 24px; }}
                .loader {{
                    width: 50px;
                    height: 50px;
                    border: 5px solid #f3f3f3;
                    border-top: 5px solid #e67e22;
                    border-radius: 50%;
                    margin: 20px auto;
                    animation: spin 1s linear infinite;
                }}
                p {{
                    color: white;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
            </style>
        </head>
        <body>
            <div class="error">✗ Missing verification parameters.</div>
            <div class="loader"></div>
            <p>Please use the verification link sent to your email or try signing up again.</p>
            <p><a href="/signup_page">Go back to signup</a></p>
        </body>
        </html>
        """, 400

    # Find matching signup session
    signup_session = SignupSession.query.filter_by(
        email=email,
        verification_code=code
    ).first()

    if not signup_session:
        # Render error page for invalid/expired link
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Invalid or Expired Link</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 40px; background-color: #2c2c2c; }}
                .error {{ color: #e74c3c; font-size: 24px; }}
                .loader {{
                    width: 50px;
                    height: 50px;
                    border: 5px solid #f3f3f3;
                    border-top: 5px solid #e74c3c;
                    border-radius: 50%;
                    margin: 20px auto;
                    animation: spin 1s linear infinite;
                }}
                p {{
                    color: white;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
            </style>
        </head>
        <body>
            <div class="error">✗ This verification link is invalid or has expired.</div>
            <div class="loader"></div>
            <p>Please request a new verification email or try signing up again.</p>
            <p><a href="/signup_page">Go back to signup</a></p>
        </body>
        </html>
        """, 400

    # Render success page with auto-redirect
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Verified</title>
        <meta http-equiv="refresh" content="5;url=/signup/complete_verification?code={code}">
        <style>
            body {{ font-family: Arial, sans-serif; text-align: center; padding: 40px; background-color:#2c2c2c;}}
            .success {{ color: #2ecc71; font-size: 24px; }}
            .loader {{ 
                width: 50px; 
                height: 50px;
                border: 5px solid #f3f3f3;
                border-top: 5px solid #3498db;
                border-radius: 50%;
                margin: 20px auto;
                animation: spin 1s linear infinite;
            }}
            p {{
                color: white;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
        </style>
    </head>
    <body>
        <div class="success">✓ Email verified successfully!</div>
        <div class="loader"></div>
        <p>Redirecting to your account...</p>
        <p><a href="/signup/complete_verification?code={code}">Click here if not redirected</a></p>
    </body>
    </html>
    """

# Verification completion endpoint
@app.route('/signup/complete_verification')
def complete_email_verification():
    """Finalize verification from link click"""
    code = request.args.get('code')
    
    if not code:
        return "Missing verification code", 400

    # Find session by code
    signup_session = SignupSession.query.filter_by(
        verification_code=code
    ).first()

    if not signup_session:
        return "Invalid verification code", 400

    # Complete the signup process
    return complete_signup_internal(signup_session)

# Shared signup completion logic
def complete_signup_internal(signup_session):
    """Shared signup completion logic"""
    try:
        # Create user and get session data
        skip_email = False if signup_session.email else True
        user_data = create_user_from_signup_session(signup_session, skip_email)
        
        # Clean up session
        db.session.delete(signup_session)
        db.session.commit()
        
        # Prepare response
        resp = redirect("/index")
        resp.set_cookie(
            "session_key", user_data['session_key'],
            httponly=True, secure=True, samesite="Strict",
            max_age=60*60*24  # 1 day
        )
        resp.set_cookie(
            "lasting_key", user_data['lasting_key'],
            httponly=True, secure=True, samesite="Strict",
            max_age=60*60*24*30  # 30 days
        )
        resp.delete_cookie("signup_session")
        return resp
        
    except Exception as e:
        app.logger.error(f"Signup completion failed: {str(e)}")
        return "Account creation failed. Please try signing up again.", 500

# Updated email sending endpoint
@app.route('/signup/send_verification', methods=['POST'])
def send_verification_email():
    data = request.get_json()
    session_id = request.cookies.get('signup_session')
    if not session_id:
        return jsonify({"error": "Session expired"}), 400
        
    signup_session = SignupSession.query.get(session_id)
    if not signup_session:
        return jsonify({"error": "Invalid session"}), 400

    # Validate email
    email = data.get('email', '').strip()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400

    # Generate and store verification code
    code = ''.join(random.choices('0123456789', k=6))
    signup_session.email = email
    signup_session.verification_code = code
    db.session.commit()

    # Build verification URL
    # Dynamically determine the site URL based on the request
    site_url = f"{request.scheme}://{request.host}"
    verify_url = f"{site_url}/signup/verify_email?code={code}&email={urllib.parse.quote(email)}"
    
    # Send email with button
    try:
        send_email(
            to_address=email,
            subject="Future Notes - Email Verification",
            content_html=f"""
                <p>Please verify your email address to complete your registration.</p>
                <p>Click the button below or use this code: <strong>{code}</strong></p>
                <p><small>Can't see the button? <a href="{verify_url}">Click here</a></small></p>
            """,
            buttons=[{
                'text': 'Verify Email',
                'href': verify_url,
                'color': '#424242'
            }],
            logo_url=app.config['LOGO_URL'],
            unsubscribe_url="#"
        )
        return jsonify({"message": "Verification email sent"}), 200
    except Exception as e:
        app.logger.error(f"Email send failed: {str(e)}")
        return jsonify({"error": "Failed to send verification email"}), 500

# Updated signup completion endpoint
@app.route('/signup/complete', methods=['POST'])
def complete_signup():
    """Original form-based signup completion"""
    session_id = request.cookies.get('signup_session')
    if not session_id:
        # Try to find by verification code
        verification_code = request.json.get('verification_code')
        if verification_code:
            signup_session = SignupSession.query.filter_by(
                verification_code=verification_code
            ).first()
            if signup_session:
                return complete_signup_internal(signup_session)
        return jsonify({"error": "Session expired"}), 400
        
    signup_session = SignupSession.query.get(session_id)
    if not signup_session:
        return jsonify({"error": "Invalid session"}), 400

    data = request.get_json()
    skip_email = data.get('skip_email', False)
    verification_code = data.get('verification_code', '')

    # Verify code if email was added
    if not skip_email:
        if not verification_code:
            return jsonify({"error": "Verification code required"}), 400
        if verification_code != signup_session.verification_code:
            return jsonify({"error": "Invalid verification code"}), 400

    try:
        # Create user and get session data
        user_data = create_user_from_signup_session(signup_session, skip_email)
        
        # Clean up session
        db.session.delete(signup_session)
        db.session.commit()
        
        # Prepare response
        payload = {
            "message": "Account created successfully!",
            "session_key": user_data['session_key'],
            "user_id": user_data['user_id'],
            "lasting_key": user_data['lasting_key']
        }
        resp = jsonify(payload)
        
        # Set cookies
        resp.set_cookie(
            "session_key", user_data['session_key'],
            httponly=True, secure=True, samesite="Strict",
            max_age=60*60*24  # 1 day
        )
        resp.set_cookie(
            "lasting_key", user_data['lasting_key'],
            httponly=True, secure=True, samesite="Strict",
            max_age=60*60*24*30  # 30 days
        )
        resp.delete_cookie("signup_session")
        return resp

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Signup completion failed: {str(e)}")
        return jsonify({"error": "Account creation failed"}), 500
    
# Password reset request endpoint
@app.route('/reset_password_request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    
    # Validate input
    if not username or not email:
        return jsonify({'error': 'Username and email are required'}), 400
    
    # Find user
    user = User.query.filter_by(username=username).first()
    if not user:
        # For security, don't reveal if username exists
        return jsonify({'message': 'If the username exists and email matches, a reset link will be sent'}), 200
    
    # Check if user has an email
    if not user.email:
        return jsonify({'error': 'This account has no email associated'}), 400
    
    # Verify email matches
    if user.email.lower() != email:
        return jsonify({'error': 'Email does not match the username'}), 400
    
    # Create reset token
    reset_token = PasswordResetToken(user_id=user.id)
    db.session.add(reset_token)
    db.session.commit()
    
    # Build reset URL
    site_url = f"{request.scheme}://{request.host}"
    # Updated email sending (in reset_password_request)
    reset_url = f"{site_url}/reset_password?token={reset_token.token}"
    
    # Send password reset email
    try:
        send_email(
            to_address=user.email,
            subject="Future Notes - Password Reset Request",
            content_html=f"""
                <p>We received a password reset request for your Future Notes account.</p>
                <p>Click the button below to reset your password:</p>
                <p><small>If you didn't request this, your account may be at risk. We strongly suggest changing your password</small></p>
            """,
            buttons=[{
                'text': 'Reset Password',
                'href': reset_url,
                'color': '#424242'
            }],
            logo_url=app.config['LOGO_URL'],
            unsubscribe_url="#"
        )
        return jsonify({'message': 'Password reset email sent if account exists'}), 200
    except Exception as e:
        app.logger.error(f"Password reset email failed: {str(e)}")
        return jsonify({'error': 'Failed to send reset email'}), 500

# Password reset validation endpoint
# New endpoint: Token validation and redirection
@app.route('/reset_password', methods=['GET'])
def reset_password_redirect():
    token = request.args.get('token')
    if not token:
        return jsonify({'error': 'Token is required'}), 400
    
    # Validate token
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if not reset_token:
        return jsonify({'error': 'Invalid token'}), 400
    if reset_token.used:
        return jsonify({'error': 'Token already used'}), 400
    if datetime.utcnow() > reset_token.expires_at:
        return jsonify({'error': 'Token expired'}), 400
    
    # Redirect to form with token
    return render_template("reset_password.html")


# Step 2: Modify the reset_password endpoint
@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400
    
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if not reset_token:
        return jsonify({'error': 'Invalid token'}), 400
    if reset_token.used:
        return jsonify({'error': 'Token already used'}), 400
    if datetime.utcnow() > reset_token.expires_at:
        return jsonify({'error': 'Token expired'}), 400
    
    user = User.query.get(reset_token.user_id)
    
    # Save old password before resetting
    old_password_hash = user.password
    
    # Set new password
    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    
    # Generate new tokens for session
    user.lasting_key = secrets.token_hex(32)  # Invalidate old sessions
    session_key = generate_session_key(user.id)  # Generate new session key
    
    # Record IP address if new
    user_ip = request.remote_addr
    if not IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first():
        db.session.add(IpAddres(user_id=user.id, ip=user_ip))
    
    # Mark reset token as used
    reset_token.used = True
    
    # Create undo token (valid for 3 days)
    undo_token = ResetUndoToken(
        user_id=user.id,
        token=secrets.token_urlsafe(32),
        old_password_hash=old_password_hash,
        expires_at=datetime.utcnow() + timedelta(days=3)
    )
    db.session.add(undo_token)
    
    db.session.commit()
    
    # Build undo URL
    site_url = f"{request.scheme}://{request.host}"
    undo_url = f"{site_url}/undo_reset?token={undo_token.token}"
    
    # Send confirmation email with undo link
    try:
        send_email(
            to_address=user.email,
            subject="Future Notes - Password Reset Confirmation",
            content_html=f"""
                <p>Your password was successfully reset.</p>
                <p>If you didn't request this change, you can undo it within 3 days:</p>
            """,
            buttons=[{
                'text': 'Undo Password Reset',
                'href': undo_url,
                'color': '#ff0000'
            }],
            logo_url=app.config['LOGO_URL'],
            unsubscribe_url="#"
        )
    except Exception as e:
        app.logger.error(f"Password reset confirmation email failed: {str(e)}")
    
    # Prepare login response
    payload = {
        "message": "Password reset successfully and logged in",
        "session_key": session_key,
        "user_id": user.id,
        "startpage": user.startpage,
        "lasting_key": user.lasting_key
    }
    
    resp = make_response(jsonify(payload), 200)
    resp.set_cookie(
        "session_key", session_key,
        httponly=True, secure=True, samesite="Strict",
        max_age=60*60*24
    )
    resp.set_cookie(
        "lasting_key", user.lasting_key,
        httponly=True, secure=True, samesite="Strict",
        max_age=60*60*24*30
    )
    return resp

# Step 3: Add undo reset endpoint
@app.route('/undo_reset', methods=['GET'])
def undo_reset():
    token = request.args.get('token')
    if not token:
        return jsonify({'error': 'Token is required'}), 400
    
    undo_token = ResetUndoToken.query.filter_by(token=token, used=False).first()
    if not undo_token:
        return jsonify({'error': 'Invalid token'}), 400
    if undo_token.used:
        return jsonify({'error': 'Token already used'}), 400
    if datetime.utcnow() > undo_token.expires_at:
        return jsonify({'error': 'Token expired'}), 400
    
    user = User.query.get(undo_token.user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Restore old password
    user.password = undo_token.old_password_hash
    
    # Mark undo token as used
    undo_token.used = True
    
    db.session.commit()

    # Render success page with auto-redirect
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Password Reset Reverted</title>
        <meta http-equiv="refresh" content="5;url=/login_page">
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 40px; background-color:#2c2c2c;}
            .success { color: #2ecc71; font-size: 24px; }
            .loader { 
                width: 50px; 
                height: 50px;
                border: 5px solid #f3f3f3;
                border-top: 5px solid #3498db;
                border-radius: 50%;
                margin: 20px auto;
                animation: spin 1s linear infinite;
            }
            p {
                color: white;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="success">✓ Password reset reverted successfully!</div>
        <div class="loader"></div>
        <p>Redirecting to login...</p>
        <p><a href="/login_page">Click here if not redirected</a></p>
    </body>
    </html>
    """

    resp = make_response(html)

    resp.delete_cookie("lasting_key")
    resp.delete_cookie("session_key")
    return resp


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    # 1) lasting_key: either in JSON body or in cookie
    lk = request.cookies.get('lasting_key')
    if lk:
        user = User.query.filter_by(lasting_key=lk).first()
        if not user:
            resp = make_response(jsonify({"error": "Invalid lasting key!"}), 401)
            resp.delete_cookie("lasting_key")
            return resp
        if user.suspended:
            resp = make_response(jsonify({"error": "You are suspended!"}), 403)
            resp.delete_cookie("lasting_key")
            resp.delete_cookie("session_key")
            return resp

        # OK, issue new session_key
        session_key = generate_session_key(user.id)
        # persist any new IP
        user_ip = request.remote_addr
        if not IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first():
            db.session.add(IpAddres(user_id=user.id, ip=user_ip))
            db.session.commit()

        payload = {
            "message":   "Login successful!",
            "session_key": session_key,
            "user_id":     user.id,
            "lasting_key": user.lasting_key,
            "startpage":   user.startpage
        }
        resp = make_response(jsonify(payload), 200)
        resp.set_cookie(
            "session_key", session_key,
            httponly=True, secure=True, samesite="Strict",
            max_age=60*60*24
        )
        # already have lasting_key cookie set on signup; refresh its expiration
        resp.set_cookie(
            "lasting_key", user.lasting_key,
            httponly=True, secure=True, samesite="Strict",
            max_age=60*60*24*30
        )
        return resp

    # 2) username/password
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 400
    if user.suspended:
        return jsonify({"error": "Account is suspended"}), 403

    session_key = generate_session_key(user.id)
    # record IP
    user_ip = request.remote_addr
    if not IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first():
        db.session.add(IpAddres(user_id=user.id, ip=user_ip))
        db.session.commit()

    payload = {
        "message":     "Login successful!",
        "session_key": session_key,
        "user_id":     user.id,
        "startpage":   user.startpage
    }
    # only include lasting_key in JSON if they asked to keep me logged in
    if data.get('keep_login'):
        if not user.lasting_key:
            user.lasting_key = secrets.token_hex(32)
            db.session.commit()
        payload["lasting_key"] = user.lasting_key

    resp = make_response(jsonify(payload), 200)
    resp.set_cookie(
        "session_key", session_key,
        httponly=True, secure=True, samesite="Strict",
        max_age=60*60*24
    )
    if data.get('keep_login'):
        resp.set_cookie(
            "lasting_key", user.lasting_key,
            httponly=True, secure=True, samesite="Strict",
            max_age=60*60*24*30
        )
    return resp


@app.route('/logout', methods=['POST'])
@require_session_key
def logout():
    # delete from server‐side session_keys store
    auth_key = request.cookies.get("session_key")
    session_keys.pop(auth_key, None)

    resp = make_response(jsonify({"message": "Logged out successfully!"}), 200)
    resp.delete_cookie("session_key")
    resp.delete_cookie("lasting_key")
    return resp

@app.route('/test-session', methods=['GET'])
@require_session_key
def test_session():
    return jsonify({"message": "Session is valid!", "user_id": g.user_id}), 200

@app.route('/password-eisen', methods=['GET'])
def password_eisen():
    if check("wachtwoord_eisen", "Ja") == "Ja":
        return jsonify({"enabled": True})  # Return as JSON
    else:
        return jsonify({"enabled": False})  # Return as JSON

# Personal notes

@app.route('/notes', methods=['GET', 'POST'])
@require_session_key
def manage_notes():
    if request.method == 'POST':
        data = request.json
        note_html = data['note']
        
        # Sanitize HTML - IMPORTANT for security
        note_html = sanitize_html(note_html)
        
        new_note = Note(
            user_id=g.user_id, 
            title=data.get('title'), 
            note=note_html,  # Store HTML with checkboxes
            tag=data.get('tag')
        )
        db.session.add(new_note)
        db.session.commit()
        return jsonify({"message": "Note added successfully!"}), 201
    else:
        notes = Note.query.filter_by(user_id=g.user_id).all()
        sanitized_notes = [{"id": note.id, "title": note.title, "note": note.note, "tag": note.tag} for note in notes]
        return jsonify(sanitized_notes)
    
    # GET handling remains the same

# Update sanitize_html function
def sanitize_html(html):
    # Allow checkbox lists and attributes
    allowed_tags = [
        'div', 'span', 'p', 'br', 'b', 'i', 'u', 'strong', 'em', 
        'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'input'
    ]
    
    allowed_attributes = {
        'input': ['type', 'class', 'checked'],
        'div': ['class'],
        'span': ['class'],
        'ul': ['class'],
        'li': ['class']
    }
    
    return bleach.clean(
        html, 
        tags=allowed_tags, 
        attributes=allowed_attributes,
        strip=True
    )

@app.route('/notes/<int:note_id>', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_note(note_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != g.user_id:
        return jsonify({"error": "Note not found"}), 404

    if request.method == 'PUT':
        data = request.json
        # Added sanitization to match POST logic
        note.title = data.get('title')
        note.note = sanitize_html(data['note'])  # Now sanitizes updates
        note.tag = data.get('tag')
        db.session.commit() 
        return jsonify({"message": "Note updated successfully!"}), 200
    elif request.method == 'DELETE':
        db.session.delete(note)
        db.session.commit()
        return jsonify({"message": "Note deleted successfully!"}), 200
    
@app.route('/draft', methods=['POST', 'GET', 'DELETE'])
@require_session_key
def handle_draft():
    group_uuid = request.args.get('group_uuid')
    
    # Always include group_uuid in filter (set to None for personal drafts)
    filter_criteria = {
        'user_id': g.user_id,
        'group_uuid': group_uuid if group_uuid else None
    }
    
    if request.method == 'POST':
        return save_draft(filter_criteria)
    elif request.method == 'GET':
        return get_draft(filter_criteria)
    elif request.method == 'DELETE':
        return clear_draft(filter_criteria)

# The rest of the functions remain unchanged

def save_draft(filter_criteria):
    data = request.get_json()
    draft = Draft.query.filter_by(**filter_criteria).first()
    
    if not draft:
        draft = Draft(
            user_id=g.user_id,
            group_uuid=filter_criteria.get('group_uuid'),
            title=data.get('title'),
            content=data.get('content'),
            tag=data.get('tag')
        )
        db.session.add(draft)
    else:
        draft.title = data.get('title')
        draft.content = data.get('content')
        draft.tag = data.get('tag')
    
    db.session.commit()
    return jsonify(success=True)

def get_draft(filter_criteria):
    draft = Draft.query.filter_by(**filter_criteria).first()
    if draft:
        return jsonify({
            'title': draft.title,
            'content': draft.content,
            'tag': draft.tag
        })
    return jsonify(None)

def clear_draft(filter_criteria):
    draft = Draft.query.filter_by(**filter_criteria).first()
    if draft:
        db.session.delete(draft)
        db.session.commit()
    return jsonify(success=True)
    
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
    app.run(debug=True, host='0.0.0.0')