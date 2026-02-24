# ------------------------------Imports--------------------------------
from flask import Flask, request, jsonify, g, render_template, make_response, session, send_from_directory, current_app, abort, redirect, url_for, send_file
from flask_compress import Compress
from flask.json.provider import DefaultJSONProvider
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, desc, event, text, MetaData, select, func, or_
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
from datetime import timezone, datetime, timedelta
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
from urllib.parse import quote_plus
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
from googleapiclient.errors import HttpError
import requests
import cohere
# verify_file_content.py
from file_check import verify_file_content_hardened
import io
import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
import base64
from collections import deque
import difflib
import dropbox
from dropbox.exceptions import ApiError
try:
    from dotenv import load_dotenv
except ImportError:
    pass
from mega import Mega
import ast
from pathlib import Path
from dateutil import parser as dtparser
import pytz
from zoneinfo import ZoneInfo
# ------------------------------Global variables--------------------------------
class CustomJSONProvider(DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        # fall back to the built‑in handlers
        return super().default(obj)
app = Flask(__name__)
CORS(app)
Compress(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': NullPool
}
def load_secrets():
    with app.app_context():
        secrets = AppSecret.query.all()
        for secret in secrets:
            app.config[secret.key] = secret.value

def is_pythonanywhere():
    home_dir = os.path.expanduser("~")
    return home_dir.startswith("/home/")

if not is_pythonanywhere():
    # Only load .env locally
    load_dotenv()
    print("Loaded .env for local development")
else:
    print("Detected PythonAnywhere, skipping .env")

# ---- Helpers ----
UTC = pytz.UTC

app.config['VAPID_PRIVATE_KEY'] = os.getenv("VAPID_PRIVATE_KEY")
app.config['ADMIN_EMAIL'] = os.getenv("ADMIN_EMAIL")
app.config['COHERE_API_KEY'] = os.getenv("COHERE_API_KEY")
app.config["TWOFA_FERNET_KEY"] = os.getenv("TWOFA_FERNET_KEY")
app.config['GMAIL_APP_PASSWORD'] = os.getenv("GMAIL_APP_PASSWORD")
CRONJOB_API_KEY = os.environ.get("CRONJOB_ORG_API_KEY")
app.config['VAPID_PUBLIC_KEY'] = 'BGcLDjMs3BA--QdukrxV24URwXLHYyptr6TZLR-j79YUfDDlN8nohDeErLxX08i86khPPCz153Ygc3DrC7w1ZJk'
app.config['GOOGLE_CLIENT_ID'] = os.getenv("GOOGLE_CLIENT_ID")
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv("GOOGLE_CLIENT_SECRET")
app.config['GITHUB_PERSONAL_ACCESS_TOKEN'] = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
app.config['MEGA_EMAIL'] = os.getenv("MEGA_EMAIL")
app.config['MEGA_PASSWORD'] = os.getenv("MEGA_PASSWORD")
app.config['VAPID_CLAIMS'] = {
    'sub': 'https://bosbes.eu.pythonanywhere.com'
}
MAX_NOTE_LENGTH = 3000
COHERE_API_KEY = app.config["COHERE_API_KEY"]
_TIME_EPS = timedelta(seconds=1)
# Temporary in-memory stores (for demo). Replace with Redis for production.
login_tokens = {}        # login_token -> {user_id, expires_at, ip}
pending_twofa = {}       # user_id -> {secret, created_at}
login_2fa_attempts = {}  # login_token -> attempts
# how long to consider a visit "the same visitor" (in seconds)
SHARE_VISIT_WINDOW_SECONDS = 30 * 60  # 30 minutes — change as you like
# Fernet key for encrypting TOTP secrets (store in env var)
TWOFA_FERNET_KEY = app.config["TWOFA_FERNET_KEY"]
if TWOFA_FERNET_KEY:
    fernet = Fernet(TWOFA_FERNET_KEY)
else:
    fernet = None  # fall back to plain storage (not recommended)
dbx = dropbox.Dropbox(
    oauth2_refresh_token=os.getenv("DROPBOX_REFRESH_TOKEN"),
    app_key=os.getenv("DROPBOX_APP_KEY"),
    app_secret=os.getenv("DROPBOX_APP_SECRET"),
)
mega_client = Mega()
mega_account = mega_client.login(app.config['MEGA_EMAIL'], app.config["MEGA_PASSWORD"])
DROPBOX_UPLOAD_FOLDER = "/uploads"  # root folder in Dropbox
REQUIRE_2FA_ALWAYS = False
REQUIRE_2FA_ON_NEW_IP = True
RANDOM_REQUIRE_2FA = True

co = cohere.ClientV2(COHERE_API_KEY)
# Jinja setup (point at your templates/)
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_PATH),
    autoescape=select_autoescape(['html', 'xml'])
)
app.config['LOGO_URL'] = 'https://bosbes.eu.pythonanywhere.com/static/android-chrome-512x512.png'
app.config['GMAIL_USER'] = 'noreplyfuturenotes@gmail.com'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Disables HTTPS check
GITHUB_REPO_OWNER = "BosbesplaysYT" 
GITHUB_REPO_NAME = "python_31"
MAX_UPLOAD_SIZE_BYTES = 30 * 1024 * 1024  # 5 MB default (changeable)
# Allowed extensions and mimetypes
ALLOWED_EXTENSIONS = {
    # Images
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'svg', 'ico',

    # Documents
    'txt', 'md', 'pdf', 'doc', 'docx', 'odt', 'rtf',
    'xls', 'xlsx', 'ods', 'csv', 'ppt', 'pptx', 'odp',

    # Archives
    'zip', 'tar', 'gz', '7z', 'rar',

    # Code / scripts (if safe for your app)
    'py', 'js', 'html', 'css', 'json', 'xml', 'yml', 'yaml',

    # Audio / video (if needed)
    'mp3', 'wav', 'ogg', 'mp4', 'mov', 'avi', 'webm', 'mkv'
}
ALLOWED_MIMETYPES = {
    # Images
    'image/png', 'image/jpeg', 'image/gif', 'image/webp',

    # Text / documents
    'text/plain',
    'application/pdf',
    'application/msword',  # .doc
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx
    'application/vnd.ms-excel',  # .xls
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',  # .xlsx
    'application/vnd.ms-powerpoint',  # .ppt
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',  # .pptx

    # Archives
    'application/zip', 'application/x-zip-compressed',

    # optional fallback
    'application/octet-stream',
}
app.json_provider_class = CustomJSONProvider
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
UPLOAD_FOLDER_PROFILE_PICS = 'static/uploads/profile_pictures'
UPLOAD_FOLDER_LOCAL_FILES = 'static/uploads/files'
app.config['UPLOAD_FOLDER_PROFILE_PICTURES'] = UPLOAD_FOLDER_PROFILE_PICS
app.config['UPLOAD_FOLDER_LOCAL_FILES'] = UPLOAD_FOLDER_LOCAL_FILES
if not os.path.exists(UPLOAD_FOLDER_PROFILE_PICS):
    os.makedirs(UPLOAD_FOLDER_PROFILE_PICS)
if not os.path.exists(UPLOAD_FOLDER_LOCAL_FILES):
    os.makedirs(UPLOAD_FOLDER_LOCAL_FILES)
app.config['SECRET_KEY'] = os.urandom(24)
# Token serializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
TOKEN_EXPIRATION = 3600  # seconds (1 hour)
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
PRIME = 7919  # arbitrary prime number
SALT = os.getenv("DEPLOY_SECRET")
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

class NoteUpload(db.Model):
    __tablename__ = 'note_uploads'
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'), nullable=False)

class BoardBackgroundUpload(db.Model):
    __tablename__ = 'board_background_uploads'
    id = db.Column(db.Integer, primary_key=True)
    board_id = db.Column(db.Integer, db.ForeignKey('board.id'), nullable=False)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    board = db.relationship('Board', backref=db.backref('background_upload', uselist=False))
    upload = db.relationship('Upload')

class CardBackgroundUpload(db.Model):
    __tablename__ = 'card_background_uploads'
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, db.ForeignKey('card.id'), nullable=False)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    card = db.relationship('Card', backref=db.backref('background_upload', uselist=False))
    upload = db.relationship('Upload')

class Upload(db.Model):
    __tablename__ = 'uploads'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original_filename = db.Column(db.String(512), nullable=False)
    stored_filename = db.Column(db.String(512), nullable=False)  # actual filename on disk
    storage_backend = db.Column(db.String(50), default="local")  # "dropbox" or "local"
    mimetype = db.Column(db.String(128))
    size_bytes = db.Column(db.Integer, nullable=False)
    deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deleted_at = db.Column(db.DateTime, nullable=True)
    mega_file_obj = db.Column(JSON, nullable=True)

    user = db.relationship('User', backref=db.backref('uploads', lazy='dynamic'))

class AppSecret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(256), nullable=False)

class Version(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    git_tag = db.Column(db.String(50), nullable=False)
    commit_sha = db.Column(db.String(40), nullable=False)
    is_production = db.Column(db.Boolean, default=False)

class Article(db.Model):
    __tablename__ = 'articles'
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(255), unique=True, nullable=False, index=True)  # url-friendly
    title = db.Column(db.String(255), nullable=False)                        # shown on homepage
    category = db.Column(db.String(128), nullable=True)                      # optional
    content = db.Column(db.Text, nullable=False)                             # full markdown content
    excerpt = db.Column(db.String(512), nullable=True)                       # short summary
    tags_json = db.Column(db.Text, nullable=True)                            # JSON list of tags
    published = db.Column(db.Boolean, default=True, nullable=False)          # published or draft
    author = db.Column(db.String(128), nullable=True)                        # last editor/author
    view_count = db.Column(db.Integer, default=0, nullable=False)            # views
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_edited_by = db.Column(db.String(128), nullable=True)

    def tags(self):
        try:
            return json.loads(self.tags_json) if self.tags_json else []
        except Exception:
            return []

    def to_dict(self, full=False):
        base = {
            "id": self.id,
            "slug": self.slug,
            "title": self.title,
            "category": self.category,
            "excerpt": self.excerpt,
            "tags": self.tags(),
            "published": self.published,
            "author": self.author,
            "view_count": self.view_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_edited_by": self.last_edited_by
        }
        if full:
            base["content"] = self.content
        return base

# -------------------------
# DB helper
# -------------------------
def slugify(s):
    s = s.lower().strip()
    s = re.sub(r'[^a-z0-9\s-]', '', s)
    s = re.sub(r'\s+', '-', s)
    s = re.sub(r'-+', '-', s)
    return s[:200]

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
    has_username_protection = db.Column(db.Boolean, default=False, nullable=False)
    has_unlimited_storage = db.Column(db.Boolean, default=False, nullable=False)
    malicious_violations = db.Column(db.Integer, nullable=True)

    # 2FA fields
    twofa_enabled = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.Text, nullable=True)  # encrypted string
    # hashed backup codes (optional)
    backup_codes_hash = db.Column(db.Text, nullable=True)

    base_storage_mb = db.Column(db.Integer, default=10)  # default 10 MB, adjust as you like
    storage_used_bytes = db.Column(db.BigInteger, default=0)  # tracks current usage
    
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

class Board(db.Model):
    __tablename__ = "board"  # top-level collection of lists
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), index=True, nullable=False)
    background_color = db.Column(db.String(7), nullable=False, default="#2c2c2c")
    title = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("boards", lazy="dynamic"))


class List(db.Model):
    __tablename__ = "list"  # formerly called 'board'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), index=True, nullable=False)
    board_id = db.Column(db.Integer, db.ForeignKey("board.id", ondelete="CASCADE"), index=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ordernr = db.Column(db.Integer, nullable=False, default=0)
    background_color = db.Column(db.String(7), nullable=True, default=None)  # New field for list background color

    board = db.relationship("Board", backref=db.backref("lists", lazy="dynamic"))
    user = db.relationship("User", backref=db.backref("lists", lazy="dynamic"))


class Card(db.Model):
    __tablename__ = "card"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), index=True, nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey("list.id", ondelete="CASCADE"), index=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    position = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed = db.Column(db.Boolean, default=False)
    background_color = db.Column(db.String(7), nullable=True, default=None)  # New field for list background color

    list = db.relationship("List", backref=db.backref("cards", lazy="dynamic"))

class CardActivity(db.Model):
    __tablename__ = "card_activity"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, db.ForeignKey("card.id", ondelete="CASCADE"), index=True, nullable=False)
    activity_type = db.Column(db.String(25), nullable=False)  # this is user or activity, indicating wether it is a manually added comment or an automatic activity log
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), index=True, nullable=True)

    card = db.relationship("Card", backref=db.backref("activities", lazy="dynamic"))

class InviteReferral(db.Model):
    __tablename__ = "invite_referral"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invited_email = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    claimed = db.Column(db.Boolean, default=False, nullable=False)
    claimed_at = db.Column(db.DateTime, nullable=True)
    claimed_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    inviter = db.relationship("User", foreign_keys=[inviter_id], backref="outgoing_invites")
    claimed_user = db.relationship("User", foreign_keys=[claimed_user_id])

class ReferralSession(db.Model):
    __tablename__ = "referral_session"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # >>> correct FK target: invite_referral.id (not invite.id)
    invite_id = db.Column(db.String(36), db.ForeignKey('invite_referral.id'), nullable=False)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invited_email = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # relationship points to InviteReferral
    invite = db.relationship("InviteReferral", backref="referral_sessions")
    inviter = db.relationship("User", backref="referral_sessions")

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
    # Use timezone=True where supported
    start_datetime = db.Column(db.DateTime(timezone=True), nullable=False)
    end_datetime = db.Column(db.DateTime(timezone=True), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    calendar_id = db.Column(db.Integer, db.ForeignKey('calendar.id'), nullable=False)

    recurrence_rule = db.Column(db.String(255), nullable=True)
    recurrence_end_date = db.Column(db.DateTime(timezone=True), nullable=True)
    is_all_day = db.Column(db.Boolean, nullable=False, default=False)
    color = db.Column(db.String(7), nullable=True)
    google_event_id = db.Column(db.String(255))
    # make defaults timezone-aware
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship('User', backref=db.backref('appointments', lazy=True))
    calendar = db.relationship('Calendar', backref=db.backref('appointments', lazy=True))
    notes = db.relationship('Note', secondary='appointment_note', backref='appointments')

    # convenience properties to always get aware UTC datetimes
    @property
    def start_utc(self):
        return ensure_dt_utc(self.start_datetime)

    @property
    def end_utc(self):
        return ensure_dt_utc(self.end_datetime)

    @property
    def recurrence_end_utc(self):
        return ensure_dt_utc(self.recurrence_end_date)

    def to_dict(self):
        # make sure to output ISO strings using iso_utc helper
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "start_datetime": iso_utc(self.start_datetime),
            "end_datetime": iso_utc(self.end_datetime),
            "user_id": self.user_id,
            "calendar_id": self.calendar_id,
            "recurrence_rule": self.recurrence_rule,
            "recurrence_end_date": iso_utc(self.recurrence_end_date),
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

# models (modify CalendarSync)
class CalendarSync(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    local_calendar_id = db.Column(db.Integer, db.ForeignKey('calendar.id'))
    google_calendar_id = db.Column(db.String(255))  # Specific Google Calendar ID
    sync_enabled = db.Column(db.Boolean, default=True)
    last_synced = db.Column(db.DateTime)
    sync_token = db.Column(db.String(1000))  # <-- new: the google nextSyncToken

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
    
    # Add to Todo model
    flow_branch_id = db.Column(db.Integer, db.ForeignKey('flow_branches.id'), nullable=True)
    estimated_impact = db.Column(db.Integer, default=0)  # Estimated impact points

    # Add relationship to FlowBranch model
    flow_branch = db.relationship('FlowBranch', backref='todos')
    # This property will give us the associated commit (if any)
    @property
    def commit(self):
        # Since we used backref='flow_commits', we get a list
        # We return the first one (should only be one)
        return self.flow_commits[0] if self.flow_commits else None

    # Relationships:
    note           = db.relationship("Note", backref="todos")
    appointment    = db.relationship("Appointment", backref="todos")
    user           = db.relationship("User", backref="todos")

    # In Todo model
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.text,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'completed': self.completed,
            'note_id': self.note_id,
            'appointment_id': self.appointment_id,
            'flow_branch_id': self.flow_branch_id,
            'estimated_impact': self.estimated_impact
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
    pinned = db.Column(db.Boolean, default=False)

    group = db.relationship("Group", backref="notes")

    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "note": self.note,
            "tag": self.tag,
            "user_id": self.user_id,
            "group_id": self.group_id,
            "folder_id": self.folder_id,
            "pinned": self.pinned
        }

class NoteVersion(db.Model):
    __tablename__ = "note_version"
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    version_number = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    editor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # snapshot fields
    title = db.Column(db.String(100), nullable=True)
    note = db.Column(db.Text, nullable=False)
    tag = db.Column(db.String(100), nullable=True)
    folder_id = db.Column(db.Integer, nullable=True)
    pinned = db.Column(db.Boolean, default=False)

    uploads = db.relationship("NoteVersionUpload", backref="note_version", cascade="all, delete-orphan")

class NoteVersionUpload(db.Model):
    __tablename__ = "note_version_upload"
    id = db.Column(db.Integer, primary_key=True)
    note_version_id = db.Column(db.Integer, db.ForeignKey('note_version.id'), nullable=False)

    # reference to the original Upload (if still present)
    upload_id = db.Column(db.Integer, nullable=True)

    # snapshot metadata (so versions remain meaningful if upload later removed)
    filename = db.Column(db.String(255), nullable=True)
    size = db.Column(db.Integer, nullable=True)
    mime_type = db.Column(db.String(100), nullable=True)
    upload_deleted = db.Column(db.Boolean, nullable=True)  # true if upload.deleted was true at snapshot

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # token used for public access. NOTE: not unique anymore because we will
    # create multiple Share rows that share the same token for folder trees.
    token = db.Column(db.String(64), index=True, nullable=False)

    # Either a note_id OR folder_id, or both can be NULL. A share row points
    # to one node that is accessible under the token.
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # owner
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)

    access_count = db.Column(db.Integer, default=0, nullable=False)

    # relationships for convenience
    note = db.relationship('Note', backref='shares', foreign_keys=[note_id])
    folder = db.relationship('Folder', backref='shares', foreign_keys=[folder_id])

class ShareVisit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    share_id = db.Column(db.Integer, db.ForeignKey('share.id'), nullable=False)
    ip = db.Column(db.String(100), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    fingerprint_hash = db.Column(db.String(128), nullable=True)  # store a hash, not raw fingerprint
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    share = db.relationship('Share', backref='visits')
    
class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    pinned = db.Column(db.Boolean, default=False)
    
    # Self-referential relationship for subfolders
    parent = db.relationship('Folder', remote_side=[id], backref='subfolders')
    notes = db.relationship('Note', backref='folder', lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "parent_id": self.parent_id,
            "user_id": self.user_id,
            "group_id": self.group_id,
            "pinned": self.pinned
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

class NotificationLog(db.Model):
    __tablename__ = 'notification_log'
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'), nullable=False)
    minutes_before = db.Column(db.Integer, nullable=False)   # 15 or 30
    sent_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('appointment_id', 'minutes_before', name='uq_appointment_minute'),
    )

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
                    impact=remaining,
                    is_completion=True
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
    todo_id = db.Column(db.Integer, db.ForeignKey('todo.id'), nullable=True)  # New field
    is_completion = db.Column(db.Boolean, nullable=False, default=False)
    
    # Relationships
    next_commits = db.relationship('FlowCommit', backref=db.backref('prev_commit', remote_side=[id]))
    todo = db.relationship('Todo', backref='flow_commits')  # Changed backref name

#---------------------------------Helper functions--------------------------------
def get_user_default_calendar(user):
    """Return the user's default calendar or None if none exists."""
    return Calendar.query.filter_by(user_id=user.id, is_default=True).first()

def resolve_local_calendar(user, calendar_id):
    """
    Resolve and return a Calendar object:
      - if calendar_id provided: return that calendar if it belongs to user
      - if not provided: return user's default calendar (if any)
    Returns (calendar, error_tuple)
      - calendar: Calendar or None
      - error_tuple: None or (json_response, status_code)
    """
    if calendar_id is not None:
        try:
            cal_id_int = int(calendar_id)
        except (ValueError, TypeError):
            return None, (jsonify({"error": "invalid_calendar_id"}), 400)
        cal = Calendar.query.filter_by(id=cal_id_int, user_id=user.id).first()
        if not cal:
            return None, (jsonify({"error": "calendar_not_found"}), 404)
        return cal, None

    # no calendar_id provided -> use default
    cal = get_user_default_calendar(user)
    if not cal:
        return None, (jsonify({"error": "no_default_calendar", "message": "No calendar_id provided and no default calendar exists. Create a calendar or provide calendar_id."}), 400)
    return cal, None

def get_google_default_calendar_for_user(user):
    """Return the user's default calendar, or None."""
    return get_user_default_calendar(user)

# helper to normalize upload attributes (works with both shapes)
def _upload_metadata(up):
    if up is None:
        return {"upload_id": None, "filename": None, "size": None, "mime_type": None, "upload_deleted": True}
    filename = getattr(up, "original_filename", None) or getattr(up, "filename", None)
    size = getattr(up, "size_bytes", None) or getattr(up, "size", None)
    mime = getattr(up, "mimetype", None) or getattr(up, "mime_type", None)
    deleted = bool(getattr(up, "deleted", False))
    return {"upload_id": up.id, "filename": filename, "size": size, "mime_type": mime, "upload_deleted": deleted}

def mega_has_space(required_bytes: int) -> bool:
    """Check MEGA free space"""
    info = mega_account.get_storage_space()
    # info contains {'used': X, 'total': Y}
    return (info['total'] - info['used']) >= required_bytes

def upload_to_mega(local_path: str, filename: str):
    """Uploads file to MEGA, returns dict with link and file object for deletion"""
    uploaded_file = mega_account.upload(local_path, dest=None)  # root folder
    link = mega_account.get_upload_link(uploaded_file)
    return {"link": link, "file": uploaded_file}

def _strip_html_tags(html):
    # crude but effective for diffing purposes
    return re.sub(r'<[^>]+>', '', html or '')

def create_note_version(note, editor_id=None):
    """
    Create a NoteVersion snapshot of `note` and its current attachments.
    Avoid creating a new version if the latest version already matches current state.
    Returns the created NoteVersion or the existing last version if identical.
    """
    last_version = NoteVersion.query.filter_by(note_id=note.id).order_by(NoteVersion.version_number.desc()).first()

    # Build current snapshot dict
    attached_rows = NoteUpload.query.filter_by(note_id=note.id).all()
    current_uploads = []
    for ar in attached_rows:
        up = Upload.query.get(ar.upload_id)
        current_uploads.append(_upload_metadata(up))

    current_snapshot = {
        "title": note.title,
        "note": note.note,
        "tag": note.tag,
        "folder_id": note.folder_id,
        "pinned": bool(note.pinned),
        "uploads": current_uploads
    }

    # Build last snapshot dict for comparison (if exists)
    if last_version:
        last_uploads = []
        for vu in last_version.uploads:
            last_uploads.append({
                "upload_id": vu.upload_id,
                "filename": vu.filename,
                "size": vu.size,
                "mime_type": vu.mime_type,
                "upload_deleted": bool(vu.upload_deleted)
            })
        last_snapshot = {
            "title": last_version.title,
            "note": last_version.note,
            "tag": last_version.tag,
            "folder_id": last_version.folder_id,
            "pinned": bool(last_version.pinned),
            "uploads": last_uploads
        }

        # Compare snapshots
        if (current_snapshot["title"] == last_snapshot["title"] and
            current_snapshot["note"] == last_snapshot["note"] and
            (current_snapshot["tag"] or None) == (last_snapshot["tag"] or None) and
            current_snapshot["folder_id"] == last_snapshot["folder_id"] and
            current_snapshot["pinned"] == last_snapshot["pinned"] and
            len(current_snapshot["uploads"]) == len(last_snapshot["uploads"]) and
            all(
                (cu["upload_id"] == lu["upload_id"] and
                 (cu["filename"] or "") == (lu["filename"] or "") and
                 (cu["size"] or 0) == (lu["size"] or 0) and
                 (cu["mime_type"] or "") == (lu["mime_type"] or "") and
                 bool(cu["upload_deleted"]) == bool(lu["upload_deleted"]))
                for cu, lu in zip(current_snapshot["uploads"], last_snapshot["uploads"])
            )):
            # identical — do not create a duplicate version
            current_app.logger.debug(f"Skipping version creation for note {note.id} — identical to last version #{last_version.version_number}")
            return last_version

    # Not identical -> create new version
    next_version_number = 1 if not last_version else last_version.version_number + 1

    nv = NoteVersion(
        note_id=note.id,
        version_number=next_version_number,
        editor_id=editor_id,
        title=note.title,
        note=note.note,
        tag=note.tag,
        folder_id=note.folder_id,
        pinned=note.pinned
    )
    db.session.add(nv)
    db.session.flush()  # get nv.id

    # snapshot attachments that are currently attached to the note
    for ar in attached_rows:
        up = Upload.query.get(ar.upload_id)
        meta = _upload_metadata(up)
        vu = NoteVersionUpload(
            note_version_id=nv.id,
            upload_id=meta["upload_id"],
            filename=meta["filename"],
            size=meta["size"],
            mime_type=meta["mime_type"],
            upload_deleted=meta["upload_deleted"]
        )
        db.session.add(vu)

    db.session.commit()
    return nv

def delete_version_history(note_id):
    """
    Delete all NoteVersion and NoteVersionUpload rows for note_id.
    """
    versions = NoteVersion.query.filter_by(note_id=note_id).all()
    for nv in versions:
        NoteVersionUpload.query.filter_by(note_version_id=nv.id).delete()
        db.session.delete(nv)
    db.session.commit()

def get_upload_url(upload):
    # simple inline URL for images
    return f'/uploads/{upload.id}/download?inline=1'

def dropbox_has_space(size_bytes: int) -> bool:
    """
    Returns True if Dropbox has enough free space for the file.
    """
    try:
        usage = dbx.users_get_space_usage()
        used = usage.used
        allocated = usage.allocation.get_individual().allocated
        return (used + size_bytes) <= allocated
    except Exception:
        # conservative fallback if API fails
        return False

def insert_card_activity(user_id, card_id, content):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return "User not found!"

    card = Card.query.filter_by(id=card_id).first()
    if not card:
        return "Card not found!"

    new_activity = CardActivity(
        card_id=card_id,
        activity_type="activity",
        content=content,
        user_id=user_id
    )

    try:
        db.session.add(new_activity)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return "Error inserting card activity!"

    return "Successfully inserted card activity!"

def collect_folder_tree_ids(root_folder_id):
    """
    Return two sets: (folder_ids_set, note_ids_set) covering root_folder_id
    and all descendants (recursive).
    BFS/stack traversal.
    """
    folder_ids = set()
    note_ids = set()

    q = deque([root_folder_id])
    while q:
        fid = q.popleft()
        if fid in folder_ids:
            continue
        folder_ids.add(fid)

        # subfolders
        subfolders = Folder.query.filter_by(parent_id=fid).with_entities(Folder.id).all()
        for (sid,) in subfolders:
            if sid not in folder_ids:
                q.append(sid)

        # notes in folder
        notes = Note.query.filter_by(folder_id=fid).with_entities(Note.id).all()
        for (nid,) in notes:
            note_ids.add(nid)

    return folder_ids, note_ids

def get_shared_node_sets_for_token(token):
    """
    Return (folder_ids_set, note_ids_set, root_folder_id_or_None, root_note_id_or_None)
    For folder shares root_folder_id is set (the first folder share created for this token).
    For note-only shares, root_note_id will be set.
    """
    shares = (Share.query
              .filter(Share.token == token)
              .order_by(Share.created_at.asc())
              .all())

    folder_ids = set()
    note_ids = set()
    root_folder_id = None
    root_note_id = None
    if not shares:
        return folder_ids, note_ids, None, None

    for s in shares:
        if s.folder_id:
            folder_ids.add(s.folder_id)
            if root_folder_id is None:
                root_folder_id = s.folder_id
        if s.note_id:
            note_ids.add(s.note_id)
            if root_note_id is None:
                root_note_id = s.note_id

    return folder_ids, note_ids, root_folder_id, root_note_id

def token_has_access_to_folder(token, folder_id):
    folder_ids, note_ids, _, _ = get_shared_node_sets_for_token(token)
    return folder_id in folder_ids

def token_has_access_to_note(token, note_id):
    folder_ids, note_ids, _, _ = get_shared_node_sets_for_token(token)
    return note_id in note_ids

def extract_text_preview(html, length=50):
    # strip HTML tags
    text = re.sub('<[^<]+?>', '', html or "")
    text = text.replace("&nbsp;", " ").strip()
    if len(text) > length:
        return text[:length].rstrip() + "…"
    return text

# Helper to get client IP (works behind proxies if you set them)
def client_ip():
    xff = request.headers.get('X-Forwarded-For', None)
    if xff:
        # if multiple IPs, first is original client
        return xff.split(',')[0].strip()
    return request.remote_addr

def encrypt_secret(plain: str) -> str:
    if not fernet:
        return plain
    return fernet.encrypt(plain.encode()).decode()


def decrypt_secret(cipher: str) -> str:
    if not fernet:
        return cipher
    try:
        return fernet.decrypt(cipher.encode()).decode()
    except InvalidToken:
        return None
    
def make_qr_data_uri(provisioning_uri: str):
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"

def generate_session_key(user_id):
    key = secrets.token_hex(32)
    session_keys[key] = {
        "user_id": user_id,
        "expires_at": datetime.now() + timedelta(minutes=120),
        "last_active": datetime.now()
    }
    return key

def generate_wopi_token(file_id, session_key):
    """
    Create a signed WOPI token tied to the user session.
    """
    session_data = session_keys.get(session_key)
    if not session_data:
        raise ValueError("Invalid session key")

    payload = {
        "file_id": file_id,
        "user_id": session_data["user_id"],
        "session_key": session_key
    }
    return serializer.dumps(payload)

def verify_wopi_token(token):
    try:
        data = serializer.loads(token, max_age=TOKEN_EXPIRATION)
    except Exception:
        return None

    # Verify session exists and is not expired
    session_key = data.get("session_key")
    session_data = session_keys.get(session_key)

    if not session_data:
        return None

    # Optional: check expiration
    if session_data["expires_at"] < datetime.now():
        # session expired
        session_keys.pop(session_key, None)
        return None

    return data


def remove_upload_if_orphan(upload_id):
    """
    If upload has no remaining NoteUpload references (and not used elsewhere),
    call the central delete_upload() to remove file and subtract storage.
    Returns (True, msg) on success, (False, msg) on error.
    """
    upload = Upload.query.get(upload_id)
    if not upload:
        return False, "Upload not found."

    # Count remaining note references
    remaining_refs = NoteUpload.query.filter_by(upload_id=upload_id).count()

    # If still referenced (maybe by other notes), don't delete the upload file
    if remaining_refs > 0:
        return True, "Still referenced by other notes; not deleting file."

    # Otherwise, call the central delete function which checks ownership & updates storage
    # We need a user object for delete_upload; use the owner of the upload
    user = User.query.get(upload.user_id)
    ok, msg = delete_upload(upload_id, user)
    return ok, msg


def _extract_text_from_cohere_response(response) -> str:
    """
    Try to robustly extract text from the SDK response object.
    The SDK response structure can vary; this handles strings, lists of chunks,
    dict-like chunks, and attribute-based chunks.
    """
    text_out = ""

    print(response)

    # Try attribute access for response.message.content
    content = None
    try:
        if hasattr(response, "message"):
            # response.message might be a dict-like or object
            msg = response.message
            if isinstance(msg, dict):
                content = msg.get("content")
            else:
                content = getattr(msg, "content", None)
    except Exception:
        content = None

    # If not found, try other common paths (some SDK versions use 'output' or 'response')
    if content is None:
        try:
            if hasattr(response, "output"):
                out = response.output
                if isinstance(out, dict):
                    content = out.get("content")
                else:
                    content = getattr(out, "content", None)
        except Exception:
            content = None

    # If content is a plain string
    if isinstance(content, str):
        return content.strip()

    # If content is a list of chunks, extract text from each chunk
    if isinstance(content, list):
        for chunk in content:
            # chunk could be dict-like or object
            val = None
            if isinstance(chunk, dict):
                for k in ("text", "content", "value"):
                    if k in chunk and isinstance(chunk[k], str):
                        val = chunk[k]
                        break
            else:
                for attr in ("text", "content", "value"):
                    if hasattr(chunk, attr):
                        cand = getattr(chunk, attr)
                        if isinstance(cand, str):
                            val = cand
                            break
            if val is None:
                # last resort: string conversion
                try:
                    val = str(chunk)
                except Exception:
                    val = ""
            text_out += val
        return text_out.strip()

    # Fallback: maybe response itself is string-like
    try:
        return str(response).strip()
    except Exception:
        return ""


@app.before_request
def ensure_secrets_loaded():
    load_secrets()

import ipaddress

def _is_local_request():
    client_ip = request.remote_addr

    # Step 1: Define what "local" means
    # Includes localhost + LAN subnets (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    local_subnets = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
    ]

    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False  # invalid IP

    return any(ip_obj in subnet for subnet in local_subnets)


def _today_utc_range():
    """Return (start_of_today_utc, now_utc) as timezone-aware datetimes."""
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, now

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
    
    # Update overall last sync time for the credentials
    creds_record = GoogleCalendarCredentials.query.filter_by(user_id=user_id).first()
    if creds_record:
        creds_record.last_sync = datetime.utcnow()
    
    for mapping in sync_mappings:
        try:
            sync_start = datetime.utcnow()
            
            # If any mapping lacks a sync_token, force a full sync for that mapping
            mapping_full_sync = full_sync or not mapping.sync_token

            # Pull remote changes and resolve conflicts (this function may also push local changes if local wins)
            pull_and_resolve(service, mapping, mapping_full_sync, sync_start)

            # After pull & conflict resolution, push remaining local-only changes that happened before sync_start
            push_local_changes(service, mapping, sync_start)

            mapping.last_synced = datetime.utcnow()
            results.append(f"Calendar {mapping.local_calendar_id} synced")
        except Exception as e:
            current_app.logger.exception(f"Sync failed for calendar {mapping.local_calendar_id}: {str(e)}")
            results.append(f"Sync failed for calendar {mapping.local_calendar_id}: {str(e)}")
    
    db.session.commit()
    return True, "\n".join(results)


def push_local_changes(service, mapping, sync_start):
    """
    Push local changes that occurred after mapping.last_synced and before sync_start.
    For existing Google event ids, we update; for local-only events we create and save google_event_id.
    """
    last_sync = mapping.last_synced or datetime.min
    appointments = Appointment.query.filter(
        Appointment.calendar_id == mapping.local_calendar_id,
        Appointment.updated_at > last_sync,
        Appointment.updated_at < sync_start  # exclude edits made during this sync cycle
    ).all()

    if not appointments:
        return

    current_app.logger.info(f"Pushing {len(appointments)} local appointment(s) to Google calendar {mapping.google_calendar_id}")

    for appt in appointments:
        # Build event body from local
        event_body = convert_appointment_to_event(appt)
        if not event_body:
            continue

        google_calendar_id = mapping.google_calendar_id

        try:
            if appt.google_event_id:
                # Before updating, fetch Google's event to compare timestamps (avoid stomping newer remote)
                try:
                    remote = service.events().get(calendarId=google_calendar_id, eventId=appt.google_event_id).execute()
                    remote_updated = parse_google_updated(remote.get('updated'))
                except Exception:
                    # If remote cannot be fetched (maybe deleted), treat as non-existent
                    remote = None
                    remote_updated = datetime.min

                # If remote is newer than local -> skip update (remote already won)
                if remote and remote_updated > (appt.updated_at or datetime.min) + _TIME_EPS:
                    current_app.logger.info(f"Skipping update for {appt.id} because Google is newer.")
                    # Optionally update the local fields from remote to keep local consistent
                    # process single remote event to update local
                    process_single_google_event(service, remote, mapping)
                    continue

                # Otherwise update remote
                updated_event = service.events().update(
                    calendarId=google_calendar_id,
                    eventId=appt.google_event_id,
                    body=event_body
                ).execute()
                # Update local google_event_id (in case Google changed id) and sync timestamps
                appt.google_event_id = updated_event.get('id', appt.google_event_id)
                appt.updated_at = max(appt.updated_at or datetime.min, parse_google_updated(updated_event.get('updated')))

            elif appt.deleted_at and appt.google_event_id:
                try:
                    service.events().delete(
                        calendarId=mapping.google_calendar_id,
                        eventId=appt.google_event_id
                    ).execute()
                    current_app.logger.info(f"Deleted Google event {appt.google_event_id} due to local deletion")
                    appt.google_event_id = None
                    db.session.add(appt)
                    db.session.commit()
                except Exception as e:
                    current_app.logger.exception(f"Failed to delete Google event {appt.google_event_id}: {str(e)}")
                continue
            else:
                # Create new event on Google
                created = service.events().insert(
                    calendarId=google_calendar_id,
                    body=event_body
                ).execute()
                appt.google_event_id = created['id']
                # Use Google 'updated' time if present, otherwise keep local updated_at
                appt.updated_at = max(appt.updated_at or datetime.min, parse_google_updated(created.get('updated')))

            db.session.add(appt)
            db.session.commit()
        except Exception as e:
            current_app.logger.exception(f"Failed to push appointment {appt.id} to Google: {str(e)}")
            # If error contains 'deleted' etc, handle cleanup
            if 'deleted' in str(e).lower():
                current_app.logger.warning(f"Event {appt.google_event_id} appears deleted on Google. Clearing local google_event_id.")
                appt.google_event_id = None
                db.session.add(appt)
                db.session.commit()


def pull_and_resolve(service, mapping, full_sync, sync_start):
    """
    Pulls changes from Google and resolves conflicts by timestamp.
    If local is newer than Google -> push local update.
    If Google is newer -> update or create local appointment.
    """
    sync_token = None if full_sync or not mapping.sync_token else mapping.sync_token

    page_token = None
    next_sync_token = None
    google_events = []

    while True:
        try:
            params = {
                'calendarId': mapping.google_calendar_id,
                'maxResults': 250,
                'singleEvents': True,
                'showDeleted': True,
            }

            if sync_token and not full_sync:
                params['syncToken'] = sync_token
            else:
                # Use a reasonable time window for full sync (e.g. last 365 days)
                params['timeMin'] = (datetime.utcnow() - timedelta(days=365)).isoformat() + 'Z'

            if page_token:
                params['pageToken'] = page_token

            events_result = service.events().list(**params).execute()
            google_events.extend(events_result.get('items', []))
            page_token = events_result.get('nextPageToken')

            if not page_token:
                next_sync_token = events_result.get('nextSyncToken')
                break

        except Exception as e:
            # Google returns 410 when sync token expired/invalid: reset and do full sync
            if hasattr(e, 'resp') and getattr(e.resp, 'status', None) == 410:
                mapping.sync_token = None
                db.session.commit()
                return pull_and_resolve(service, mapping, True, sync_start)
            current_app.logger.exception(f"Google API error while pulling events: {str(e)}")
            raise

    # Process each event and resolve conflicts
    for event in google_events:
        process_single_google_event(service, event, mapping, sync_start=sync_start)

    # store next sync token for incremental syncs
    if next_sync_token:
        mapping.sync_token = next_sync_token
        db.session.add(mapping)
        db.session.commit()


def process_single_google_event(service, event, mapping, sync_start=None):
    """
    Resolve a single google event vs local appointment by timestamps.
    If event['status']=='cancelled' => handle deletion/maybe recreate.
    """
    user_id = mapping.user_id
    google_id = event.get('id')
    google_calendar_id = mapping.google_calendar_id

    google_updated = parse_google_updated(event.get('updated'))

    # Deleted on Google
    if event.get('status') == 'cancelled':
        # Local appointment with this google id (if any)
        local = Appointment.query.filter_by(google_event_id=google_id, user_id=user_id).first()
        if local:
            # If local was modified after Google deletion -> recreate on Google
            if local.updated_at and local.updated_at > google_updated + _TIME_EPS:
                current_app.logger.info(f"Local {local.id} modified after Google deletion. Recreating on Google.")
                event_body = convert_appointment_to_event(local)
                created = service.events().insert(calendarId=google_calendar_id, body=event_body).execute()
                local.google_event_id = created['id']
                local.updated_at = max(local.updated_at or datetime.min, parse_google_updated(created.get('updated')))
                db.session.add(local)
                db.session.commit()
            else:
                # Google deletion wins -> remove local
                current_app.logger.info(f"Deleting local appointment {local.id} because Google removed the event.")
                db.session.delete(local)
                db.session.commit()
        return

    # Non-deleted event: find local
    local = Appointment.query.filter_by(google_event_id=google_id, user_id=user_id).first()

    if not local:
        # Create locally from Google event
        try:
            appt_data = google_event_to_appt_data(event, mapping.local_calendar_id, user_id, google_updated)
            appointment = Appointment(**appt_data)
            db.session.add(appointment)
            db.session.commit()
            current_app.logger.info(f"Created local appointment from Google event {google_id}")
        except Exception as e:
            current_app.logger.exception(f"Failed creating local appt for Google event {google_id}: {str(e)}")
        return

    # Both exist -> compare timestamps
    local_updated = local.updated_at or datetime.min

    if google_updated > local_updated + _TIME_EPS:
        # Google is newer: update local from Google
        try:
            appt_data = google_event_to_appt_data(event, local.calendar_id, local.user_id, google_updated)
            for k, v in appt_data.items():
                setattr(local, k, v)
            local.updated_at = google_updated
            db.session.add(local)
            db.session.commit()
            current_app.logger.info(f"Updated local appointment {local.id} from Google event {google_id}")
        except Exception as e:
            current_app.logger.exception(f"Error updating local appt {local.id} from Google: {str(e)}")
    elif local_updated > google_updated + _TIME_EPS:
        # Local is newer: push local update to Google (but only if local change occurred before sync_start)
        # We avoid pushing edits made during this sync run (sync loop)
        if sync_start and local_updated >= sync_start:
            current_app.logger.info(f"Skipping push for local {local.id} because edit occurred during sync.")
            return

        try:
            event_body = convert_appointment_to_event(local)
            updated_event = service.events().update(
                calendarId=google_calendar_id,
                eventId=google_id,
                body=event_body
            ).execute()
            # update local updated_at to reflect Google's updated timestamp (prevents flip-flop)
            local.updated_at = max(local.updated_at, parse_google_updated(updated_event.get('updated')))
            db.session.add(local)
            db.session.commit()
            current_app.logger.info(f"Pushed local appointment {local.id} to Google event {google_id}")
        except Exception as e:
            current_app.logger.exception(f"Failed to push local {local.id} to Google: {str(e)}")
    else:
        # timestamps equal or within epsilon -> nothing to do
        return


def google_event_to_appt_data(event, local_calendar_id, user_id, google_updated):
    """
    Convert Google event dict -> appointment dict for creating/updating local.
    """
    return {
        'title': event.get('summary', 'No Title'),
        'description': event.get('description', ''),
        'start_datetime': parse_google_datetime(event['start']),
        'end_datetime': parse_google_datetime(event['end']),
        'google_event_id': event['id'],
        'calendar_id': local_calendar_id,
        'user_id': user_id,
        'color': event.get('colorId'),
        'is_all_day': 'date' in event.get('start', {}),
        'recurrence_rule': (event.get('recurrence') or [None])[0],
        'updated_at': google_updated
    }


# Utility: parse Google's 'updated' RFC3339 string into naive UTC datetime
def parse_google_updated(updated_str):
    try:
        if not updated_str:
            return datetime.min.replace(tzinfo=None)
        # example: "2023-01-01T12:34:56.789Z"
        dt = datetime.fromisoformat(updated_str.replace('Z', '+00:00'))
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        current_app.logger.exception(f"Error parsing google updated: {updated_str}")
        return datetime.min.replace(tzinfo=None)
    
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
    
# ---- helper: verify password or 2FA code (TOTP or backup) ----
def _verify_password_or_2fa(user, password: str = None, code: str = None):
    """
    Returns a tuple (ok: bool, used_backup: bool, reason: str).
    If a backup code is used, it will be consumed (removed) here and DB committed.
    """
    if password:
        # verify password
        try:
            if bcrypt.check_password_hash(user.password, password):
                return True, False, "password"
        except Exception:
            # in case bcrypt object/naming differs, fail safely
            pass
        return False, False, "bad_password"

    if code:
        code = code.strip()
        # try TOTP first
        secret = decrypt_secret(user.twofa_secret) if user.twofa_secret else None
        if secret:
            try:
                totp = pyotp.TOTP(secret)
                if totp.verify(code, valid_window=1):
                    return True, False, "totp"
            except Exception:
                # invalid secret format or other error — fall through to backup codes
                pass

        # then try backup codes (stored hashed, comma-separated)
        if user.backup_codes_hash:
            hashed_codes = user.backup_codes_hash.split(',')
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            if code_hash in hashed_codes:
                # consume this backup code
                hashed_codes.remove(code_hash)
                user.backup_codes_hash = ','.join(hashed_codes) if hashed_codes else None
                db.session.commit()
                return True, True, "backup"
        # failed both
        return False, False, "bad_code"

    return False, False, "no_credentials"

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

def parse_flow_tags(text):
    """Extracts project, branch, and impact tags from todo text.
    Returns: {project_id: int, branch_id: int, impact: int}
    """
    tags = {
        'project_id': None,
        'branch_name': None,  # We'll look up the ID later
        'impact': 0
    }
    
    # Example: #proj-123 → project_id=123
    project_match = re.search(r'#proj-(\d+)', text)
    if project_match:
        tags['project_id'] = int(project_match.group(1))
    
    # Example: #branch-feature-auth → branch_name="feature-auth"
    branch_match = re.search(r'#branch-([\w-]+)', text)
    if branch_match:
        tags['branch_name'] = branch_match.group(1)
    
    # Example: #impact-8 → impact=8
    impact_match = re.search(r'#impact-(\d+)', text)
    if impact_match:
        tags['impact'] = int(impact_match.group(1))
    
    return tags

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
    utm_source = request.args.get('utm_source')
    utm_medium = request.args.get('utm_medium')
    utm_campaign = request.args.get('utm_campaign')

    if utm_source:
        session['utm_source'] = utm_source
    if utm_medium:
        session['utm_medium'] = utm_medium
    if utm_campaign:
        session['utm_campaign'] = utm_campaign

    # Get the real client IP (PythonAnywhere sets X-Forwarded-For)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip.split(',')[0].strip()  # In case there are multiple IPs

    if utm_source or utm_medium or utm_campaign:
        tracking = UTMTracking(
            utm_source=utm_source,
            utm_medium=utm_medium,
            utm_campaign=utm_campaign,
            ip=ip
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
    
    if (user.malicious_violations or 0) > 10:
        user.suspended = True
        db.session.add(user)
        db.session.commit()
        return False, "You have been suspended for violating the TOS"

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

def get_user_from_session(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Try to get session info, but ignore if missing/invalid
        valid, resp = validate_session_key()
        if valid:
            g.user_id = resp["user_id"]
        else:
            g.user_id = None  # explicitly set to None if no valid session
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

def delete_shares(note_id):
    try:
        # Load shares for this note
        shares = Share.query.filter_by(note_id=note_id).all()
        if not shares:
            return

        share_ids = [s.id for s in shares]

        # Delete ShareVisit rows referencing these shares (bulk delete)
        # use synchronize_session=False for performance / to avoid session state issues
        ShareVisit.query.filter(ShareVisit.share_id.in_(share_ids)).delete(synchronize_session=False)

        # Delete Share rows (bulk delete)
        Share.query.filter(Share.id.in_(share_ids)).delete(synchronize_session=False)

        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to delete share and sharevisits")
        # Consider re-raising or returning False if you want caller to abort the parent deletion

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

def require_localhost_domain(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        host = request.host.split(":", 1)[0].lower()
        if not (host == "localhost" or host == "127.0.0.1" or host == "::1"):
           return (
                jsonify({"error": "Forbidden: this endpoint only works on localhost domain"}),
                403
            )
        return fn(*args, **kwargs)
    return wrapper

def has_changes():
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True
    )
    return result.stdout.strip() != ""

def generate_deploy_hash():
    today = datetime.utcnow().strftime("%Y-%m-%d")
    data = f"{PRIME}-{today}-{SALT}"
    return hashlib.sha256(data.encode()).hexdigest()

def delete_profile_pictures(username):
    """ Deletes all profile pictures associated with the given username. """
    profile_pictures_path = os.path.join(UPLOAD_FOLDER_PROFILE_PICS)
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
    profile_pictures = os.listdir(app.config['UPLOAD_FOLDER_PROFILE_PICS'])
    profile_pictures = [os.path.join(app.config['UPLOAD_FOLDER_PROFILE_PICS'], pic).replace("\\", "/") for pic in profile_pictures]

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

        # Delete uploads
        Upload.query.filter_by(user_id=user_to_delete.id).delete()


        # Finally, delete the user
        db.session.delete(user_to_delete)
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user data: {str(e)}")
        return False
    
def _redeem_referral_for_user(user, signup_session):
    """
    If there's a referral_session cookie and it points to a valid invite,
    run the anti-cheat checks and — if allowed — award +5MB to both the inviter
    and the newly created user. Always remove the ReferralSession afterwards
    to prevent replay.
    """
    try:
        referral_cookie = request.cookies.get('referral_session')
        if not referral_cookie:
            return

        ref = ReferralSession.query.get(referral_cookie)
        if not ref:
            return

        invite = InviteReferral.query.get(ref.invite_id)
        if not invite or invite.claimed:
            # clean up referral session anyway
            db.session.delete(ref)
            db.session.commit()
            return

        allow_award = False

        # If signup_session has an email and it matches the invited email -> allow
        if signup_session.email and invite.invited_email and \
           signup_session.email.lower() == (invite.invited_email or "").lower():
            allow_award = True
        else:
            # If signup_session.email is missing (skip-email) we permit awarding,
            # but we'll keep the IP/self-invite protections below.
            if not signup_session.email:
                allow_award = True

        # Prevent self-invite via email match with inviter's email (if available)
        if allow_award and signup_session.email and not _is_local_request():
            inviter_obj = User.query.get(ref.inviter_id)
            inviter_email = (inviter_obj.email or "").lower() if inviter_obj else ""
            if inviter_email and inviter_email == signup_session.email.lower():
                allow_award = False

        # IP-based anti-cheat (skip when running on localhost)
        if allow_award and not _is_local_request():
            same_ip = IpAddres.query.filter_by(user_id=ref.inviter_id, ip=signup_session.user_ip).first()
            if same_ip:
                allow_award = False

        if allow_award and not _is_local_request():
            same_email_again = InviteReferral.query.filter_by(inviter_id=ref.inviter_id, invited_email=signup_session.email).first()
            if same_email_again:
                allow_award = False

        # Apply awards and mark invite claimed in one DB transaction
        if allow_award:
            inviter = User.query.get(ref.inviter_id)
            if inviter:
                inviter.base_storage_mb = (inviter.base_storage_mb or 0) + 5
                user.base_storage_mb = (user.base_storage_mb or 0) + 5

                invite.claimed = True
                invite.claimed_at = datetime.now(timezone.utc)
                invite.claimed_user_id = user.id

                db.session.add_all([inviter, user, invite])
                # delete referral session to prevent reuse
                db.session.delete(ref)
                db.session.commit()

                # notify inviter and (optionally) the new user
                send_notification(
                    ref.inviter_id,
                    "Invite redeemed!",
                    f"{user.username} signed up via your invite — you got +5MB storage!",
                    "/index"
                )
                send_notification(
                    user.id,
                    "Welcome bonus!",
                    "You signed up using an invite — you received +5MB extra storage!",
                    "/index"
                )
                return

        # If not allowed, we still delete the referral session to avoid replays
        db.session.delete(ref)
        db.session.commit()
    except Exception:
        # Non-fatal: log and continue signup
        app.logger.exception("Referral redemption failed (non-fatal)")
        try:
            # best-effort cleanup
            if 'ref' in locals() and ref:
                db.session.delete(ref)
                db.session.commit()
        except Exception:
            pass
    

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

from werkzeug.datastructures import FileStorage

def allowed_extension(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXTENSIONS

def folder_belongs_to_owner(folder_obj, owner_user_id=None, owner_group_id=None):
    """
    Return True if folder_obj belongs to the provided owner user_id or group_id.
    Exactly one of owner_user_id or owner_group_id should be non-None when called.
    """
    if owner_user_id is not None:
        return folder_obj.user_id == owner_user_id and folder_obj.group_id is None
    if owner_group_id is not None:
        return folder_obj.group_id == owner_group_id and folder_obj.user_id is None
    return False

def collect_all_folder_ids(root_folder):
    """
    Returns a set of folder ids for the whole subtree starting from root_folder (includes root_folder.id).
    Traversal respects owner: user_id or group_id on the root folder.
    """
    owner_user_id = root_folder.user_id
    owner_group_id = root_folder.group_id

    ids = set()
    stack = [root_folder]
    while stack:
        f = stack.pop()
        ids.add(f.id)
        # children must share the same owner type (user or group)
        if owner_user_id is not None:
            children = Folder.query.filter_by(parent_id=f.id, user_id=owner_user_id).all()
        else:
            children = Folder.query.filter_by(parent_id=f.id, group_id=owner_group_id).all()
        stack.extend(children)
    return ids

def collect_note_ids_in_folders(folder_ids, owner_user_id=None, owner_group_id=None):
    """
    Return list of Note ids that are in folder_ids and belong to the same owner (user or group).
    If owner_user_id provided, we filter Note.user_id==owner_user_id; if owner_group_id provided, Note.group_id==owner_group_id.
    """
    if owner_user_id is not None:
        notes = Note.query.filter(Note.folder_id.in_(list(folder_ids)), Note.user_id == owner_user_id).all()
    else:
        notes = Note.query.filter(Note.folder_id.in_(list(folder_ids)), Note.group_id == owner_group_id).all()
    return [n.id for n in notes]

def get_recursive_folder_tree(root_folder):
    """
    Return list of Folder objects in post-order (children first, then parent) for deletion.
    Keeps the same owner constraint as root_folder.
    """
    owner_user_id = root_folder.user_id
    owner_group_id = root_folder.group_id

    result = []
    def dfs(folder):
        if owner_user_id is not None:
            children = Folder.query.filter_by(parent_id=folder.id, user_id=owner_user_id).all()
        else:
            children = Folder.query.filter_by(parent_id=folder.id, group_id=owner_group_id).all()
        for c in children:
            dfs(c)
        result.append(folder)
    dfs(root_folder)
    return result

def delete_notes_and_attachments(note_objs_or_ids, user, owner_group_id=None):
    """
    Delete notes and their uploads. Accepts either:
      - list of Note objects
      - list of note IDs (ints)

    If owner_group_id is given, only deletes notes with that group_id.
    """
    try:
        if not note_objs_or_ids:
            app.logger.debug("delete_notes_and_attachments: nothing to delete")
            return True, "Nothing to delete."

        # normalize
        if all(isinstance(x, int) for x in note_objs_or_ids):
            note_ids = list(note_objs_or_ids)
        elif all(hasattr(x, "id") for x in note_objs_or_ids):
            note_ids = [int(x.id) for x in note_objs_or_ids]
        else:
            app.logger.warning("delete_notes_and_attachments: mixed or unexpected input types: %r", note_objs_or_ids[:5])
            # try to coerce any ints or objects
            note_ids = []
            for x in note_objs_or_ids:
                if isinstance(x, int):
                    note_ids.append(x)
                elif hasattr(x, "id"):
                    note_ids.append(int(x.id))
            if not note_ids:
                return True, "Nothing to delete."

        # ensure unique ints
        note_ids = list({int(n) for n in note_ids})

        # gather upload ids referenced by these notes
        note_upload_rows = NoteUpload.query.filter(NoteUpload.note_id.in_(note_ids)).all()
        upload_ids = {nu.upload_id for nu in note_upload_rows}

        # delete NoteUpload rows
        if note_ids:
            NoteUpload.query.filter(NoteUpload.note_id.in_(note_ids)).delete(synchronize_session=False)

        # delete notes, honoring ownership (group or user)
        if note_ids:
            if owner_group_id is not None:
                deleted = Note.query.filter(Note.id.in_(note_ids), Note.group_id == owner_group_id).delete(synchronize_session=False)
            else:
                deleted = Note.query.filter(Note.id.in_(note_ids), Note.user_id == g.user_id).delete(synchronize_session=False)
            app.logger.debug("delete_notes_and_attachments: deleted %s notes", deleted)

        # handle actual upload deletion where no remaining NoteUpload refs exist
        for uid in upload_ids:
            other_ref = NoteUpload.query.filter_by(upload_id=uid).first()
            if not other_ref:
                ok, msg = delete_upload(uid, user)
                if not ok:
                    db.session.rollback()
                    return False, f"Failed deleting upload {uid}: {msg}"

        db.session.flush()
        return True, "Notes and attachments deleted."
    except Exception as e:
        app.logger.exception("Error deleting notes and attachments: %s", e)
        db.session.rollback()
        return False, "Server error while deleting notes."

def get_user_quota_bytes(user):
    """
    Return quota in bytes.
    If user.has_unlimited_storage is True, return float('inf') to indicate no limit.
    If user.base_storage_mb is None -> default to 10 MB.
    Coerce strings to int safely; on failure fall back to 10.
    """
    # Check for unlimited storage
    if getattr(user, "has_unlimited_storage", False):
        return float("inf")

    default_mb = 10
    try:
        base_mb = user.base_storage_mb
        if base_mb is None:
            base_mb = default_mb
        else:
            # coerce strings like "10" or b"10" to int, sanitize weird values
            base_mb = int(str(base_mb).strip())
            # negative values don't make sense; fallback to default
            if base_mb < 0:
                base_mb = default_mb
    except (ValueError, TypeError):
        base_mb = default_mb

    return int(base_mb) * 1024 * 1024

import os
import math
import shutil
from flask import jsonify, request
from datetime import datetime

@app.route("/admin/storage", methods=["GET"])
@require_session_key
@require_admin
def admin_storage_overview():
    def make_inf_dict():
        local_dir = os.path.abspath(UPLOAD_FOLDER_LOCAL_FILES)
        used = 0
        if os.path.isdir(local_dir):
            for root, _, files in os.walk(local_dir):
                for fn in files:
                    try:
                        fp = os.path.join(root, fn)
                        used += os.path.getsize(fp)
                    except Exception:
                        pass
        return {
            "used_bytes": used,
            "total_bytes": None,
            "free_bytes": None,
            "free_percent": None,
            "note": "local capacity reported as infinite for localhost requests"
        }

    def safe_int(v):
        try:
            return int(v)
        except Exception:
            return None

    result = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "local": {},
        "dropbox": {},
        "mega": {}
    }

    # Local storage stats
    remote_addr = (request.remote_addr or "").split(",")[0].strip()
    try:
        if remote_addr in ("127.0.0.1", "::1", "localhost"):
            result["local"] = make_inf_dict()
        else:
            local_dir = os.path.abspath(UPLOAD_FOLDER_LOCAL_FILES)
            used = 0
            if os.path.isdir(local_dir):
                for root, _, files in os.walk(local_dir):
                    for fn in files:
                        try:
                            fp = os.path.join(root, fn)
                            used += os.path.getsize(fp)
                        except Exception:
                            pass

            # Prefer explicit configured quota
            quota = None
            try:
                quota = current_app.config.get("LOCAL_UPLOAD_QUOTA_BYTES")
            except Exception:
                quota = None

            if not quota:
                try:
                    quota = safe_int(os.environ.get("LOCAL_UPLOAD_QUOTA_BYTES"))
                except Exception:
                    quota = None

            if quota is None and "PYTHONANYWHERE_DOMAIN" in os.environ:
                quota = 512 * 1024 * 1024  # 512 MiB

            total = None
            free = None
            free_pct = None
            source = None

            if isinstance(quota, int) and quota > 0:
                total = quota
                free = max(total - used, 0)
                free_pct = round((free / total) * 100, 2) if total > 0 else None
                source = "quota"
            else:
                try:
                    du = shutil.disk_usage(local_dir)
                    total = du.total
                    free = du.free
                    free_pct = round((free / total) * 100, 2) if total and total > 0 else None
                    source = "filesystem"
                except Exception:
                    total = None
                    free = None
                    free_pct = None
                    source = "unknown"

            # --- New: optional PythonAnywhere "du" total used value ---
            pa_total_used = None
            if "PYTHONANYWHERE_DOMAIN" in os.environ:
                # run the command only on PythonAnywhere; guard with timeout and capture errors
                try:
                    # This command is the one PythonAnywhere recommends in their docs for user total:
                    # du -s -B 1 /tmp ~/.[!.]* ~/* | awk '{s+=$1}END{print s}'
                    cmd = "du -s -B 1 /tmp ~/.[!.]* ~/* | awk '{s+=$1}END{print s}'"
                    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                    out = proc.stdout.strip()
                    if out:
                        pa_total_used = safe_int(out)
                except Exception:
                    # ignore failures (we don't want to break the whole endpoint)
                    pa_total_used = None

            result["local"] = {
                "used_bytes": used,
                "total_bytes": total,
                "free_bytes": free,
                "free_percent": free_pct,
                "path": local_dir,
                "reported_from": source,
                # optional field only present when running on PythonAnywhere and the command succeeded
                "pythonanywhere_total_used_bytes": pa_total_used
            }
    except Exception as e:
        result["local"] = {"error": f"Failed to determine local storage: {str(e)}"}


    # -------------------
    # Dropbox stats
    # -------------------
    try:
        usage = dbx.users_get_space_usage()
        # usage.used (int)
        used = safe_int(getattr(usage, "used", None))
        total = None
        try:
            # allocation can be team or individual; prefer individual when available
            alloc = getattr(usage, "allocation", None)
            if alloc is not None:
                # allocation might be of different shapes depending on account type
                # try the individual allocation accessor used previously
                try:
                    total = safe_int(alloc.get_individual().allocated)
                except Exception:
                    # fall back to other possible fields
                    total = safe_int(getattr(alloc, "allocated", None) or getattr(alloc, "team", None))
        except Exception:
            total = None

        free = None
        free_pct = None
        if isinstance(total, int) and isinstance(used, int):
            free = max(total - used, 0)
            free_pct = round((free / total) * 100, 2) if total > 0 else None

        result["dropbox"] = {
            "used_bytes": used,
            "total_bytes": total,
            "free_bytes": free,
            "free_percent": free_pct
        }
    except Exception as e:
        # conservative fallback if API fails
        result["dropbox"] = {
            "error": f"Failed to query Dropbox: {str(e)}"
        }

    # -------------------
    # MEGA stats
    # -------------------
    try:
        info = mega_account.get_storage_space()  # expected {'used': X, 'total': Y}
        used = safe_int(info.get("used")) if isinstance(info, dict) else None
        total = safe_int(info.get("total")) if isinstance(info, dict) else None
        free = None
        free_pct = None
        if isinstance(total, int) and isinstance(used, int):
            free = max(total - used, 0)
            free_pct = round((free / total) * 100, 2) if total > 0 else None

        result["mega"] = {
            "used_bytes": used,
            "total_bytes": total,
            "free_bytes": free,
            "free_percent": free_pct
        }
    except Exception as e:
        result["mega"] = {
            "error": f"Failed to query MEGA: {str(e)}"
        }

    return jsonify(result), 200


def verify_file_content(file_path: str, mimetype: str) -> bool:
    """
    Backwards-compatible wrapper.
    Calls the hardened implementation and returns True/False.
    """
    try:
        return bool(verify_file_content_hardened(file_path, mimetype))
    except Exception:
        # In case the hardened version raises unexpectedly, fail closed.
        return False

def verify_and_record_upload(file: FileStorage, user, max_size_bytes=MAX_UPLOAD_SIZE_BYTES):
    """
    Verifies file and uploads to Dropbox if space is available,
    then Mega if space is available, else falls back to local storage.
    Returns (True, Upload) or (False, error_str).
    All exceptions are converted to strings for JSON safety.
    """
    try:
        if file is None:
            return False, "No file provided."

        filename = secure_filename(file.filename)
        if not filename:
            return False, "Invalid filename."
        if not allowed_extension(filename):
            return False, f"Extension not allowed. Allowed: {sorted(ALLOWED_EXTENSIONS)}"

        # Determine file size
        file.stream.seek(0, os.SEEK_END)
        size = file.stream.tell()
        file.stream.seek(0)
        if size > max_size_bytes:
            return False, f"File too large: {size} bytes (max {max_size_bytes} bytes)."

        # Check user quota
        quota = get_user_quota_bytes(user)
        if quota != float("inf") and (user.storage_used_bytes or 0) + size > quota:
            return False, "User storage quota exceeded."

        mimetype = file.mimetype or ''
        if mimetype not in ALLOWED_MIMETYPES and not mimetype.startswith('image/'):
            return False, "MIME type not allowed."

        # Save to temp file for verification
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_name = tmp.name
            file.save(tmp_name)

        if not verify_file_content(tmp_name, mimetype):
            os.remove(tmp_name)
            if user:
                try:
                    user.malicious_violations = (user.malicious_violations or 0) + 1
                    db.session.add(user)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            return False, "Uploaded file failed content verification."

        storage_backend = "local"
        stored_path = None
        mega_file_obj = None

        # --- Read file bytes once for Mega / Dropbox ---
        with open(tmp_name, "rb") as f:
            file_bytes = f.read()

        # --- Try Dropbox first ---
        if dropbox_has_space(size):
            dropbox_path = f"{DROPBOX_UPLOAD_FOLDER}/{uuid.uuid4().hex}_{filename}"
            try:
                dbx.files_upload(file_bytes, dropbox_path, mode=dropbox.files.WriteMode.overwrite)
                storage_backend = "dropbox"
                stored_path = dropbox_path
            except Exception:
                storage_backend = "local"

        elif mega_has_space(size):
            try:
                mega_file_info = mega_account.upload(tmp_name, dest_filename=filename)

                # IMPORTANT: store this immediately
                mega_file_obj = json.dumps(mega_file_info)

                # Generate public link AFTER storing
                stored_path = mega_account.get_upload_link(mega_file_info)

                storage_backend = "mega"
            except Exception as e:
                print(f"exception when uploading to mega!!!: {e}")
                storage_backend = "local"


        # --- Fallback to local ---
        if storage_backend == "local":
            unique = f"{uuid.uuid4().hex}_{filename}"
            stored_path = os.path.join(UPLOAD_FOLDER_LOCAL_FILES, unique)
            try:
                os.replace(tmp_name, stored_path)
            except Exception as e:
                os.remove(tmp_name)
                return False, f"Failed to save locally: {str(e)}"
        else:
            # remove temp file after Mega / Dropbox upload
            os.remove(tmp_name)

        # --- Record in DB ---
        try:
            upload = Upload(
                user_id=user.id,
                original_filename=filename,
                stored_filename=stored_path,
                storage_backend=storage_backend,
                mimetype=mimetype,
                size_bytes=size,
                created_at=datetime.utcnow(),
                deleted=False,
                mega_file_obj=str(mega_file_obj) if mega_file_obj else None  # store string for JSON/DB safety
            )
            db.session.add(upload)
            user.storage_used_bytes = (user.storage_used_bytes or 0) + size
            db.session.commit()
            return True, upload
        except Exception as e:
            # Cleanup in case of DB failure
            try:
                if storage_backend == "dropbox":
                    dbx.files_delete_v2(stored_path)
                elif storage_backend == "local" and os.path.exists(stored_path):
                    os.remove(stored_path)
                elif storage_backend == "mega" and mega_file_obj:
                    try:
                        mega_account.delete(mega_file_obj)
                    except Exception:
                        pass
            except Exception:
                pass
            db.session.rollback()
            return False, str(e)

    except Exception as outer_e:
        return False, str(outer_e)
    
# Force-delete an upload regardless of who the actor is (used for group flows)
def force_delete_upload(upload_id, actor_user=None):
    """
    Force-delete an upload:
      - remove file from disk if present
      - delete from Dropbox or MEGA if applicable
      - mark Upload.deleted = True and set deleted_at
      - subtract size_bytes from the original uploader's storage_used_bytes
    Returns (True, "msg") or (False, "msg")
    """
    upload = Upload.query.get(upload_id)
    if not upload:
        return False, "Upload not found."
    if upload.deleted:
        return True, "Already deleted."

    owner = User.query.get(upload.user_id) if upload.user_id else None
    stored_path = os.path.join(UPLOAD_FOLDER_LOCAL_FILES, upload.stored_filename) if upload.stored_filename else None

    try:
        if upload.storage_backend == "dropbox":
            try:
                dbx.files_delete_v2(upload.stored_filename)
            except Exception:
                pass
        elif upload.storage_backend == "mega" and getattr(upload, "mega_file_obj", None):
            try:
                mega_account.delete(upload.mega_file_obj)
            except Exception:
                app.logger.exception("Failed to delete MEGA file %s", upload.stored_filename)
        elif stored_path and os.path.exists(stored_path):
            try:
                os.remove(stored_path)
            except Exception as e:
                app.logger.exception("Error removing upload file %s: %s", stored_path, e)
    except Exception:
        # ignore any deletion errors — we still want to mark DB as deleted
        pass

    try:
        upload.deleted = True
        upload.deleted_at = datetime.utcnow()
        if owner:
            owner.storage_used_bytes = max(0, (owner.storage_used_bytes or 0) - (upload.size_bytes or 0))

        db.session.add(upload)
        if owner:
            db.session.add(owner)
        db.session.commit()
        return True, "Upload force-deleted."
    except Exception as e:
        db.session.rollback()
        app.logger.exception("DB error while force-deleting upload %s: %s", upload_id, e)
        return False, "Database error while force-deleting upload."


def _note_attachment_ids(note_id):
    return {nu.upload_id for nu in NoteUpload.query.filter_by(note_id=note_id).all()}


def delete_upload(upload_id, user):
    """
    Centralized delete handler.
    Marks upload deleted, removes file from storage (local, Dropbox, or MEGA),
    and subtracts bytes from user's storage_used_bytes.
    Only owner or admins should call this function.
    """
    upload = Upload.query.get(upload_id)
    if not upload:
        return False, "Upload not found."
    if upload.user_id != user.id:
        return False, "Permission denied."
    if upload.deleted:
        return False, "Already deleted."

    try:
        if upload.storage_backend == "dropbox":
            try:
                dbx.files_delete_v2(upload.stored_filename)
            except Exception:
                pass
        # inside your delete_upload function, in the Mega block:
        elif upload.storage_backend == "mega" and getattr(upload, "mega_file_obj", None):
            try:
                # Convert string to dict if necessary
                if isinstance(upload.mega_file_obj, str):
                    mega_file_obj = ast.literal_eval(upload.mega_file_obj)
                else:
                    mega_file_obj = upload.mega_file_obj

                # get public handle of first file
                handle = mega_file_obj['f'][0]['h']
                # request deletion directly
                mega_account._api_request({'a': 'd', 'n': handle})
            except Exception:
                app.logger.exception("Failed to delete MEGA file %s", upload.stored_filename)
        else:
            # Delete from local disk
            stored_path = os.path.join(UPLOAD_FOLDER_LOCAL_FILES, upload.stored_filename)
            if os.path.exists(stored_path):
                try:
                    os.remove(stored_path)
                except Exception as e:
                    app.logger.exception("Error removing upload file %s: %s", stored_path, e)

        # Update DB
        upload.deleted = True
        upload.deleted_at = datetime.utcnow()
        user.storage_used_bytes = max(0, (user.storage_used_bytes or 0) - (upload.size_bytes or 0))
        db.session.commit()
        return True, "Deleted."
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Database error on delete_upload %s: %s", upload_id, e)
        return False, "Database error on delete."

def initialize_user_storage(user_id):
    """
    Initialize storage-related fields for a user.
    This is called when a user is created or when their storage is reset.
    """
    user = User.query.get(user_id)
    if not user:
        return False, "User not found."

    user.storage_used_bytes = 0
    user.base_storage_mb = 50
    db.session.add(user)
    db.session.commit()
    return True, "User storage initialized."

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

@app.errorhandler(418)
def im_a_teapot(e):
    if request.path.startswith('/api') or request.is_json:
        return jsonify({"error": "I'm a teapot"}), 418
    return render_template('418.html'), 418

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

@app.route("/brew-coffee")
def brew_coffee():
    # Pretend your API can't brew coffee
    abort(418)

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
    return render_template('both_notes.html')

@app.route('/notes_page')
def notes_page():
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

@app.route('/trello_page')
def trello_page():
    if check("trello", "Ja") == "Ja":
        return render_template("trello.html")
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

@app.route('/version-management')
def version_management():
    return render_template("version_management.html")

@app.route('/why-protected-usernames')
def why_protected_usernames():
    return render_template("why_protected_usernames.html")

# Homepage / Overview (search & listing)
@app.route("/help")
def help_homepage():
    return render_template("help.html")

# Article detail page
@app.route("/help/article/<string:slug>")
def help_article(slug):
    return render_template("help_article.html", slug=slug)

# Admin overview page (serves the admin UI; UI will auto-login)
@app.route("/help/admin")
def help_admin():
    return render_template("help_admin.html")

# Add/Edit page (admin editor). If editing you can pass ?id=#
@app.route("/help/admin/editor")
def help_editor():
    return render_template("help_admin_editor.html")

@app.route('/2fa_page')
def manage_2fa():
    return render_template("setup_2fa.html")

#---------------------------------API routes--------------------------------


# Create share link (owner only)
@app.route('/notes/<int:note_id>/share', methods=['POST'])
@require_session_key
def create_share(note_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != g.user_id:
        return jsonify({"error": "Note not found or access denied"}), 404

    # optional: expiration in minutes provided by client
    data = request.json or {}
    expires_minutes = data.get('expires_minutes')  # e.g. 60 -> expires in 60 minutes
    expires_at = None
    if expires_minutes:
        try:
            expires_at = datetime.utcnow() + timedelta(minutes=int(expires_minutes))
        except Exception:
            pass

    token = secrets.token_urlsafe(24)
    share = Share(token=token, note_id=note.id, user_id=g.user_id, expires_at=expires_at)
    db.session.add(share)
    db.session.commit()

    share_url = url_for('public_share', token=token, _external=True)
    return jsonify({"token": token, "url": share_url}), 201

# -------------------------------------------------------
# Create a folder share
# -------------------------------------------------------
@app.route('/folders/<int:folder_id>/share', methods=['POST'])
@require_session_key
def create_folder_share(folder_id):
    # ensure folder exists and belongs to user (or group logic if needed)
    folder = Folder.query.get(folder_id)
    if not folder or folder.user_id != g.user_id:
        return jsonify({"error": "Folder not found or access denied"}), 404

    data = request.json or {}
    expires_minutes = data.get('expires_minutes')
    expires_at = None
    if expires_minutes:
        try:
            expires_at = datetime.utcnow() + timedelta(minutes=int(expires_minutes))
        except Exception:
            pass

    # generate token once
    token = secrets.token_urlsafe(24)

    try:
        # collect all folder and note ids under this folder (root included)
        folder_ids, note_ids = collect_folder_tree_ids(folder_id)

        # create a Share row for the root folder first (we will use it for visit counting)
        root_share = Share(token=token, folder_id=folder_id, user_id=g.user_id, expires_at=expires_at)
        db.session.add(root_share)
        db.session.flush()  # so root_share.id exists

        # create share rows for all other folder nodes (including root again is OK if unique constraint removed)
        for fid in folder_ids:
            if fid == folder_id:
                continue
            s = Share(token=token, folder_id=fid, user_id=g.user_id, expires_at=expires_at)
            db.session.add(s)

        # create share rows for notes
        for nid in note_ids:
            s = Share(token=token, note_id=nid, user_id=g.user_id, expires_at=expires_at)
            db.session.add(s)

        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to create folder share for folder=%s user=%s", folder_id, g.user_id)
        return jsonify({"error": "DB error while creating share"}), 500

    share_url = url_for('public_share', token=token, _external=True)
    return jsonify({"token": token, "url": share_url}), 201

# Revoke share (owner only)
@app.route('/notes/share/<token>', methods=['DELETE'])
@require_session_key
def revoke_share(token):
    share = Share.query.filter_by(token=token, user_id=g.user_id).first()
    if not share:
        return jsonify({"error": "Share not found or access denied"}), 404
    try:
        ShareVisit.query.filter_by(share_id=share.id).delete()
        db.session.delete(share)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "DB error while revoking share"}), 500
    return jsonify({"message": "Share revoked"}), 200

# -------------------------------------------------------
# Revoke folder share (by token)
# -------------------------------------------------------
@app.route('/folders/share/<token>', methods=['DELETE'])
@require_session_key
def revoke_folder_share(token):
    # find shares owned by user with this token
    shares = Share.query.filter_by(token=token, user_id=g.user_id).all()
    if not shares:
        return jsonify({"error": "Share not found or access denied"}), 404

    try:
        # delete any ShareVisit rows for these shares
        share_ids = [s.id for s in shares]
        ShareVisit.query.filter(ShareVisit.share_id.in_(share_ids)).delete(synchronize_session=False)
        # delete shares
        Share.query.filter(Share.id.in_(share_ids)).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("DB error while revoking folder share token=%s owner=%s", token, g.user_id)
        return jsonify({"error": "DB error while revoking share"}), 500

    return jsonify({"message": "Share revoked"}), 200


from datetime import datetime
from flask import render_template

@app.route('/s/<token>', methods=['GET'])
def public_share(token):
    # fetch shared node sets
    folder_ids, note_ids, root_folder_id, root_note_id = get_shared_node_sets_for_token(token)

    # default safe value for template
    display_folder_id = None

    if not folder_ids and not note_ids:
        # no shares for token
        return render_template('shared_not_found.html', token=token), 404

    # check if any share is still valid
    now = datetime.utcnow()
    any_unexpired = any(
        (s.expires_at is None or s.expires_at > now)
        for s in Share.query.filter_by(token=token).all()
    )
    if not any_unexpired:
        return render_template('share_expired.html', token=token, expired_at=now), 410

    # handle explicit note query
    q_note_id = request.args.get('note_id', type=int)
    if q_note_id:
        if not token_has_access_to_note(token, q_note_id):
            return render_template('shared_not_found.html', token=token), 404

        note = Note.query.get(q_note_id)
        if not note:
            return render_template('shared_not_found.html', token=token), 404

        safe_note_html = sanitize_html(note.note)
        attachments = []
        for nu in NoteUpload.query.filter_by(note_id=note.id).all():
            up = Upload.query.get(nu.upload_id)
            if up and not up.deleted:
                attachments.append({
                    "upload_id": up.id,
                    "filename": up.original_filename,
                    "size_bytes": up.size_bytes,
                    "mimetype": up.mimetype
                })

        lang = request.accept_languages.best_match(['nl', 'en'])
        template = "shared_note.html" if lang != 'nl' else "shared_note_dutch.html"

        # determine folder for back button
        return_folder_id = request.args.get('folder_id', type=int) or note.folder_id

        return render_template(
            template,
            token=token,
            note_id=note.id,
            note_title=note.title,
            note_html=safe_note_html,
            note_tag=note.tag,
            attachments=attachments,
            is_folder_view=False,
            return_folder_id=return_folder_id,
            display_folder_id=return_folder_id
        ), 200

    # handle note-only share
    if note_ids and not folder_ids:
        note = Note.query.get(root_note_id)
        if not note:
            return render_template('shared_not_found.html', token=token), 404

        safe_note_html = sanitize_html(note.note)
        attachments = []
        for nu in NoteUpload.query.filter_by(note_id=note.id).all():
            up = Upload.query.get(nu.upload_id)
            if up and not up.deleted:
                attachments.append({
                    "upload_id": up.id,
                    "filename": up.original_filename,
                    "size_bytes": up.size_bytes,
                    "mimetype": up.mimetype
                })

        lang = request.accept_languages.best_match(['nl', 'en'])
        template = "shared_note.html" if lang != 'nl' else "shared_note_dutch.html"

        return render_template(
            template,
            token=token,
            note_id=note.id,
            note_title=note.title,
            note_html=safe_note_html,
            note_tag=note.tag,
            attachments=attachments,
            is_folder_view=False,
            display_folder_id=None
        ), 200

    # handle folder share or mixed share
    q_folder_id = request.args.get('folder_id', type=int)
    if q_folder_id and q_folder_id in folder_ids:
        display_folder_id = q_folder_id
    else:
        display_folder_id = root_folder_id or (next(iter(folder_ids)) if folder_ids else None)

    if display_folder_id is None:
        return render_template('shared_not_found.html', token=token), 404

    # fetch folder name for header/title
    folder_obj = Folder.query.get(display_folder_id)
    display_folder_name = folder_obj.name if folder_obj else None

    lang = request.accept_languages.best_match(['nl', 'en'])
    template = "shared_note.html" if lang != 'nl' else "shared_note_dutch.html"

    # fetch children folders
    child_folders = Folder.query.filter_by(parent_id=display_folder_id).all()

    # fetch notes inside folder
    child_notes = Note.query.filter_by(folder_id=display_folder_id).all()

    # add preview text
    notes_payload = []
    for n in child_notes:
        notes_payload.append({
            "id": n.id,
            "title": n.title,
            "tag": n.tag,
            "preview": extract_text_preview(n.note),
        })

    folders_payload = [{"id": f.id, "name": f.name} for f in child_folders]


    return render_template(
        template,
        token=token,
        note_id=None,
        note_title=None,
        note_html=None,
        note_tag=None,
        attachments=[],
        is_folder_view=True,
        display_folder_id=display_folder_id,
        display_folder_name=display_folder_name,
        folders=folders_payload,
        notes=notes_payload,
    )


# -------------------------------------------------------
# API: get folder contents for a token
# -------------------------------------------------------
@app.route('/s/<token>/api/folder/<int:folder_id>', methods=['GET'])
def shared_folder_contents(token, folder_id):
    folder_ids, note_ids, root_folder_id, root_note_id = get_shared_node_sets_for_token(token)
    if not folder_ids:
        return jsonify({"ok": False, "reason": "not_a_folder_share"}), 404

    if folder_id not in folder_ids:
        return jsonify({"ok": False, "reason": "access_denied"}), 404

    # get folder metadata for the folder we are showing (so client has parent_id + name)
    folder = Folder.query.get(folder_id)
    folder_meta = None
    if folder:
        # if you have to_dict(), use that; otherwise provide minimal fields
        try:
            folder_meta = folder.to_dict()
        except Exception:
            folder_meta = {"id": folder.id, "name": folder.name, "parent_id": folder.parent_id}

    # list child folders that are also shared
    child_folders = (Folder.query
                     .filter(Folder.parent_id == folder_id, Folder.id.in_(list(folder_ids)))
                     .order_by(Folder.name.asc())
                     .all())

    # list notes in this folder that are shared
    notes = (Note.query
             .filter(Note.folder_id == folder_id, Note.id.in_(list(note_ids)))
             .order_by(Note.title.asc())
             .all())

    folder_list = [f.to_dict() for f in child_folders]
    note_list = [
        {
            "id": n.id,
            "title": n.title,
            "tag": n.tag,
            "preview": extract_text_preview(n.note),  # <-- add this
        }
        for n in notes
    ]


    return jsonify({
        "ok": True,
        "folder_id": folder_id,
        "folder": folder_meta,
        "folders": folder_list,
        "notes": note_list,
    }), 200

@app.route('/s/<token>/visit', methods=['POST'])
@get_user_from_session
def public_share_visit(token):
    # pick canonical share row for counting visits: use first created share for the token
    share = (Share.query
             .filter(Share.token == token)
             .order_by(Share.created_at.asc())
             .first())
    if not share:
        return jsonify({"ok": False, "reason": "share_not_found"}), 404

    data = request.get_json(silent=True) or {}
    fingerprint_hash = (data.get('fingerprint_hash') or '').strip()
    ip = client_ip()

    if not fingerprint_hash or not ip:
        current_app.logger.debug(
            "Visit ignored: missing fingerprint or ip (token=%s, ip=%s, fp=%s)",
            token, bool(ip), bool(fingerprint_hash)
        )
        return jsonify({"ok": True, "counted": False, "reason": "missing_fp_or_ip"}), 200

    # Skip counting if the visitor is the owner
    if g.get('user_id') is not None and g.user_id == share.user_id:
        current_app.logger.debug(
            "Visit ignored: visitor is the owner (token=%s, user_id=%s)",
            token, g.user_id
        )
        return jsonify({"ok": True, "counted": False, "reason": "self_visit"}), 200

    now = datetime.utcnow()
    window_start = now - timedelta(seconds=SHARE_VISIT_WINDOW_SECONDS)

    try:
        # Check if a recent visit exists from this fingerprint/ip
        existing = (ShareVisit.query
                    .filter(ShareVisit.share_id == share.id,
                            ShareVisit.fingerprint_hash == fingerprint_hash,
                            ShareVisit.ip == ip,
                            ShareVisit.created_at >= window_start)
                    .with_for_update(read=False)
                    .first())
        if existing:
            existing.created_at = now
            db.session.add(existing)
            db.session.commit()
            return jsonify({"ok": True, "counted": False, "reason": "extended"}), 200

        # Add new visit
        visit = ShareVisit(
            share_id=share.id,
            ip=ip,
            user_agent=request.headers.get('User-Agent'),
            fingerprint_hash=fingerprint_hash,
            created_at=now
        )
        db.session.add(visit)
        share.access_count = (share.access_count or 0) + 1
        db.session.add(share)
        db.session.commit()
        return jsonify({"ok": True, "counted": True, "new_count": share.access_count}), 200
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to record visit for share token=%s", token)
        return jsonify({"ok": False, "reason": "db_error"}), 500

# -------------------
# Board endpoints
# -------------------

@app.route('/api/boards', methods=['GET'])
@require_session_key
def api_get_boards():
    """Return top-level boards for the user (no lists included)."""
    user_id = g.user_id
    boards = Board.query.filter_by(user_id=user_id).order_by(Board.id).all()
    out = [{"id": b.id, "title": b.title, "created_at": b.created_at.isoformat()} for b in boards]
    return jsonify(out)

@app.route('/api/boards', methods=['POST'])
@require_session_key
def api_create_board():
    user_id = g.user_id
    payload = request.get_json() or {}
    title = (payload.get('title') or '').strip()
    if not title:
        return jsonify({"error": "Title required"}), 400
    board = Board(user_id=user_id, title=title)
    db.session.add(board)
    db.session.flush()  # get board.id
    default_lists = ['To Do', 'In Progress', 'Done']
    for ordernr, list_title in enumerate(default_lists):
        l = List(user_id=user_id, board_id=board.id, title=list_title, ordernr=ordernr)
        db.session.add(l)
    db.session.commit()
    return jsonify({"id": board.id, "title": board.title}), 201

@app.route('/api/boards/<int:board_id>/background_uploads', methods=['POST'])
@require_session_key
def attach_board_background(board_id):
    """
    Body JSON: { "upload_id": <int> }
    Attaches an existing upload (already validated & stored by /uploads) as the board background.
    If a previous background exists it will be unlinked (deleted from BoardBackgroundUpload),
    but the actual Upload row is NOT deleted here.
    """
    user = g.user if hasattr(g, 'user') else User.query.get(g.user_id)
    board = Board.query.filter_by(id=board_id, user_id=user.id).first()
    if not board:
        return jsonify({"error": "Board not found"}), 404

    data = request.get_json() or {}
    upload_id = data.get('upload_id')
    if not upload_id:
        return jsonify({"error": "upload_id required"}), 400

    upload = Upload.query.filter_by(id=upload_id, user_id=user.id, deleted=False).first()
    if not upload:
        return jsonify({"error": "Upload not found"}), 404

    # remove any existing background link for this board
    existing = BoardBackgroundUpload.query.filter_by(board_id=board.id).first()
    if existing:
        db.session.delete(existing)

    bbu = BoardBackgroundUpload(board_id=board.id, upload_id=upload.id)
    db.session.add(bbu)
    db.session.commit()

    return jsonify({
        "upload_id": upload.id,
        "url": get_upload_url(upload)
    }), 201

@app.route('/api/boards/<int:board_id>', methods=['PATCH'])
@require_session_key
def api_rename_board(board_id):
    user_id = g.user_id
    b = Board.query.filter_by(id=board_id, user_id=user_id).first()
    if not b:
        return jsonify({"error": "Board not found"}), 404
    payload = request.get_json() or {}
    title = (payload.get('title') or '').strip()
    if not title:
        return jsonify({"error": "Title required"}), 400
    b.title = title
    db.session.commit()
    return jsonify({"id": b.id, "title": b.title})

@app.route('/api/boards/color/<int:board_id>', methods=['PATCH'])
@require_session_key
def api_change_board_color(board_id):
    user_id = g.user_id
    b = Board.query.filter_by(id=board_id, user_id=user_id).first()
    if not b:
        return jsonify({"error": "Board not found"}), 404
    payload = request.get_json() or {}
    color = payload.get('color')
    if payload['color'] == "none":
        b.background_color = None
    else:
        b.background_color = color
    db.session.commit()
    return jsonify({"id": b.id, "color": b.background_color})

@app.route('/api/boards/<int:board_id>/background_uploads', methods=['DELETE'])
@require_session_key
def detach_board_background(board_id):
    """
    Removes the association between board and upload.
    Returns the upload_id so the frontend may call the generic upload-delete endpoint if desired.
    """
    user = g.user if hasattr(g, 'user') else User.query.get(g.user_id)
    board = Board.query.filter_by(id=board_id, user_id=user.id).first()
    if not board:
        return jsonify({"error": "Board not found"}), 404

    existing = BoardBackgroundUpload.query.filter_by(board_id=board.id).first()
    if not existing:
        return jsonify({"error": "No background image attached"}), 404

    upload_id = existing.upload_id
    db.session.delete(existing)
    db.session.commit()

    return jsonify({"upload_id": upload_id}), 200


@app.route('/api/boards/<int:board_id>', methods=['DELETE'])
@require_session_key
def api_delete_board(board_id):
    user_id = g.user_id
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 401

    b = Board.query.filter_by(id=board_id, user_id=user_id).first()
    if not b:
        return jsonify({"error": "Board not found"}), 404
    bg = BoardBackgroundUpload.query.filter_by(board_id=board_id).first()

    if bg:
        if bg.upload:
            delete_upload(bg.upload.id, user)
        db.session.delete(bg)

    # cascading deletes should remove lists & cards but delete them anyway to be sure
    lists = List.query.filter_by(board_id=b.id, user_id=user_id).all()
    for l in lists:
        cards = Card.query.filter_by(list_id=l.id, user_id=user_id).all()
        for c in cards:
            c_bg = CardBackgroundUpload.query.filter_by(card_id=c.id).first()
            if c_bg:
                delete_upload(c_bg.upload_id, user)
                db.session.delete(c_bg)
            # delete card activities
            activities = CardActivity.query.filter_by(card_id=c.id).all()
            for a in activities:
                db.session.delete(a)
            db.session.delete(c)
        db.session.delete(l)
    db.session.delete(b)
    db.session.commit()
    return jsonify({"ok": True})


# -------------------
# List endpoints (these replace the old "boards as columns")
# -------------------

@app.route('/api/lists', methods=['GET'])
@require_session_key
def api_get_lists():
    """
    Query param: board_id (required)
    Returns lists and their cards for the authenticated user belonging to the board.
    Includes card background images.
    """
    user_id = g.user_id
    board_id = request.args.get('board_id', type=int)
    if board_id is None:
        return jsonify({"error": "board_id required as query param"}), 400

    # ensure board exists and belongs to user
    board = Board.query.filter_by(id=board_id, user_id=user_id).first()
    if not board:
        return jsonify({"error": "Board not found"}), 404

    # determine board background image url if present
    board_bg = BoardBackgroundUpload.query.filter_by(board_id=board.id).first()
    board_background_image_url = None
    if board_bg:
        upload = Upload.query.filter_by(id=board_bg.upload_id, deleted=False).first()
        if upload:
            board_background_image_url = get_upload_url(upload)

    # fetch all lists for board
    lists = List.query.filter_by(user_id=user_id, board_id=board_id).order_by(List.id).all()
    list_ids = [l.id for l in lists]

    # fetch all cards for those lists
    cards = Card.query.filter(Card.user_id==user_id, Card.list_id.in_(list_ids)).order_by(Card.position).all()
    card_ids = [c.id for c in cards]

    # fetch all card background uploads in one query
    card_bg_map = {}
    if card_ids:
        card_bgs = CardBackgroundUpload.query.filter(CardBackgroundUpload.card_id.in_(card_ids)).all()
        upload_ids = [bg.upload_id for bg in card_bgs]
        uploads = {u.id: u for u in Upload.query.filter(Upload.id.in_(upload_ids), Upload.deleted==False).all()}

        # map card_id -> background url
        for bg in card_bgs:
            u = uploads.get(bg.upload_id)
            if u:
                card_bg_map[bg.card_id] = get_upload_url(u)

    # build output
    out = []
    for l in lists:
        l_cards = [c for c in cards if c.list_id == l.id]
        out.append({
            "id": l.id,
            "title": l.title,
            "order": l.ordernr,
            "color": l.background_color,
            "cards": [
                {
                    "id": c.id,
                    "title": c.title,
                    "description": c.description or "",
                    "position": c.position,
                    "completed": c.completed,
                    "color": c.background_color,
                    "background_image_url": card_bg_map.get(c.id)  # None if no background
                }
                for c in l_cards
            ]
        })

    return jsonify({
        "board_color": board.background_color,
        "board_background_image_url": board_background_image_url,
        "lists": out
    })


@app.route('/api/lists', methods=['POST'])
@require_session_key
def api_create_list():
    user_id = g.user_id
    payload = request.get_json() or {}
    title = (payload.get('title') or '').strip()
    board_id = payload.get('board_id') or payload.get('board')  # accept either name
    if not title or board_id is None:
        return jsonify({"error": "title and board_id required"}), 400
    # ensure board belongs to user
    if not Board.query.filter_by(id=board_id, user_id=user_id).first():
        return jsonify({"error": "Board not found"}), 404
    # make sure the new list always gets the highest ordernr
    max_ordernr = db.session.query(db.func.max(List.ordernr)).filter_by(user_id=user_id, board_id=board_id).scalar()
    if max_ordernr is None:
        max_ordernr = 0
    else:
        max_ordernr += 1
    l = List(user_id=user_id, board_id=board_id, title=title, ordernr=max_ordernr)
    db.session.add(l)
    db.session.commit()
    return jsonify({"id": l.id, "title": l.title}), 201

@app.route('/api/lists/copy/<int:list_id>', methods=['POST'])
@require_session_key
def api_copy_list(list_id):
    user_id = g.user_id
    l = List.query.filter_by(id=list_id, user_id=user_id).first()
    if not l:
        return jsonify({"error": "List not found"}), 404
    # ensure board belongs to user
    if not Board.query.filter_by(id=l.board_id, user_id=user_id).first():
        return jsonify({"error": "Board not found"}), 404
    # make sure the new list always gets the highest ordernr
    max_ordernr = db.session.query(db.func.max(List.ordernr)).filter_by(user_id=user_id, board_id=l.board_id).scalar()
    if max_ordernr is None:
        max_ordernr = 0
    else:
        max_ordernr += 1
    new_list = List(user_id=user_id, board_id=l.board_id, title=f"Copy of {l.title}", ordernr=max_ordernr)
    db.session.add(new_list)
    db.session.commit()
    # copy cards from the original list to the new list
    cards = Card.query.filter_by(list_id=l.id, user_id=user_id).all()
    for c in cards:
        new_card = Card(
            user_id=user_id,
            list_id=new_list.id,
            title=c.title,
            description=c.description,
            position=c.position,
            completed=c.completed
        )
        db.session.add(new_card)
        db.session.commit()
    return jsonify({"id": new_list.id, "title": new_list.title}), 201

@app.route('/api/lists/<int:list_id>', methods=['PATCH'])
@require_session_key
def api_rename_list(list_id):
    user_id = g.user_id
    l = List.query.filter_by(id=list_id, user_id=user_id).first()
    if not l:
        return jsonify({"error": "List not found"}), 404
    payload = request.get_json() or {}
    if 'title' in payload:
        l.title = payload['title']
        db.session.commit()
    return jsonify({"id": l.id, "title": l.title})

# Make the list order adjustable
@app.route('/api/lists/order/<int:list_id>', methods=['PATCH'])
@require_session_key
def api_order_list(list_id):
    user_id = g.user_id
    l = List.query.filter_by(id=list_id, user_id=user_id).first()
    if not l:
        return jsonify({"error": "List not found"}), 404
    payload = request.get_json() or {}
    if 'order' in payload:
        l.ordernr = payload['order']
        db.session.commit()
    return jsonify({"id": l.id, "order": l.ordernr})

@app.route('/api/lists/color/<int:list_id>', methods=['PATCH'])
@require_session_key
def api_color_list(list_id):
    user_id = g.user_id
    l = List.query.filter_by(id=list_id, user_id=user_id).first()
    if not l:
        return jsonify({"error": "List not found"}), 404
    payload = request.get_json() or {}
    if 'color' in payload:
        print(payload['color'])
        if payload['color'] == "none":
            l.background_color = None
        l.background_color = payload['color']
        db.session.commit()
    return jsonify({"id": l.id, "color": l.background_color})

@app.route('/api/lists/<int:list_id>', methods=['DELETE'])
@require_session_key
def api_delete_list(list_id):
    user_id = g.user_id
    user = User.query.get(user_id)
    l = List.query.filter_by(id=list_id, user_id=user_id).first()
    if not l:
        return jsonify({"error": "List not found"}), 404
    # delete cards in the list
    cards = Card.query.filter_by(list_id=l.id, user_id=user_id).all()
    for c in cards:
        background_image = CardBackgroundUpload.query.filter_by(card_id=c.id).first()
        if background_image:
            delete_upload(background_image.upload_id, user)
            db.session.delete(background_image)
        # delete card activities
        activities = CardActivity.query.filter_by(card_id=c.id).all()
        for a in activities:
            db.session.delete(a)
        db.session.delete(c)

    db.session.delete(l)
    db.session.commit()
    return jsonify({"ok": True})

# -------------------
# Cards endpoints
# -------------------

@app.route('/api/cards/info/<int:card_id>', methods=['GET'])
@require_session_key
def api_get_card_info(card_id):
    user_id = g.user_id
    card = Card.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    # Determine background image for the card
    card_bg = CardBackgroundUpload.query.filter_by(card_id=card.id).first()
    card_background_image_url = None
    if card_bg:
        upload = Upload.query.filter_by(id=card_bg.upload_id, deleted=False).first()
        if upload:
            card_background_image_url = get_upload_url(upload)

    return jsonify({
        "id": card.id,
        "title": card.title,
        "description": card.description or "",
        "position": card.position,
        "completed": card.completed,
        "color": card.background_color,
        "background_image_url": card_background_image_url
    })

@app.route('/api/cards/<int:card_id>/activity', methods=['GET'])
@require_session_key
def api_get_card_activity(card_id):
    user_id = g.user_id
    card = Card.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404
    card_username = User.query.filter_by(id=card.user_id).first().username
    activities = CardActivity.query.filter_by(card_id=card.id).order_by(CardActivity.created_at.desc()).all()
    return jsonify([{
        "id": a.id,
        "type": a.activity_type,
        "card_id": a.card_id,
        "user_id": a.user_id,
        "username": card_username,
        "content": a.content,
        "created_at": a.created_at
    } for a in activities])

@app.route('/api/card/<int:card_id>/comment', methods=['POST'])
@require_session_key
def api_add_comment(card_id):
    user_id = g.user_id
    card = Card.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404
    
    username = User.query.filter_by(id=user_id).first().username
    payload = request.get_json() or {}
    content = payload.get('content', '').strip()
    if not content:
        return jsonify({"error": "Comment content required"}), 400
    comment = CardActivity(user_id=user_id, card_id=card.id, activity_type="comment", content=content)
    db.session.add(comment)
    db.session.commit()
    return jsonify({"id": comment.id, "user_id": comment.user_id, "username": username, "content": comment.content})

@app.route('/api/card/comment/<int:comment_id>', methods=['PATCH'])
@require_session_key
def api_edit_comment(comment_id):
    user_id = g.user_id
    comment = CardActivity.query.filter_by(id=comment_id, user_id=user_id).first()
    if not comment:
        return jsonify({"error": "Comment not found"}), 404
    if not comment.activity_type == "comment":
        return jsonify({"error": "Not a comment"}), 400
    payload = request.get_json() or {}
    content = payload.get('content', '').strip()
    if not content:
        return jsonify({"error": "Comment content required"}), 400
    comment.content = content
    db.session.commit()
    return jsonify({"id": comment.id, "user_id": comment.user_id, "content": comment.content})

@app.route('/api/cards/color/<int:card_id>', methods=['PATCH'])
@require_session_key
def api_change_card_color(card_id):
    user_id = g.user_id
    c = Card.query.filter_by(id=card_id, user_id=user_id).first()
    if not c:
        return jsonify({"error": "Card not found"}), 404
    payload = request.get_json() or {}
    color = payload.get('color')
    if payload['color'] == "none":
        c.background_color = None
    else:
        c.background_color = color
    db.session.commit()
    return jsonify({"id": c.id, "color": c.background_color})

@app.route('/api/card/comment/<int:comment_id>', methods=['DELETE'])
@require_session_key
def api_delete_comment(comment_id):
    user_id = g.user_id
    comment = CardActivity.query.filter_by(id=comment_id, user_id=user_id).first()
    if not comment:
        return jsonify({"error": "Comment not found"}), 404
    if not comment.activity_type == "comment":
        return jsonify({"error": "Not a comment"}), 400
    db.session.delete(comment)
    db.session.commit()
    return jsonify({"ok": True})

@app.route('/api/cards', methods=['POST'])
@require_session_key
def api_create_card():
    user_id = g.user_id
    payload = request.get_json() or {}
    title = (payload.get('title') or '').strip()
    # accept either list_id (new) or board_id (compat)
    list_id = payload.get('list_id') or payload.get('board_id') or payload.get('board')  # keep compat
    description = payload.get('description') or ''
    if not title or list_id is None:
        return jsonify({"error": "title and list_id required"}), 400
    # ensure list exists and belongs to user
    list_obj = List.query.filter_by(id=list_id, user_id=user_id).first()
    if not list_obj:
        return jsonify({"error": "List not found"}), 404
    max_pos = db.session.query(db.func.max(Card.position)).filter_by(user_id=user_id, list_id=list_id).scalar()
    position = ((max_pos or 0) + 1000)
    card = Card(user_id=user_id, list_id=list_id, title=title, description=description, position=position)
    db.session.add(card)
    db.session.commit()
    return jsonify({"id": card.id, "title": card.title, "description": card.description or "", "position": card.position}), 201

@app.route('/api/cards/<int:card_id>/background_uploads', methods=['POST'])
@require_session_key
def attach_card_background(card_id):
    """
    Body JSON: { "upload_id": <int> }
    Attaches an existing upload (already validated & stored by /uploads) as the card background.
    If a previous background exists it will be unlinked (deleted from CardBackgroundUpload),
    but the actual Upload row is NOT deleted here.
    """
    user = g.user if hasattr(g, 'user') else User.query.get(g.user_id)
    card = Card.query.filter_by(id=card_id, user_id=user.id).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    data = request.get_json() or {}
    upload_id = data.get('upload_id')
    if not upload_id:
        return jsonify({"error": "upload_id required"}), 400

    upload = Upload.query.filter_by(id=upload_id, user_id=user.id, deleted=False).first()
    if not upload:
        return jsonify({"error": "Upload not found"}), 404

    # remove any existing background link for this board
    existing = CardBackgroundUpload.query.filter_by(card_id=card.id).first()
    if existing:
        db.session.delete(existing)

    bbu = CardBackgroundUpload(card_id=card.id, upload_id=upload.id)
    db.session.add(bbu)
    db.session.commit()

    return jsonify({
        "upload_id": upload.id,
        "url": get_upload_url(upload)
    }), 201


@app.route('/api/cards/<int:card_id>', methods=['PATCH'])
@require_session_key
def api_update_card(card_id):
    user_id = g.user_id

    card = Card.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    payload = request.get_json() or {}

    title_changed = False
    description_changed = False

    if 'title' in payload and payload['title'] != card.title:
        card.title = payload['title']
        title_changed = True

    if 'description' in payload and payload['description'] != card.description:
        card.description = payload['description']
        description_changed = True

    if title_changed:
        insert_card_activity(
            user_id,
            card.id,
            f"Card title updated to '{card.title}'"
        )

    if description_changed:
        insert_card_activity(
            user_id,
            card.id,
            "Card description updated"
        )

    db.session.commit()

    return jsonify({
        "id": card.id,
        "title": card.title,
        "description": card.description or ""
    })

@app.route('/api/cards/complete/<int:card_id>', methods=['PATCH'])
@require_session_key
def api_complete_card(card_id):
    user_id = g.user_id

    card = Card.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    payload = request.get_json() or {}

    if 'completed' in payload:
        card.completed = bool(payload['completed'])

        status = "Complete" if card.completed else "Uncomplete"
        insert_card_activity(
            user_id,
            card.id,
            f"Card set to {status}"
        )

        db.session.commit()

    return jsonify({
        "id": card.id,
        "completed": card.completed
    })

@app.route('/api/cards/<int:card_id>/background_uploads', methods=['DELETE'])
@require_session_key
def detach_card_background(card_id):
    """
    Removes the association between board and upload.
    Returns the upload_id so the frontend may call the generic upload-delete endpoint if desired.
    """
    user = g.user if hasattr(g, 'user') else User.query.get(g.user_id)
    card = Card.query.filter_by(id=card_id, user_id=user.id).first()
    if not card:
        return jsonify({"error": "Board not found"}), 404

    existing = CardBackgroundUpload.query.filter_by(card_id=card.id).first()
    if not existing:
        return jsonify({"error": "No background image attached"}), 404

    upload_id = existing.upload_id
    db.session.delete(existing)
    db.session.commit()

    return jsonify({"upload_id": upload_id}), 200

@app.route('/api/cards/<int:card_id>', methods=['DELETE'])
@require_session_key
def api_delete_card(card_id):
    user_id = g.user_id
    user = User.query.get(g.user_id)
    card = Card.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404
    background_image = CardBackgroundUpload.query.filter_by(card_id=card.id).first()
    if background_image:
        delete_upload(background_image.upload_id, user)
        db.session.delete(background_image)
    # delete card activities
    activities = CardActivity.query.filter_by(card_id=card.id).all()
    for a in activities:
        db.session.delete(a)
    db.session.delete(card)
    db.session.commit()
    return jsonify({"ok": True})


@app.route('/api/cards/move', methods=['POST'])
@require_session_key
def api_move_card():
    """
    Move card to other list and reorder destination.
    Payload:
      { "card_id": int, "to_list_id": int OR "to_board_id" (compat),
        "order_in_list": [card_id,...] }
    """
    user_id = g.user_id
    payload = request.get_json() or {}

    card_id = payload.get('card_id')
    to_list_id = payload.get('to_list_id') or payload.get('to_board_id')  # backward compatibility
    order = payload.get('order_in_board') or payload.get('order_in_list') or []

    if not card_id or to_list_id is None:
        return jsonify({"error": "card_id and to_list_id required"}), 400

    card = Card.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        return jsonify({"error": "Card not found"}), 404

    dest_list = List.query.filter_by(id=to_list_id, user_id=user_id).first()
    if not dest_list:
        return jsonify({"error": "Destination list not found"}), 404
    
    should_insert_activity = True

    if card.list_id == to_list_id:
        should_insert_activity = False

    # Move card
    card.list_id = to_list_id
    db.session.add(card)

    if should_insert_activity == True:
        insert_card_activity(
            user_id,
            card_id,
            f"Card moved to list '{dest_list.title}'"
        )

    try:
        for idx, cid in enumerate(order):
            c = Card.query.filter_by(id=cid, user_id=user_id).first()
            if c:
                c.position = (idx + 1) * 1000
                db.session.add(c)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify(
            {"error": "Could not reorder cards", "detail": str(e)},
            500
        )

    return jsonify({"ok": True})


@app.route('/api/lists/<int:list_id>/reorder', methods=['POST'])
@require_session_key
def api_reorder_list(list_id):
    """Reorder cards inside a list. Payload: {"order": [card_id,...]}"""
    user_id = g.user_id
    payload = request.get_json() or {}
    order = payload.get('order', [])
    if not List.query.filter_by(id=list_id, user_id=user_id).first():
        return jsonify({"error": "List not found"}), 404
    try:
        for i, cid in enumerate(order):
            c = Card.query.filter_by(id=cid, user_id=user_id, list_id=list_id).first()
            if c:
                c.position = (i + 1) * 1000
                db.session.add(c)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Could not reorder", "detail": str(e)}), 500
    return jsonify({"ok": True})
    
import os
from werkzeug.datastructures import FileStorage
from flask import current_app, jsonify, abort, g
from datetime import datetime

@app.route('/s/<token>/save', methods=["POST"])
@require_session_key
def save_note(token):
    user = User.query.get(g.user_id)
    if not user:
        abort(401)

    share = (Share.query
             .filter(Share.token == token)
             .order_by(Share.created_at.asc())
             .first())
    if not share:
        abort(404)

    now = datetime.utcnow()
    any_unexpired = any((s.expires_at is None or s.expires_at > now) for s in Share.query.filter_by(token=token).all())
    if not any_unexpired:
        abort(410)

    requested_note_id = request.args.get('note_id', type=int)
    if share.note_id and requested_note_id is None:
        target_note = Note.query.get(share.note_id)
    else:
        if not requested_note_id:
            abort(400, description="note_id required for folder share")
        if not token_has_access_to_note(token, requested_note_id):
            abort(404)
        target_note = Note.query.get(requested_note_id)

    if not target_note:
        abort(404)

    original = target_note
    created_uploads = []

    def cleanup_created_uploads():
        """Remove partially copied uploads if we hit an error"""
        for up in created_uploads:
            try:
                db_up = Upload.query.get(up.id)
                if not db_up:
                    continue

                stored_path = os.path.join(
                    current_app.config.get("UPLOAD_FOLDER_LOCAL_FILES") or UPLOAD_FOLDER_LOCAL_FILES,
                    db_up.stored_filename
                )
                # If stored in local filesystem, remove file
                if db_up.storage_backend == "local" and os.path.exists(stored_path):
                    try:
                        os.remove(stored_path)
                    except Exception:
                        current_app.logger.exception("Failed to remove local file during cleanup %s", stored_path)

                # If stored in dropbox, try to delete it (best-effort)
                if db_up.storage_backend == "dropbox":
                    try:
                        dbx.files_delete_v2(db_up.stored_filename)
                    except Exception:
                        current_app.logger.exception("Failed to remove Dropbox file during cleanup %s", db_up.stored_filename)

                # If MEGA, try to delete via mega_account (best-effort)
                if db_up.storage_backend == "mega" and getattr(db_up, "mega_file_obj", None):
                    try:
                        mega_account.delete(db_up.mega_file_obj)
                    except Exception:
                        current_app.logger.exception("Failed to remove MEGA file during cleanup %s", db_up.stored_filename)

                u = User.query.get(user.id)
                u.storage_used_bytes = max(0, (u.storage_used_bytes or 0) - (db_up.size_bytes or 0))
                db.session.add(u)
                db.session.delete(db_up)
                db.session.commit()
            except Exception:
                db.session.rollback()
                current_app.logger.exception("Cleanup failed for upload %s", getattr(up, "id", None))

    try:
        new_note = Note(
            title=original.title,
            note=original.note,
            tag=original.tag,
            user_id=user.id,
            group_id=None,
            folder_id=None
        )
        db.session.add(new_note)
        db.session.flush()

        note_uploads = NoteUpload.query.filter_by(note_id=original.id).all()
        upload_folder = current_app.config.get("UPLOAD_FOLDER_LOCAL_FILES") or UPLOAD_FOLDER_LOCAL_FILES

        for nu in note_uploads:
            orig_upload = Upload.query.get(nu.upload_id)
            if not orig_upload or orig_upload.deleted:
                continue

            file_size = orig_upload.size_bytes or 0

            # --- Obtain file bytes from source backend ---
            file_bytes = None
            try:
                if orig_upload.storage_backend == "dropbox":
                    try:
                        _, res = dbx.files_download(orig_upload.stored_filename)
                        file_bytes = res.content
                    except Exception:
                        current_app.logger.exception("Failed to download original from Dropbox %s", orig_upload.stored_filename)
                        raise

                elif orig_upload.storage_backend == "mega":
                    # Prefer using the stored mega_file_obj if available
                    mega_obj = getattr(orig_upload, "mega_file_obj", None)
                    stored_link = orig_upload.stored_filename if orig_upload.stored_filename and str(orig_upload.stored_filename).startswith("http") else None

                    # Attempt to download via mega client first
                    if mega_obj:
                        tmp_fd, tmp_path = tempfile.mkstemp()
                        os.close(tmp_fd)
                        try:
                            # mega_account.download writes file to dest
                            mega_account.download(mega_obj, dest=tmp_path)
                            with open(tmp_path, "rb") as f:
                                file_bytes = f.read()
                        finally:
                            try:
                                if os.path.exists(tmp_path):
                                    os.remove(tmp_path)
                            except Exception:
                                current_app.logger.exception("Failed to remove temporary MEGA download file %s", tmp_path)

                    # If we don't have a mega_file_obj, try HTTP GET on the stored public link (best-effort)
                    elif stored_link:
                        try:
                            r = requests.get(stored_link, timeout=60)
                            r.raise_for_status()
                            file_bytes = r.content
                        except Exception:
                            current_app.logger.exception("Failed to fetch MEGA public link %s", stored_link)
                            raise
                    else:
                        current_app.logger.error("MEGA origin upload missing both file object and public link: %s", orig_upload.id)
                        raise RuntimeError("Missing MEGA source metadata")

                else:
                    # local or unknown stored backend -> read from local filesystem
                    src_path = os.path.join(upload_folder, orig_upload.stored_filename or "")
                    if not os.path.isfile(src_path):
                        current_app.logger.warning("Original upload file missing: %s; skipping copy", src_path)
                        continue
                    with open(src_path, "rb") as f:
                        file_bytes = f.read()

                if file_bytes is None:
                    current_app.logger.warning("No bytes obtained for original upload %s; skipping", orig_upload.id)
                    continue

                # Wrap as FileStorage for reuse of verify_and_record_upload
                fs = FileStorage(
                    stream=BytesIO(file_bytes),
                    filename=orig_upload.original_filename or orig_upload.stored_filename or "attachment",
                    content_type=orig_upload.mimetype or ''
                )

                success, result = verify_and_record_upload(fs, user, max_size_bytes=MAX_UPLOAD_SIZE_BYTES)

            except Exception:
                current_app.logger.exception("Failed to copy attachment %s", orig_upload.id)
                cleanup_created_uploads()
                db.session.rollback()
                abort(500, description="Internal error while copying attachments.")

            if not success:
                current_app.logger.warning("Failed to copy attachment for note %s: %s", original.id, result)
                cleanup_created_uploads()
                db.session.rollback()
                abort(400, description=f"Failed to copy attachment: {result}")

            new_upload = result
            created_uploads.append(new_upload)
            note_upload_link = NoteUpload(note_id=new_note.id, upload_id=new_upload.id)
            db.session.add(note_upload_link)

        # Increment access count
        canonical = Share.query.filter_by(token=token).order_by(Share.created_at.asc()).first()
        if canonical:
            canonical.access_count = (canonical.access_count or 0) + 1
            db.session.add(canonical)

        db.session.commit()
        return jsonify(new_note.to_dict()), 201

    except Exception:
        current_app.logger.exception("Failed to save shared note (final exception)")
        try:
            cleanup_created_uploads()
        except Exception:
            current_app.logger.exception("Cleanup also failed")
        db.session.rollback()
        abort(500, description="Failed to save shared note.")

@app.route('/s/<token>/attachments/<int:upload_id>', methods=['GET'])
def shared_attachment_download(token, upload_id):
    # check token exists and has some allowed nodes
    folder_ids, note_ids, _, _ = get_shared_node_sets_for_token(token)
    if not folder_ids and not note_ids:
        abort(404)

    # find upload
    up = Upload.query.get(upload_id)
    if not up or up.deleted:
        abort(404)

    # find the note(s) that reference this upload
    linked_nu = NoteUpload.query.filter_by(upload_id=upload_id).first()
    if not linked_nu:
        abort(404)

    note = Note.query.get(linked_nu.note_id)
    if not note:
        abort(404)

    # allow access if either:
    allowed = (note.id in note_ids) or (note.folder_id in folder_ids)
    if not allowed:
        abort(404)

    # ---------- DROPBOX ----------
    if up.storage_backend == "dropbox":
        try:
            temp_link = dbx.files_get_temporary_link(up.stored_filename).link
            return redirect(temp_link)
        except Exception:
            current_app.logger.exception("Failed to generate Dropbox shared link for upload %s", upload_id)
            return jsonify({"error": "Failed to generate Dropbox link"}), 500

    # ---------- MEGA ----------
    if up.storage_backend == "mega":
        mega_obj = getattr(up, "mega_file_obj", None)
        stored_link = up.stored_filename if up.stored_filename and str(up.stored_filename).startswith("http") else None

        # Prefer redirecting to a public link (no proxying)
        if stored_link:
            return redirect(stored_link)

        try:
            if mega_obj:
                # try to generate a public link and redirect
                try:
                    link = mega_account.get_upload_link(mega_obj)
                    return redirect(link)
                except Exception:
                    # log and fall through to proxying
                    current_app.logger.exception("Failed to generate MEGA public link for upload %s", upload_id)
            else:
                # no mega object and no link — cannot redirect
                current_app.logger.error("MEGA metadata missing for upload %s", upload_id)
        except Exception:
            current_app.logger.exception("Unexpected MEGA error for upload %s", upload_id)

        # Fallback: proxy MEGA file through server (reads into memory then sends)
        tmp_fd = None
        tmp_path = None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp()
            os.close(tmp_fd)  # we only need the path; mega client will write to it
            mega_account.download(mega_obj, dest=tmp_path)

            # Read file bytes then remove temp file (reduces window file exists on disk)
            with open(tmp_path, "rb") as f:
                file_bytes = f.read()
            try:
                os.remove(tmp_path)
            except Exception:
                current_app.logger.exception("Failed to remove temporary MEGA download file %s", tmp_path)

            return send_file(
                BytesIO(file_bytes),
                as_attachment=True,
                download_name=up.original_filename,
                mimetype=up.mimetype or None
            )
        except Exception:
            # ensure cleanup
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    current_app.logger.exception("Failed to cleanup temp file %s after MEGA error", tmp_path)
            current_app.logger.exception("Failed to proxy MEGA file %s", upload_id)
            return jsonify({"error": "Failed to generate or proxy MEGA file"}), 500

    # ---------- LOCAL fallback ----------
    # local file fallback
    file_path = os.path.join(app.config.get('UPLOAD_FOLDER_LOCAL_FILES', UPLOAD_FOLDER_LOCAL_FILES),
                             up.stored_filename or "")
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=up.original_filename,
            mimetype=up.mimetype or None
        )
    except TypeError:
        # older Flask versions
        return send_file(
            file_path,
            as_attachment=True,
            attachment_filename=up.original_filename,
            mimetype=up.mimetype or None
        )

@app.route('/notes/<int:note_id>/share', methods=['GET'])
@require_session_key
def get_share_for_note(note_id):
    # Ensure the note exists & belongs to the user
    note = Note.query.get(note_id)
    if not note or note.user_id != g.user_id:
        return jsonify({"error": "Note not found or access denied"}), 404

    # Find active (non-expired) shares for this note owned by this user.
    now = datetime.utcnow()
    # Prefer non-expired shares; order by created_at desc so newest first
    share = (Share.query
             .filter(Share.note_id == note_id, Share.user_id == g.user_id)
             .filter((Share.expires_at == None) | (Share.expires_at > now))
             .order_by(Share.created_at.desc())
             .first())

    if not share:
        return jsonify({"error": "No active share found"}), 404

    # Build external URL to public share view
    share_url = url_for('public_share', token=share.token, _external=True)

    return jsonify({
        "token": share.token,
        "url": share_url,
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
        "access_count": share.access_count or 0
    }), 200

@app.route('/folders/<int:folder_id>/share', methods=['GET'])
@require_session_key
def get_folder_share(folder_id):
    folder = Folder.query.get(folder_id)
    if not folder or folder.user_id != g.user_id:
        return jsonify({"error": "Folder not found or access denied"}), 404

    now = datetime.utcnow()
    # Find active (non-expired) shares for this folder
    share = (Share.query
             .filter_by(folder_id=folder_id, user_id=g.user_id)
             .filter((Share.expires_at == None) | (Share.expires_at > now))
             .order_by(Share.created_at.desc())
             .first())

    if not share:
        return jsonify({"error": "No active share found"}), 404

    share_url = url_for('public_share', token=share.token, _external=True)

    return jsonify({
        "token": share.token,
        "url": share_url,
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
        "access_count": share.access_count or 0
    }), 200


# -------------------------
# Public API routes (no auth)
# -------------------------
@app.route("/api/articles", methods=["GET"])
def api_list_articles():
    # supports search q=, category=, page/limit (simple)
    q = request.args.get("q", "").strip()
    category = request.args.get("category")
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    qry = Article.query.filter_by(published=True)
    if category:
        qry = qry.filter(Article.category == category)
    if q:
        like = f"%{q}%"
        qry = qry.filter((Article.title.ilike(like)) | (Article.content.ilike(like)) | (Article.excerpt.ilike(like)))
    total = qry.count()
    items = qry.order_by(Article.updated_at.desc()).offset((page-1)*limit).limit(limit).all()
    return jsonify({
        "total": total,
        "page": page,
        "limit": limit,
        "articles": [a.to_dict(full=False) for a in items]
    })

@app.route("/api/article/<string:slug_or_id>", methods=["GET"])
def api_get_article(slug_or_id):
    a = None
    if slug_or_id.isdigit():
        a = Article.query.get(int(slug_or_id))
    else:
        a = Article.query.filter_by(slug=slug_or_id).first()
    if not a:
        return jsonify({"error": "not_found"}), 404
    # increment view count (non-blocking-ish)
    try:
        a.view_count = Article.view_count + 1 if hasattr(Article, 'view_count') else a.view_count + 1
        a.view_count += 0  # no-op to silence editors
        a.view_count = a.view_count + 1
        db.session.commit()
    except:
        db.session.rollback()
    return jsonify(a.to_dict(full=True))

# -------------------------
# Admin API routes (protected)
# -------------------------
@app.route("/api/admin/articles", methods=["GET"])
@require_session_key
@require_admin
def api_admin_list_articles():
    # return all (for admin)
    items = Article.query.order_by(Article.updated_at.desc()).all()
    return jsonify([a.to_dict(full=False) for a in items])

@app.route("/api/admin/article", methods=["POST"])
@require_session_key
@require_admin
def api_admin_create_article():
    data = request.get_json() or {}
    title = data.get("title")
    if not title:
        return jsonify({"error": "title_required"}), 400
    content = data.get("content", "")
    category = data.get("category")
    excerpt = data.get("excerpt")
    tags = data.get("tags", [])
    published = bool(data.get("published", True))
    author = session.get("user", "admin")
    slug_candidate = slugify(data.get("slug") or title)
    # ensure unique slug
    base = slug_candidate
    i = 1
    while Article.query.filter_by(slug=slug_candidate).first():
        slug_candidate = f"{base}-{i}"
        i += 1
    a = Article(
        title=title,
        slug=slug_candidate,
        content=content,
        category=category,
        excerpt=excerpt,
        tags_json=json.dumps(tags),
        published=published,
        author=author,
        last_edited_by=author
    )
    db.session.add(a)
    db.session.commit()
    return jsonify(a.to_dict(full=True)), 201

@app.route("/api/admin/article/<int:aid>", methods=["PUT"])
@require_session_key
@require_admin
def api_admin_update_article(aid):
    a = Article.query.get(aid)
    if not a:
        return jsonify({"error": "not_found"}), 404
    data = request.get_json() or {}
    a.title = data.get("title", a.title)
    maybe_slug = data.get("slug")
    if maybe_slug:
        s = slugify(maybe_slug)
        if s != a.slug and Article.query.filter_by(slug=s).first():
            return jsonify({"error": "slug_conflict"}), 400
        a.slug = s
    a.content = data.get("content", a.content)
    a.category = data.get("category", a.category)
    a.excerpt = data.get("excerpt", a.excerpt)
    a.tags_json = json.dumps(data.get("tags", a.tags()))
    a.published = bool(data.get("published", a.published))
    a.last_edited_by = session.get("user", "admin")
    db.session.commit()
    return jsonify(a.to_dict(full=True))

@app.route("/api/admin/article/<int:aid>", methods=["DELETE"])
@require_session_key
@require_admin
def api_admin_delete_article(aid):
    a = Article.query.get(aid)
    if not a:
        return jsonify({"error": "not_found"}), 404
    db.session.delete(a)
    db.session.commit()
    return jsonify({"ok": True})

# Flow routes:

@app.route('/flow/tag-suggestions', methods=['GET'])
@require_session_key
def get_flow_tag_suggestions():
    user_id = g.user_id
    
    # Fetch all projects and their branches
    projects = FlowProject.query.filter_by(user_id=user_id).all()
    suggestions = []
    
    for project in projects:
        project_data = {
            'id': project.id,
            'title': project.title,
            'branches': []
        }
        
        # Get all branches for this project
        branches = FlowBranch.query.filter_by(project_id=project.id).all()
        for branch in branches:
            project_data['branches'].append({
                'id': branch.id,
                'name': branch.name,
                'is_main': branch.name == 'main'
            })
        
        suggestions.append(project_data)
    
    return jsonify(suggestions)

@app.route('/invites/status', methods=['GET'])
@require_session_key
def invites_status():
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # ---- STORAGE ----
    raw_quota = get_user_quota_bytes(user)
    unlimited = raw_quota == float('inf')

    raw_used = getattr(user, 'storage_used_bytes', None)
    persist_null_to_zero = True

    if raw_used is None:
        used_bytes = 0
        if persist_null_to_zero:
            try:
                user.storage_used_bytes = 0
                db.session.add(user)
                db.session.commit()
            except Exception:
                db.session.rollback()
    else:
        try:
            used_bytes = int(raw_used)
        except (ValueError, TypeError):
            # sanitize: keep digits only
            s = re.sub(r'\D', '', str(raw_used or ''))
            used_bytes = int(s) if s else 0

    if unlimited:
        total_mb = None
        used_mb = None
        storage_message = "Unlimited storage"
    else:
        total_bytes = int(raw_quota)
        total_mb = round(total_bytes / 1024 / 1024, 2)
        used_mb = round(used_bytes / 1024 / 1024, 2)
        storage_message = None

    # ---- INVITES SENT TODAY ----
    start, now = _today_utc_range()
    sent_today = InviteReferral.query.filter(
        InviteReferral.inviter_id == user.id,
        InviteReferral.created_at >= start
    ).count()
    per_day_limit = 3
    remaining_today = max(per_day_limit - sent_today, 0)

    # ---- PENDING INVITES ----
    pending = InviteReferral.query.filter_by(inviter_id=user.id, claimed=False)\
        .order_by(InviteReferral.created_at.desc()).all()
    pending_list = [{
        "id": inv.id,
        "email": inv.invited_email,
        "created_at": inv.created_at.isoformat(),
        "token": inv.token
    } for inv in pending]

    return jsonify({
        "used_mb": used_mb,
        "total_mb": total_mb,
        "storage_message": storage_message,
        "sent_today": sent_today,
        "remaining_today": remaining_today,
        "per_day_limit": per_day_limit,
        "pending_invites": pending_list
    })

@app.route('/invites/send', methods=['POST'])
@require_session_key
def send_invite():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    if not email or not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        return jsonify({"error": "Invalid email"}), 400

    inviter = User.query.get(g.user_id)
    if not inviter:
        return jsonify({"error": "No inviter user"}), 404

    # Localhost testing bypass - allow sending freely on localhost
    if not _is_local_request():
        # Can't invite yourself
        if inviter.email and inviter.email.lower() == email:
            return jsonify({"error": "You can't invite your own email"}), 400

        # Prevent inviting existing registered user
        if User.query.filter(func.lower(User.email) == email).first():
            return jsonify({"error": "This email is already registered"}), 400

        # Rate-limit: 3 invites/day
        start, now = _today_utc_range()
        sent_today = InviteReferral.query.filter(InviteReferral.inviter_id == inviter.id, InviteReferral.created_at >= start).count()
        if sent_today >= 3:
            return jsonify({"error": "Daily invite limit reached (3/day)"}), 429

    # create invite
    token = str(uuid.uuid4())
    new_invite = InviteReferral(
        inviter_id=inviter.id,
        invited_email=email,
        token=token
    )
    db.session.add(new_invite)
    db.session.commit()

    # build accept url
    site_url = f"{request.scheme}://{request.host}"
    accept_url = f"{site_url}/invite/accept?token={urllib.parse.quote(token)}"

    # send email using your existing send_email helper
    try:
        send_email(
            to_address=email,
            subject="Future Notes — You've been invited!",
            content_html=f"""
                <h2>You've been invited to Future Notes!</h2>
                <p>{inviter.username} invited you. Click the button to accept and sign up — You both get +5MB of storage when you complete signup.</p>
                <p><small>If you wish to decline this invitation, simply ignore this email.</small></p>
            """,
            buttons=[{
                "text": "Accept invite & sign up",
                "href": accept_url,
                "color": "#313ca3"
            }],
            logo_url=app.config.get('LOGO_URL'),
            unsubscribe_url="#"
        )
    except Exception as e:
        app.logger.exception("Error sending invite email")
        # don't leak internal errors, but let caller know
        return jsonify({"error": "Failed to send invite email"}), 500

    return jsonify({"message": "Invite sent", "invite_id": new_invite.id}), 200

@app.route('/invites/cancel/<string:id>', methods=['POST'])
@require_session_key
def invite_cancel(id):
    invite_id_to_cancel = id

    invite = InviteReferral.query.filter_by(id=invite_id_to_cancel, inviter_id=g.user_id).first()
    if not invite:
        return jsonify({"error": "Invite not found"}), 404

    db.session.delete(invite)
    db.session.commit()
    return jsonify({"message": "Invite canceled"}), 200

@app.route('/invite/accept')
def invite_accept():
    token = request.args.get('token')
    if not token:
        return "Missing invite token", 400

    invite = InviteReferral.query.filter_by(token=token).first()
    if not invite:
        return "Invalid or expired invite link", 400

    # Check if a ReferralSession already exists for this invite and email
    existing_ref = ReferralSession.query.filter_by(
        invite_id=invite.id,
        invited_email=invite.invited_email
    ).first()

    if existing_ref:
        ref = existing_ref
    else:
        # create referral session record
        ref = ReferralSession(
            invite_id=invite.id,
            inviter_id=invite.inviter_id,
            invited_email=invite.invited_email
        )
        db.session.add(ref)
        db.session.commit()

    # Set cookie (non-httponly so front-end can inspect if needed; but we only need backend)
    resp = redirect("/signup_page")
    # cookie name "referral_session"
    # Set a longer expiration (e.g., 7 days) so user can sign up later
    resp.set_cookie("referral_session", ref.id, httponly=True, secure=False, samesite="Lax", max_age=60*60*24*7)
    return resp

@app.route('/cron/notifications', methods=["GET", "POST"])
def cron_notifications():
    now = datetime.now(timezone.utc)

    # Query upcoming appointments: not deleted, not already ended
    # Adjust filters to your app conventions (deleted_at usage, timezone handling, etc.)
    appts = Appointment.query.filter(
        Appointment.deleted_at.is_(None),
        Appointment.end_datetime >= now
    ).all()

    sent_count = 0
    skipped_count = 0
    errors = []

    for appt in appts:
        try:
            # Ensure appointment.start_datetime is timezone-aware in UTC
            start = appt.start_datetime
            if start.tzinfo is None:
                # assume UTC if naive (adjust if your DB stores local times)
                start = start.replace(tzinfo=timezone.utc)
            # minutes until start (float)
            minutes_until = (start - now).total_seconds() / 60.0

            # only future events
            if minutes_until < 0:
                skipped_count += 1
                continue

            # Decide whether we should send 30 or 15 minute notice
            notice_minutes = None
            # Prefer 15 if within 15 minutes, otherwise 30 if within 30.
            if minutes_until <= 15:
                notice_minutes = 15
            elif minutes_until <= 30:
                notice_minutes = 30

            if notice_minutes is None:
                skipped_count += 1
                continue

            # check NotificationLog to avoid duplicates
            already = NotificationLog.query.filter_by(
                appointment_id=appt.id,
                minutes_before=notice_minutes
            ).first()

            if already:
                skipped_count += 1
                continue

            # send notification (assumed function already in your codebase)
            minutes_text = f"{int(round(minutes_until))} minutes"
            title = appt.title
            text = f"You have appointment \"{appt.title}\" coming up in {minutes_text}"

            # send_notification should be non-blocking/robust; handle exceptions
            send_notification(
                user_id=appt.user_id,
                title=title,
                text=text,
                module="/scheduler-page"
            )

            # record it
            log = NotificationLog(
                appointment_id=appt.id,
                minutes_before=notice_minutes
            )
            db.session.add(log)
            db.session.commit()
            sent_count += 1

        except Exception as exc:
            db.session.rollback()
            errors.append({"appointment_id": getattr(appt, "id", None), "error": str(exc)})

    return jsonify({
        "now": now.isoformat(),
        "processed": len(appts),
        "sent": sent_count,
        "skipped": skipped_count,
        "errors": errors
    }), (500 if errors else 200)

@app.route('/cron/cleanup_uploads', methods=['GET'])
def cron_cleanup_uploads():
    """
    Cron endpoint: Deletes files in UPLOAD_FOLDER_LOCAL_FILES that are:
      - not present in the uploads table for local storage and not marked active, OR
      - present in the uploads table but marked deleted=True (for local storage).
    Then deletes the corresponding DB records with deleted==True from uploads table.

    NOTE: Ensure app.config['UPLOAD_FOLDER_LOCAL_FILES'] is set to the absolute path of your
    local upload folder before calling this route (from cron).
    """
    upload_folder = current_app.config.get('UPLOAD_FOLDER_LOCAL_FILES')
    if not upload_folder:
        return jsonify({"error": "UPLOAD_FOLDER_LOCAL_FILES not configured"}), 500

    upload_folder_path = Path(upload_folder).resolve()
    if not upload_folder_path.exists():
        return jsonify({"error": f"Upload folder does not exist: {upload_folder_path}"}), 500

    # Query DB: local storage entries
    local_uploads = db.session.query(Upload).filter(Upload.storage_backend == 'local').all()

    # Build sets of normalized stored filenames for active and deleted records.
    # Normalize using os.path.normpath and store relative forms.
    def norm(p: str) -> str:
        # treat None or empty as empty string
        if not p:
            return ''
        return os.path.normpath(p).lstrip(os.sep)

    active_files = set()
    deleted_files_db = set()
    for u in local_uploads:
        stored = norm(u.stored_filename)
        if u.deleted:
            deleted_files_db.add(stored)
        else:
            active_files.add(stored)

    deleted_files = []
    failed_deletions = []
    removed_empty_dirs = 0

    # Walk the upload folder (top-down)
    for root, dirs, files in os.walk(upload_folder_path, topdown=False):
        root_path = Path(root)
        for fname in files:
            file_path = root_path / fname
            try:
                # compute relative path from upload folder, normalized for comparison
                rel = os.path.relpath(file_path.resolve(), upload_folder_path)
            except Exception:
                # if resolving fails, skip file (safety)
                continue

            rel_norm = norm(rel)
            base_name = fname  # basename fallback match

            # Decide whether to delete:
            # delete if file is either:
            #  - marked deleted in DB (exists in deleted_files_db), OR
            #  - not present in active_files (not in DB as local active)
            in_deleted_db = rel_norm in deleted_files_db or base_name in deleted_files_db
            in_active_db = rel_norm in active_files or base_name in active_files

            if in_deleted_db or (not in_active_db):
                # Safety: verify that file_path is inside upload_folder_path
                try:
                    abs_fp = file_path.resolve()
                except Exception:
                    failed_deletions.append(str(file_path))
                    continue
                if not str(abs_fp).startswith(str(upload_folder_path)):
                    # skip deletion if outside folder (should not happen)
                    failed_deletions.append(str(file_path))
                    continue

                try:
                    os.remove(abs_fp)
                    deleted_files.append(str(abs_fp))
                except Exception as e:
                    failed_deletions.append(f"{file_path} (err: {e})")

    # Delete DB records where deleted == True
    try:
        deleted_records_q = db.session.query(Upload).filter(Upload.deleted == True)
        # count before delete
        deleted_records_count = deleted_records_q.count()
        # bulk delete
        deleted_records_q.delete(synchronize_session=False)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "error": "Failed to delete DB records marked deleted",
            "exception": str(e),
            "deleted_files_attempted": len(deleted_files),
            "deleted_files_failed": len(failed_deletions),
        }), 500

    summary = {
        "upload_folder": str(upload_folder_path),
        "deleted_files_count": len(deleted_files),
        "deleted_files_sample": deleted_files[:50],  # limit listing to first 50
        "failed_file_deletions_count": len(failed_deletions),
        "failed_file_deletions_sample": failed_deletions[:20],
        "removed_empty_directories": removed_empty_dirs,
        "deleted_db_records_count": deleted_records_count
    }

    return jsonify(summary), 200

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
    
    if source_id == target_id or target_id == source_id:
        return jsonify({'error': 'Source cannot match destination'})
    
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
    current_progress = project.progress  # BEFORE the new step
    new_step = FlowCommit(
        branch_id=branch_id,
        title=data['title'],
        description=data['description'],
        impact=data['impact']
    )
    db.session.add(new_step)
    db.session.flush()  # Push the step to the DB so project.progress updates

    is_completion = False
    updated_progress = project.progress  # NOW includes new_step

    if (
        current_progress < project.total_impact and
        updated_progress >= project.total_impact and
        project.status != 'completed'
    ):
        project.status = 'completed'
        is_completion = True

    db.session.commit()

    return jsonify({
        'id': new_step.id,
        'message': 'Step created',
        'is_completion': is_completion
    }), 201

@app.route('/flow/commits/<int:commit_id>/revert', methods=['POST'])
@require_session_key
def revert_commit_flow(commit_id):
    commit = FlowCommit.query.get_or_404(commit_id)
    branch = FlowBranch.query.get(commit.branch_id)
    project = FlowProject.query.get(branch.project_id)
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if commit.is_completion:
        project.status = 'active'
    
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

@app.route('/flow/projects/<int:project_id>/reactivate', methods=['POST'])
@require_session_key
def reactivate_project(project_id):
    # 1. Fetch & validate
    project = FlowProject.query.get(project_id)
    if not project:
        return jsonify({'error': 'Project not found'}), 404

    if project.status != 'completed':
        return jsonify({'error': 'Project is not completed'}), 400

    # 2. Locate the “completion” step
    #    We’ll assume it's the last step on the “main” branch.
    main_branch = (
        FlowBranch.query
        .filter_by(project_id=project.id, name='main')
        .first()
    )
    if main_branch:
        completion_step = (
            FlowCommit.query
            .filter_by(branch_id=main_branch.id)
            .order_by(FlowCommit.created_at.desc())
            .first()
        )
        # Optionally, you could further check a flag or title on that step:
        if completion_step and completion_step.is_completion:
            db.session.delete(completion_step)

    # 3. Flip the status back
    project.status = 'active'

    # 4. (Re-)calculate any aggregates if needed.
    #    e.g. project.progress = sum(step.impact for branch in project.branches for step in branch.steps)
    #    but if you recalc on-the-fly elsewhere you can skip it.

    # 5. Commit & respond
    db.session.commit()
    return jsonify({'message': 'Project re-activated'}), 200

@app.route('/flow/branches/<int:branch_id>/todos', methods=['GET', 'POST'])
@require_session_key
def branch_todos(branch_id):
    branch = FlowBranch.query.get_or_404(branch_id)
    project = FlowProject.query.get(branch.project_id)
    
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'GET':
        todos = Todo.query.filter_by(flow_branch_id=branch_id).all()
        return jsonify([{
            'id': t.id,
            'title': t.title,
            'description': t.text,  # Still using t.text here for backward compatibility
            'due_date': t.due_date.isoformat() if t.due_date else None,
            'completed': t.completed,
            'estimated_impact': t.estimated_impact
        } for t in todos])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        # Validate required fields
        if not data.get('title'):
            return jsonify({'error': 'Title is required'}), 400
        
        try:
            # Handle due date
            due_date = None
            if data.get('due_date'):
                try:
                    due_date = datetime.fromisoformat(data['due_date'])
                except ValueError as e:
                    return jsonify({'error': f'Invalid date format: {str(e)}'}), 400
            
            # Create new todo - using description instead of text
            new_todo = Todo(
                user_id=g.user_id,
                title=data['title'],
                text=data.get('description', ''),  # This matches your frontend
                due_date=due_date,
                flow_branch_id=branch_id,
                estimated_impact=data.get('estimated_impact', 0)
            )
            
            db.session.add(new_todo)
            db.session.commit()
            
            return jsonify({
                'id': new_todo.id,
                'message': 'Todo created successfully',
                'todo': {
                    'id': new_todo.id,
                    'title': new_todo.title,
                    'description': new_todo.text,  # Consistent with frontend
                    'due_date': new_todo.due_date.isoformat() if new_todo.due_date else None,
                    'completed': new_todo.completed,
                    'estimated_impact': new_todo.estimated_impact
                }
            }), 201
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Error creating todo: {str(e)}'}), 500

@app.route('/flow/branches/<int:branch_id>/todos/bulk', methods=['POST'])
@require_session_key
def create_bulk_branch_todos(branch_id):
    branch = FlowBranch.query.get_or_404(branch_id)
    project = FlowProject.query.get(branch.project_id)
    
    if project.user_id != g.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    created_ids = []
    
    # Validate at least one todo exists
    if not data.get('todos') or not isinstance(data['todos'], list):
        return jsonify({'error': 'No todos provided or invalid format'}), 400
    
    try:
        for todo_data in data['todos']:
            # Validate required fields
            if not todo_data.get('title'):
                continue  # Skip invalid entries
                
            # Parse and validate impact
            impact = todo_data.get('estimated_impact', 0)
            if impact < 0:
                continue  # Skip invalid entries
                
            # Handle due date
            due_date = None
            if todo_data.get('due_date'):
                try:
                    due_date = datetime.fromisoformat(todo_data['due_date'])
                except ValueError:
                    continue  # Skip entries with invalid date format
                
            # Create new todo - using description field consistently
            new_todo = Todo(
                user_id=g.user_id,
                title=todo_data['title'],
                text=todo_data.get('description', ''),  # Using description from frontend
                due_date=due_date,
                flow_branch_id=branch_id,
                estimated_impact=impact
            )
            db.session.add(new_todo)
            created_ids.append(new_todo.id)
        
        db.session.commit()
        
        return jsonify({
            'message': f'Created {len(created_ids)} todos',
            'created_ids': created_ids,
            'created_count': len(created_ids)
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creating todos: {str(e)}'}), 500

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
    """
    Generate a persistent device ID using browser fingerprint, IP, and other headers.
    More data = more uniqueness, while still respecting privacy.
    """
    
    # Real client IP (behind proxies)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip.split(',')[0].strip()
    
    # Core browser fingerprinting headers
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    encoding = request.headers.get('Accept-Encoding', '')
    connection = request.headers.get('Connection', '')
    
    # Optional headers for added uniqueness
    dnt = request.headers.get('DNT', '')  # Do Not Track
    referer = request.headers.get('Referer', '')
    sec_ch_ua = request.headers.get('Sec-CH-UA', '')
    sec_ch_ua_platform = request.headers.get('Sec-CH-UA-Platform', '')
    
    # Concatenate all data into a single string
    fingerprint_data = "|".join([
        ip,
        user_agent,
        accept_language,
        encoding,
        connection,
        dnt,
        referer,
        sec_ch_ua,
        sec_ch_ua_platform
    ])
    
    # Hash to produce a consistent, fixed-length device ID
    device_id = hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    return device_id

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

    # First clean with bleach
    message = bleach.clean(message)
    
    try:
        # Send confirmation email with promo content
        html_content = """
        <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; color: white;">
            
            <p style="font-size: 16px; line-height: 1.6;">
                We've received your message and will get back to you shortly. In the meantime, 
                we'd like to share some of the amazing features that make Future Notes the perfect 
                tool for organizing your thoughts and tasks.
            </p>
            
            <div style="background-color: #f9f9f9; padding: 20px; border-radius: 8px; margin: 25px 0;">
                <h3 style="color: #4A90E2; margin-top: 0;">✨ Key Features of Future Notes ✨</h3>
                
                <div style="display: flex; align-items: center; margin: 20px 0;">
                    <img src="https://images.unsplash.com/photo-1515378791036-0648a3ef77b2?ixlib=rb-4.0.3&auto=format&fit=crop&w=100&h=100&q=80" 
                        alt="Organized Notes" style="width: 80px; height: 80px; border-radius: 8px; margin-right: 15px;">
                    <div>
                        <h4 style="margin: 0; color: #333;">Smart Organization</h4>
                        <p style="margin: 5px 0 0; font-size: 14px;">Categorize, tag, and search your notes with our intuitive system.</p>
                    </div>
                </div>
                
                <div style="display: flex; align-items: center; margin: 20px 0;">
                    <img src="https://images.unsplash.com/photo-1589652717521-10c0d092dea9?ixlib=rb-4.0.3&auto=format&fit=crop&w=100&h=100&q=80" 
                        alt="Sync Across Devices" style="width: 80px; height: 80px; border-radius: 8px; margin-right: 15px;">
                    <div>
                        <h4 style="margin: 0; color: #333;">Cross-Device Sync</h4>
                        <p style="margin: 5px 0 0; font-size: 14px;">Access your notes from anywhere - phone, tablet, or computer.</p>
                    </div>
                </div>
                
                <div style="display: flex; align-items: center; margin: 20px 0;">
                    <img src="https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?ixlib=rb-4.0.3&auto=format&fit=crop&w=100&h=100&q=80" 
                        alt="Rich Text Editing" style="width: 80px; height: 80px; border-radius: 8px; margin-right: 15px;">
                    <div>
                        <h4 style="margin: 0; color: #333;">Rich Text Editing</h4>
                        <p style="margin: 5px 0 0; font-size: 14px;">Format your notes with bold, italics, lists, and more.</p>
                    </div>
                </div>
                
                <div style="display: flex; align-items: center; margin: 20px 0;">
                    <img src="https://images.unsplash.com/photo-1552664730-d307ca884978?ixlib=rb-4.0.3&auto=format&fit=crop&w=100&h=100&q=80" 
                        alt="Reminders" style="width: 80px; height: 80px; border-radius: 8px; margin-right: 15px;">
                    <div>
                        <h4 style="margin: 0; color: #333;">Smart Reminders</h4>
                        <p style="margin: 5px 0 0; font-size: 14px;">Set reminders for important tasks and never miss a deadline.</p>
                    </div>
                </div>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="https://bosbes.eu.pythonanywhere.com/signup_page" 
                style="background-color: #4A90E2; color: white; padding: 12px 24px; 
                        text-decoration: none; border-radius: 4px; font-weight: bold; 
                        display: inline-block;">Explore Future Notes Now</a>
            </div>
            
            <p style="font-size: 14px; text-align: center; color: #666;">
                We're constantly working to improve Future Notes. Stay tuned for exciting updates!
            </p>
        </div>
        """
        
        send_email(
            to_address=email,
            subject="Thank You for Contacting Future Notes!",
            content_html=html_content,
            content_text="Thank you for contacting us! We've received your message and will get back to you shortly. In the meantime, check out Future Notes at https://bosbes.eu.pythonanywhere.com",
            logo_url="https://bosbes.eu.pythonanywhere.com/static/android-chrome-192x192.png",
            unsubscribe_url="https://bosbes.eu.pythonanywhere.com"
        )
        
        # Also send notification to yourself
        admin_html = f"<p>New contact form submission from: {email}</p><p>Message: {message}</p>"
        send_email(
            to_address=app.config['ADMIN_EMAIL'],
            subject=f"New Contact Form Submission from {email}",
            content_html=admin_html,
            content_text=f"New contact form submission from: {email}\nMessage: {message}",
            logo_url="https://bosbes.eu.pythonanywhere.com/static/android-chrome-192x192.png",
            unsubscribe_url="https://bosbes.eu.pythonanywhere.com",
        )
        
        # Save to database
        message = Messages(email=email, message=message)
        db.session.add(message)
        db.session.commit()
        
        return jsonify({"success": "Message received successfully!"}), 201
    except Exception as e:
        return jsonify({"error": f"Message not received {e}"}), 400

@app.route('/username-check/<string:username>', methods=['GET'])
def check_username(username):
    # Block impersonation of reserved names (case-insensitive, normalized, similar)
    reserved_names = ["admin", "administrator", "moderator", "mod", "support", "staff", "root", "system"]
    norm_input = re.sub(r'[_\-]', '', username.lower())

    # Direct reserved name match
    for reserved in reserved_names:
        norm_reserved = re.sub(r'[_\-]', '', reserved.lower())
        # Case-insensitive and normalized match
        if username.lower() == reserved or norm_input == norm_reserved:
            return jsonify({"exists": False, "protected": True, "reason": "Reserved name"}), 200
        # Levenshtein similarity
        def levenshtein(a, b):
            if a == b:
                return 0
            if len(a) < len(b):
                return levenshtein(b, a)
            if len(b) == 0:
                return len(a)
            previous_row = range(len(b) + 1)
            for i, c1 in enumerate(a):
                current_row = [i + 1]
                for j, c2 in enumerate(b):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            return previous_row[-1]
        if levenshtein(norm_input, norm_reserved) <= 1:
            return jsonify({"exists": False, "protected": True, "reason": "Reserved name similarity"}), 200
        # Regex: block substrings or extra digits/letters
        pattern = re.compile(rf"^{re.escape(reserved)}[\d\w\-_.]*$", re.IGNORECASE)
        if pattern.match(username):
            return jsonify({"exists": False, "protected": True, "reason": "Reserved name regex similarity"}), 200

    # Check for exact match in database
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"exists": True, "protected": False}), 200

    # Check for similarity to protected usernames in DB
    protected_users = User.query.filter_by(has_username_protection=True).all()
    for protected_user in protected_users:
        protected_name = protected_user.username

        # Case-insensitive match
        if username.lower() == protected_name.lower():
            return jsonify({"exists": False, "protected": True, "reason": "Case-insensitive match"}), 200

        # Remove underscores/dashes and compare
        norm_protected = re.sub(r'[_\-]', '', protected_name.lower())
        if norm_input == norm_protected:
            return jsonify({"exists": False, "protected": True, "reason": "Normalized match"}), 200

        # Levenshtein distance <= 1 (very similar)
        if levenshtein(username.lower(), protected_name.lower()) <= 1:
            return jsonify({"exists": False, "protected": True, "reason": "Levenshtein similarity"}), 200

        # Regex: block usernames that are substrings or have extra digits/letters at the end
        pattern = re.compile(rf"^{re.escape(protected_name)}[\d\w\-_.]*$", re.IGNORECASE)
        if pattern.match(username):
            return jsonify({"exists": False, "protected": True, "reason": "Regex similarity"}), 200

    # If no match found
    return jsonify({"exists": False, "protected": False}), 200

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


def to_utc(dt_str):
    """Parse ISO datetime string (with or without tz) and return a timezone-aware UTC datetime.
    If client sends naive datetime, we assume it was UTC (matches existing code that used datetime.utcnow()).
    """
    if dt_str is None:
        return None
    # parse using dateutil (handles both date-only and datetimes)
    dt = dtparser.isoparse(dt_str)
    if dt.tzinfo is None:
        # assume naive from clients is UTC (consistent with existing storage using utcnow())
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)

def ensure_dt_utc(dt):
    """Given a datetime from the DB or elsewhere, return a tz-aware datetime in UTC.
    If dt is naive we assume it is already UTC (safe given usage of datetime.utcnow()).
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)

def iso_utc(dt):
    """Return an ISO 8601 string in UTC (with +00:00) or None.
    Accepts naive datetimes (assumes UTC) or aware datetimes.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()

def parse_iso_to_utc(iso_str):
    if not iso_str:
        return None
    from datetime import timezone  # local import, only visible in this function
    import dateutil.parser

    dt = dateutil.parser.isoparse(iso_str)
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(tzinfo=None)  # naive UTC for SQLite

def appointment_to_fc_event(appt, user_tz=None):
    """
    Convert Appointment model to a FullCalendar-compatible event object.

    - For all-day events we return `start`/`end` as date-only strings (YYYY-MM-DD).
    - For timed events we return ISO datetimes with timezone (+00:00).
    - We include both `id` (string e.g. "local-123") and `db_id` (int).
    - Keep `start_datetime` / `end_datetime` fields for compatibility.
    """
    # normalize datetimes (ensure aware UTC)
    s_utc = ensure_dt_utc(appt.start_datetime)
    e_utc = ensure_dt_utc(appt.end_datetime)

    if appt.is_all_day:
        # For all-day: use date-only strings. FullCalendar expects the end date to be exclusive.
        start_val = s_utc.date().isoformat() if s_utc else None
        end_val = e_utc.date().isoformat() if e_utc else None
        # Also provide the full ISO datetimes for other code that expects them
        start_iso_full = iso_utc(s_utc)
        end_iso_full = iso_utc(e_utc)
    else:
        # Timed events: ISO with timezone
        start_val = iso_utc(s_utc)
        end_val = iso_utc(e_utc)
        start_iso_full = start_val
        end_iso_full = end_val

    ev = {
        # FullCalendar-visible id (useful to tag events by source), and numeric db id for API calls
        "id": f"local-{appt.id}",
        "db_id": appt.id,
        "title": appt.title or "(no title)",
        # primary fields FullCalendar will read
        "start": start_val,
        "end": end_val,
        "allDay": bool(appt.is_all_day),
        "color": appt.color or None,
        "description": appt.description,
        "calendar_id": appt.calendar_id,
        "user_id": appt.user_id,
        "google_event_id": appt.google_event_id,
        "notes": [n.id for n in appt.notes],
        # keep the full ISO datetimes too (legacy clients / debugging)
        "start_datetime": start_iso_full,
        "end_datetime": end_iso_full,
    }

    # Recurrence: respond with rrule that FullCalendar rrule plugin understands (string).
    if appt.recurrence_rule:
        ev["rrule"] = appt.recurrence_rule
        if appt.recurrence_end_date:
            ev.setdefault("extendedProps", {})["recurrence_end_date"] = iso_utc(ensure_dt_utc(appt.recurrence_end_date))

    return ev

# ---- Calendar endpoints ----

@app.route("/api/calendars", methods=["GET"])
@require_session_key
def api_list_calendars():
    user = User.query.get(g.user_id)
    rows = Calendar.query.filter_by(user_id=user.id).all()
    return jsonify([c.to_dict() for c in rows]), 200

@app.route("/api/calendars", methods=["POST"])
@require_session_key
def api_create_calendar():
    user = User.query.get(g.user_id)
    payload = request.json or {}
    name = payload.get("name", "My calendar")
    is_default = bool(payload.get("is_default", False))
    if is_default:
        # unset previous defaults
        Calendar.query.filter_by(user_id=user.id, is_default=True).update({"is_default": False})
    cal = Calendar(name=name, user_id=user.id, is_default=is_default)
    db.session.add(cal)
    db.session.commit()
    return jsonify(cal.to_dict()), 201

@app.route("/api/calendars/<int:calendar_id>", methods=["PUT", "DELETE"])
@require_session_key
def api_update_delete_calendar(calendar_id):
    user = User.query.get(g.user_id)
    cal = Calendar.query.filter_by(id=calendar_id, user_id=user.id).first_or_404()
    if request.method == "DELETE":
        # optionally, handle orphaned appointments — soft-delete or reassign
        # Here we soft-delete appointments belonging to this calendar
        for ap in cal.appointments:
            ap.deleted_at = datetime.utcnow()
        db.session.delete(cal)
        db.session.commit()
        return jsonify({"ok": True}), 200
    payload = request.json or {}
    cal.name = payload.get("name", cal.name)
    if "is_default" in payload and payload["is_default"]:
        Calendar.query.filter_by(user_id=user.id, is_default=True).update({"is_default": False})
        cal.is_default = True
    db.session.commit()
    return jsonify(cal.to_dict()), 200

# ---- Appointment endpoints ----

@app.route("/api/appointments", methods=["GET"])
@require_session_key
def api_get_appointments():
    user = User.query.get(g.user_id)

    # Resolve calendar (allow query param calendar_id optional)
    cal_param = request.args.get("calendar_id")
    cal, err = resolve_local_calendar(user, cal_param if cal_param is not None else None)
    if err:
        return err  # (json_response, status_code)

    # base query: only appointments belonging to that calendar and user, not deleted
    q = Appointment.query.filter_by(user_id=user.id, deleted_at=None, calendar_id=cal.id)

    start = request.args.get("start")
    end = request.args.get("end")
    start_dt = to_utc(start) if start else None
    end_dt = to_utc(end) if end else None

    rows = q.all()
    results = []
    for ap in rows:
        ap_start = ensure_dt_utc(ap.start_datetime)
        ap_end = ensure_dt_utc(ap.end_datetime)

        if start_dt and end_dt and not ap.recurrence_rule:
            # skip if appointment ends before range start or starts after range end
            if ap_end is not None and ap_end < start_dt:
                continue
            if ap_start is not None and ap_start > end_dt:
                continue
        results.append(appointment_to_fc_event(ap))
    return jsonify(results), 200

@app.route("/api/appointments", methods=["POST"])
@require_session_key
def api_create_appointment():
    user = User.query.get(g.user_id)
    data = request.json or {}
    title = data.get("title", "")
    description = data.get("description")
    start = to_utc(data.get("start"))
    end = to_utc(data.get("end"))
    if not start or not end:
        return jsonify({"error":"start and end required"}), 400

    # Resolve calendar (allow missing -> default)
    calendar_id = data.get("calendar_id")
    cal, err = resolve_local_calendar(user, calendar_id if calendar_id is not None else None)
    if err:
        return err

    ap = Appointment(
        title=title,
        description=description,
        start_datetime=start,
        end_datetime=end,
        user_id=user.id,
        calendar_id=cal.id,
        recurrence_rule=data.get("recurrence_rule"),
        recurrence_end_date=to_utc(data.get("recurrence_end_date")) if data.get("recurrence_end_date") else None,
        is_all_day=bool(data.get("is_all_day", False)),
        color=data.get("color")
    )
    db.session.add(ap)
    # attach notes if provided
    note_ids = data.get("notes") or []
    if note_ids:
        notes = Note.query.filter(Note.id.in_(note_ids), Note.user_id==user.id).all()
        ap.notes = notes
    db.session.commit()
    return jsonify(appointment_to_fc_event(ap)), 201

@app.route("/api/appointments/<int:appt_id>", methods=["PUT"])
@require_session_key
def api_update_appointment(appt_id):
    user = User.query.get(g.user_id)
    ap = Appointment.query.filter_by(id=appt_id, user_id=user.id).first_or_404()
    data = request.json or {}
    if "title" in data: ap.title = data["title"]
    if "description" in data: ap.description = data["description"]
    if "start" in data: ap.start_datetime = parse_iso_to_utc(data["start"])
    if "end" in data: ap.end_datetime = parse_iso_to_utc(data["end"])
    if "recurrence_rule" in data: ap.recurrence_rule = data.get("recurrence_rule")
    if "recurrence_end_date" in data: ap.recurrence_end_date = to_utc(data["recurrence_end_date"]) if data.get("recurrence_end_date") else None
    if "is_all_day" in data: ap.is_all_day = bool(data["is_all_day"])
    if "color" in data: ap.color = data.get("color")
    if "calendar_id" in data:
        # validate target calendar belongs to user
        target_calendar_id = data.get("calendar_id")
        if target_calendar_id is None:
            return jsonify({"error": "invalid_calendar_id"}), 400
        cal = Calendar.query.filter_by(id=int(target_calendar_id), user_id=user.id).first()
        if cal:
            ap.calendar_id = cal.id
        else:
            return jsonify({"error": "calendar_not_found"}), 404
    if "notes" in data:
        note_ids = data.get("notes") or []
        ap.notes = Note.query.filter(Note.id.in_(note_ids), Note.user_id==user.id).all()
    db.session.commit()
    return jsonify(appointment_to_fc_event(ap)), 200

@app.route("/api/appointments/<int:appt_id>", methods=["DELETE"])
@require_session_key
def api_delete_appointment(appt_id):
    user = User.query.get(g.user_id)
    ap = Appointment.query.filter_by(id=appt_id, user_id=user.id).first_or_404()
    # soft delete
    ap.deleted_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True}), 200

# ---- Google OAuth / sync ----

def get_google_flow(state=None):
    # Construct flow, redirect URI must match your Google Console setting (/google/callback)
    client_config = {
        "web": {
            "client_id": app.config['GOOGLE_CLIENT_ID'],
            "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }
    flow = Flow.from_client_config(
        client_config,
        scopes=["https://www.googleapis.com/auth/calendar"],
        redirect_uri=url_for("google_callback", _external=True)
    )
    if state:
        flow.state = state
    return flow

@app.route("/api/google/connect", methods=["GET"])
@require_session_key
def api_google_connect():
    user = User.query.get(g.user_id)
    local_calendar_id = request.args.get("local_calendar_id")
    
    # resolve calendar
    cal, err = resolve_local_calendar(user, local_calendar_id if local_calendar_id is not None else None)
    if err:
        return err
    
    flow = get_google_flow(state=None)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )

    # Save state and associated calendar_id somewhere (DB or session)
    # For simplicity, associate in CalendarSync if needed after callback

    return jsonify({
        "auth_url": auth_url,
        "local_calendar_id": cal.id  # frontend can keep this to pass back on callback
    }), 200

def get_user_id(session_key):
    current_key = request.cookies.get('session_key')
    for sk in list(session_keys.keys()):
        meta = session_keys.get(sk)
        if meta and meta.get("session_key") == current_key:
            return meta.get("user_id")
    return None

@app.route("/google/callback")
def google_callback():
    # get session user
    user_id = get_user_id(request.cookies.get("session_key"))
    user = User.query.get(user_id)

    # fetch local_calendar_id from frontend query param or state (frontend should pass it)
    local_calendar_id = request.args.get("local_calendar_id")
    cal, err = resolve_local_calendar(user, local_calendar_id if local_calendar_id else None)
    if err:
        return err

    flow = get_google_flow()
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials  # google.oauth2.credentials.Credentials

    # Save or update Google credentials
    gcred = GoogleCalendarCredentials.query.filter_by(user_id=user.id).first()
    if not gcred:
        gcred = GoogleCalendarCredentials(user_id=user.id)
        db.session.add(gcred)
    gcred.access_token = creds.token
    gcred.refresh_token = creds.refresh_token or gcred.refresh_token
    gcred.token_expiry = creds.expiry
    gcred.calendar_id = None  # actual Google calendar selected later
    gcred.last_sync = None
    db.session.commit()

    # Optionally, create a CalendarSync mapping for the local calendar
    cs = CalendarSync.query.filter_by(user_id=user.id, local_calendar_id=cal.id).first()
    if not cs:
        cs = CalendarSync(user_id=user.id, local_calendar_id=cal.id, google_calendar_id=None, sync_enabled=True)
        db.session.add(cs)
        db.session.commit()

    return redirect(url_for("scheduler_page"))

@app.route("/api/google/calendars", methods=["GET"])
@require_session_key
def api_google_list_calendars():
    user = User.query.get(g.user_id)
    local_calendar_id = request.args.get("local_calendar_id")
    cal, err = resolve_local_calendar(user, local_calendar_id if local_calendar_id else None)
    if err:
        return err

    gcred = GoogleCalendarCredentials.query.filter_by(user_id=user.id).first()
    if not gcred:
        return jsonify({"error": "no_google_credentials"}), 404

    creds = Credentials(
        token=gcred.access_token,
        refresh_token=gcred.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        expiry=gcred.token_expiry
    )

    service = build("calendar", "v3", credentials=creds, cache_discovery=False)
    try:
        resp = service.calendarList().list().execute()
        items = resp.get("items", [])

        # return id, summary, and optionally map it to local calendar
        calendars = []
        for i in items:
            cs = CalendarSync.query.filter_by(user_id=user.id, local_calendar_id=cal.id, google_calendar_id=i["id"]).first()
            calendars.append({
                "id": i["id"],
                "summary": i.get("summary"),
                "primary": i.get("primary", False),
                "linked": bool(cs)  # true if mapped to this local calendar
            })
        return jsonify({"calendars": calendars}), 200
    except HttpError as e:
        return jsonify({"error": "google_api_error", "details": str(e)}), 500

def ensure_aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)

from datetime import datetime, time, timezone
from zoneinfo import ZoneInfo
import dateutil.parser as dtparser

def parse_google_event_datetime(event_time_dict):
    app.logger.warning("---- PARSE GOOGLE DATETIME ----")
    app.logger.warning("RAW event_time_dict: %s", event_time_dict)

    if "dateTime" in event_time_dict:
        dt_str = event_time_dict["dateTime"]
        tz_str = event_time_dict.get("timeZone")

        app.logger.warning("dateTime string: %s", dt_str)
        app.logger.warning("timeZone field: %s", tz_str)

        dt = dtparser.isoparse(dt_str)

        app.logger.warning("After isoparse: %s (tzinfo=%s)", dt, dt.tzinfo)

        if dt.tzinfo is None:
            if tz_str:
                app.logger.warning("Naive datetime — applying ZoneInfo(%s)", tz_str)
                dt = dt.replace(tzinfo=ZoneInfo(tz_str))
            else:
                app.logger.warning("Naive datetime — assuming UTC")
                dt = dt.replace(tzinfo=timezone.utc)

        app.logger.warning("After tz handling: %s (tzinfo=%s)", dt, dt.tzinfo)

        dt_utc = dt.astimezone(timezone.utc)

        app.logger.warning("Converted to UTC: %s", dt_utc)
        app.logger.warning("---- END PARSE ----")

        return dt_utc, False

    elif "date" in event_time_dict:
        app.logger.warning("All-day date field detected: %s", event_time_dict["date"])
        d = dtparser.isoparse(event_time_dict["date"]).date()
        dt = datetime.combine(d, time.min, tzinfo=timezone.utc)
        app.logger.warning("All-day converted to UTC midnight: %s", dt)
        return dt, True

    return None, False

@app.route("/api/google/sync", methods=["POST"])
@require_session_key
def api_google_sync():
    user = User.query.get(g.user_id)
    body = request.json or {}
    google_calendar_id = body.get("google_calendar_id")
    local_calendar_id_param = body.get("local_calendar_id")
    direction = body.get("direction", "both")
    if not google_calendar_id:
        return jsonify({"error": "google_calendar_id required"}), 400

    # Resolve local calendar (default if not provided)
    cal, err = resolve_local_calendar(user, local_calendar_id_param if local_calendar_id_param is not None else None)
    if err:
        return err
    local_calendar_id = cal.id

    gcred = GoogleCalendarCredentials.query.filter_by(user_id=user.id).first()
    if not gcred:
        return jsonify({"error":"no_google_credentials"}), 404

    # find or create mapping row (use resolved local_calendar_id)
    cs = CalendarSync.query.filter_by(user_id=user.id, local_calendar_id=local_calendar_id, google_calendar_id=google_calendar_id).first()
    if not cs:
        cs = CalendarSync(user_id=user.id, local_calendar_id=local_calendar_id, google_calendar_id=google_calendar_id, sync_enabled=True)
        db.session.add(cs)
        db.session.commit()

    creds = Credentials(token=gcred.access_token, refresh_token=gcred.refresh_token,
                        token_uri="https://oauth2.googleapis.com/token",
                        client_id=app.config['GOOGLE_CLIENT_ID'],
                        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
                        expiry=gcred.token_expiry)

    service = build("calendar", "v3", credentials=creds, cache_discovery=False)
    results = {"pulled":0, "pushed":0, "errors":[]}

    def parse_google_dt(val):
        # val is a string like '2025-02-20T12:00:00Z' or returned 'date' (all-day)
        if val is None:
            return None
        dt = dtparser.isoparse(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)

    # ---- PULL phase (remote -> local) ----
    if direction in ("pull", "both"):
        try:
            params = {
                "calendarId": google_calendar_id,
                "showDeleted": True,
                "singleEvents": False,
                "maxResults": 2500
            }

            # Use incremental sync if possible
            try:
                if cs.sync_token:
                    events_resp = service.events().list(calendarId=google_calendar_id, syncToken=cs.sync_token).execute()
                else:
                    events_resp = service.events().list(**params).execute()
            except HttpError as e:
                if getattr(e, "status_code", None) == 410:  # sync token invalid
                    cs.sync_token = None
                    db.session.commit()
                    events_resp = service.events().list(calendarId=google_calendar_id, showDeleted=True, singleEvents=False, maxResults=2500).execute()
                else:
                    raise

            items = events_resp.get("items", [])
            app.logger.warning("Google returned %d items", len(items))
            for item in items:
                # ... (existing pull loop unchanged, but use local_calendar_id when creating new Appointment)
                geid = item.get("id")
                status = item.get("status")
                google_updated = parse_google_dt(item.get("updated"))

                local = Appointment.query.filter_by(google_event_id=geid, user_id=user.id).first()

                # Handle cancelled events
                if status == "cancelled":
                    if local and not local.deleted_at:
                        local.deleted_at = datetime.now(timezone.utc)
                        db.session.commit()
                    continue

                s = item.get("start", {})
                e = item.get("end", {})

                if "dateTime" in s:
                    start_dt, is_all_day = parse_google_event_datetime(s)
                    end_dt, _ = parse_google_event_datetime(e)
                    is_all_day = False
                else:
                    start_date_str = s.get("date")
                    end_date_str = e.get("date") if e else None
                    start_dt = dtparser.isoparse(start_date_str).replace(tzinfo=UTC)
                    if end_date_str:
                        end_dt = dtparser.isoparse(end_date_str).replace(tzinfo=UTC)
                    else:
                        end_dt = (start_dt + timedelta(days=1)).replace(tzinfo=UTC)
                    is_all_day = True

                rrule = None
                if item.get("recurrence"):
                    rrule = item["recurrence"][0] if len(item["recurrence"]) > 0 else None

                if not local:
                    # Create new local appointment against the resolved local_calendar_id
                    ap = Appointment(
                        title=item.get("summary") or "",
                        description=item.get("description"),
                        start_datetime=start_dt.astimezone(UTC),
                        end_datetime=end_dt.astimezone(UTC),
                        user_id=user.id,
                        calendar_id=local_calendar_id,  # <- resolved calendar
                        recurrence_rule=rrule,
                        is_all_day=is_all_day,
                        google_event_id=geid,
                        updated_at=google_updated
                    )
                    db.session.add(ap)
                    db.session.commit()
                    results["pulled"] += 1
                else:
                    # existing local update logic unchanged
                    local_updated = local.updated_at or getattr(local, "created_at", None)
                    lu = ensure_aware(local_updated)
                    gu = ensure_aware(google_updated)

                    update_from_google = False
                    if not lu:
                        update_from_google = True
                    elif gu and gu > lu:
                        update_from_google = True

                    if update_from_google:
                        local.title = item.get("summary") or local.title
                        local.description = item.get("description")
                        local.start_datetime = start_dt.astimezone(UTC)
                        local.end_datetime = end_dt.astimezone(UTC)
                        local.recurrence_rule = rrule
                        local.is_all_day = is_all_day
                        local.deleted_at = None
                        local.updated_at = google_updated  # keep tz-aware
                        db.session.commit()
                        results["pulled"] += 1

            # Save nextSyncToken for incremental sync
            if events_resp.get("nextSyncToken"):
                cs.sync_token = events_resp.get("nextSyncToken")
                cs.last_synced = datetime.now(timezone.utc)
                db.session.commit()
        except HttpError as e:
            results["errors"].append(str(e))
            return jsonify({"error": "google_pull_error", "details": str(e)}), 500

    # ---- PUSH phase (local -> remote) ----
    if direction in ("push", "both"):
        try:
            # fetch all local events for the resolved calendar (excluding soft-deleted)
            local_events = Appointment.query.filter_by(user_id=user.id, calendar_id=local_calendar_id).filter(Appointment.deleted_at == None).all()

            for le in local_events:
                body = {
                    "summary": le.title,
                    "description": le.description
                }
                start_utc = ensure_dt_utc(le.start_datetime)
                end_utc   = ensure_dt_utc(le.end_datetime)

                if le.is_all_day:
                    body["start"] = {"date": start_utc.date().isoformat()}
                    body["end"] = {"date": end_utc.date().isoformat()}
                else:
                    body["start"] = {"dateTime": start_utc.isoformat()}
                    body["end"]   = {"dateTime": end_utc.isoformat()}

                if le.recurrence_rule:
                    body["recurrence"] = [le.recurrence_rule]

                if le.google_event_id:
                    try:
                        ge = service.events().get(calendarId=google_calendar_id, eventId=le.google_event_id).execute()
                        google_updated = parse_google_dt(ge.get("updated"))
                        local_updated = le.updated_at

                        local_updated_aware = ensure_aware(local_updated)
                        google_updated_aware = ensure_aware(google_updated)

                        if local_updated_aware and (not google_updated_aware or local_updated_aware > google_updated_aware):
                            service.events().update(calendarId=google_calendar_id, eventId=le.google_event_id, body=body).execute()
                            results["pushed"] += 1
                    except HttpError as e:
                        if getattr(e, "status_code", None) in (404, 410):
                            created = service.events().insert(calendarId=google_calendar_id, body=body).execute()
                            le.google_event_id = created.get("id")
                            db.session.commit()
                            results["pushed"] += 1
                        else:
                            results["errors"].append(str(e))
                else:
                    created = service.events().insert(calendarId=google_calendar_id, body=body).execute()
                    le.google_event_id = created.get("id")
                    db.session.commit()
                    results["pushed"] += 1

            # Handle local deletions: delete soft-deleted events from Google
            deleted_locals = Appointment.query.filter_by(user_id=user.id, calendar_id=local_calendar_id).filter(Appointment.deleted_at != None).all()
            for dl in deleted_locals:
                if dl.google_event_id:
                    try:
                        service.events().delete(calendarId=google_calendar_id, eventId=dl.google_event_id).execute()
                    except HttpError:
                        pass

        except HttpError as e:
            results["errors"].append(str(e))
            return jsonify({"error": "google_push_error", "details": str(e)}), 500

    return jsonify(results), 200

@app.route("/api/notes", methods=["GET"])
@require_session_key
def api_list_notes():
    user = User.query.get(g.user_id)
    notes = Note.query.filter_by(user_id=user.id).all()
    # Keep the payload minimal for the picker
    return jsonify([{"id": n.id, "title": (n.title[:60] if getattr(n, "title", None) else (n.content[:60] if getattr(n,"content",None) else "Untitled")), "snippet": getattr(n, "content", "")[:150]} for n in notes]), 200

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
    flow_tags = parse_flow_tags(f"{title} {text}")
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
        
    if flow_tags['project_id']:
        project = FlowProject.query.filter_by(
            id=flow_tags['project_id'],
            user_id=user_id
        ).first()
        if not project:
            return jsonify(error="Project not found or access denied"), 404
        
        # Find or default to 'main' branch
        branch = None
        if flow_tags['branch_name']:
            branch = FlowBranch.query.filter_by(
                name=flow_tags['branch_name'],
                project_id=project.id
            ).first()
            if not branch:
                return jsonify(error=f"Branch '{flow_tags['branch_name']}' not found in project"), 404
        else:
            branch = FlowBranch.query.filter_by(
                project_id=project.id,
                name='main'
            ).first()
        
        # Assign to todo
        new_todo.flow_branch_id = branch.id if branch else None
        new_todo.estimated_impact = flow_tags['impact']

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

    if 'title' in data or 'description' in data:
        new_text = f"{data.get('title', todo.title)} {data.get('description', todo.text)}"
        flow_tags = parse_flow_tags(new_text)
        
        # Only process if project tag exists
        if flow_tags['project_id']:
            project = FlowProject.query.filter_by(
                id=flow_tags['project_id'],
                user_id=user_id
            ).first()
            if not project:
                return jsonify(error="Project not found or access denied"), 404
            
            # Update branch linkage
            if flow_tags['branch_name']:
                branch = FlowBranch.query.filter_by(
                    name=flow_tags['branch_name'],
                    project_id=project.id
                ).first()
                if not branch:
                    return jsonify(error=f"Branch '{flow_tags['branch_name']}' not found"), 404
                todo.flow_branch_id = branch.id
            elif todo.flow_branch_id:  # Clear branch if no tag
                todo.flow_branch_id = None
            
            # Update impact
            todo.estimated_impact = flow_tags['impact']

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
    
@app.route('/todos/<int:todo_id>/toggle-completed', methods=['POST'])
@require_session_key
def toggle_todo_completed(todo_id):
    user_id = g.user_id
    todo = Todo.query.get(todo_id)
    
    if not todo or todo.user_id != user_id:
        return jsonify({"error": "Todo not found"}), 404
    
    was_completed = todo.completed
    todo.completed = not todo.completed
    
    try:
        if not was_completed and todo.completed and todo.flow_branch_id and todo.estimated_impact > 0:
            # Marking as complete - create commit
            new_commit = FlowCommit(
                branch_id=todo.flow_branch_id,
                title=f"Completed: {todo.title}",
                description=f"Automatically completed todo: {todo.text or 'No description'}",
                impact=todo.estimated_impact,
                todo_id=todo.id  # Link the commit to the todo
            )
            db.session.add(new_commit)
            
            # Update project status if needed
            project = FlowProject.query.get(todo.flow_branch.project_id)
            if project.progress >= project.total_impact and project.status != 'completed':
                project.status = 'completed'
        
        elif was_completed and not todo.completed:
            # Marking as incomplete - find and revert the commit
            commit_to_revert = todo.commit  # This uses our property
            
            if commit_to_revert:
                # Find all subsequent commits to revert
                subsequent_commits = FlowCommit.query.filter(
                    FlowCommit.branch_id == todo.flow_branch_id,
                    FlowCommit.created_at >= commit_to_revert.created_at
                ).all()
                
                # Delete the commits
                for commit in subsequent_commits:
                    db.session.delete(commit)
                
                # Update project status if needed
                project = FlowProject.query.get(todo.flow_branch.project_id)
                if project.status == 'completed':
                    # Recalculate progress
                    if project.progress < project.total_impact:
                        project.status = 'active'
        
        db.session.commit()
        
        return jsonify({
            "message": f"Todo marked as {'completed' if todo.completed else 'uncompleted'}!",
            "completed": todo.completed
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

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

@app.route('/groups/modify', methods=['POST'])
@require_session_key
def modify_group():
    data = request.json
    title = data.get('name')
    group_id = data.get('group_id')
    group = Group.query.get(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404
    # Check if the user is an admin of the group
    membership = GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first()
    if not membership or not membership.admin:
        return jsonify({"error": "User is not an admin of this group"}), 403
    if not title:
        return jsonify({"error": "Group name is required"}), 400

    group.name = title
    db.session.commit()

    return jsonify({"message": "Group name updated successfully!"}), 200

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

# -----------------------
# Group notes routes (updated to support folders)
# -----------------------
@app.route('/groups/<string:group_id>/notes', methods=['GET'])
@require_session_key
def get_group_notes(group_id):
    # membership check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    # optional folder filter (query param)
    folder_id = request.args.get('folder_id', type=int)
    query = Note.query.filter_by(group_id=group_id)

    if folder_id is not None:
        # ensure folder exists and belongs to this group
        folder = Folder.query.filter_by(id=folder_id, group_id=group_id).first()
        if not folder:
            return jsonify({"error": "Folder not found or does not belong to this group"}), 400
        query = query.filter_by(folder_id=folder_id)
    else:
        # if folder_id not specified, return notes in root (folder_id is None)
        query = query.filter_by(folder_id=None)

    notes = query.order_by(Note.id.desc()).all()

    def attachments_for_note(n):
        rows = NoteUpload.query.filter_by(note_id=n.id).all()
        out = []
        for r in rows:
            up = Upload.query.get(r.upload_id)
            if up and not up.deleted:
                out.append({
                    "upload_id": up.id,
                    "filename": up.original_filename,
                    "size_bytes": up.size_bytes,
                    "mimetype": up.mimetype
                })
        return out

    return jsonify([{
        "id": note.id,
        "title": note.title,
        "note": note.note,
        "tag": note.tag,
        "folder_id": note.folder_id,
        "attachments": attachments_for_note(note)
    } for note in notes]), 200


@app.route('/groups/<string:group_id>/notes', methods=['POST'])
@require_session_key
def add_group_note(group_id):
    # membership check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    data = request.json or {}
    if 'note' not in data:
        return jsonify({"error": "Missing note content"}), 400

    sanitized_note = sanitize_html(data['note'])

    # validate folder_id if provided
    folder_id = data.get('folder_id')
    if folder_id is not None:
        folder = Folder.query.filter_by(id=folder_id, group_id=group_id).first()
        if not folder:
            return jsonify({"error": "Folder not found or does not belong to this group"}), 400

    attachments = data.get('attachments') or []
    valid_attachments = []

    # Validate attachments: ensure they exist and are not deleted and not already attached
    for uid in attachments:
        up = Upload.query.get(uid)
        if not up or up.deleted:
            return jsonify({"error": f"Invalid or deleted attachment id: {uid}"}), 400
        if NoteUpload.query.filter_by(upload_id=uid).first():
            return jsonify({"error": f"Attachment {uid} is already attached to a note."}), 400
        valid_attachments.append(up.id)

    new_note = Note(
        user_id=None,
        group_id=group_id,
        title=data.get('title'),
        note=sanitized_note,
        tag=data.get('tag'),
        folder_id=folder_id
    )
    db.session.add(new_note)
    db.session.commit()

    # associate attachments
    try:
        for uid in valid_attachments:
            db.session.add(NoteUpload(note_id=new_note.id, upload_id=uid))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to associate attachments to new group note: %s", e)
        return jsonify({"error": "Failed to associate attachments"}), 500

    return jsonify({"message": "Group note added successfully!", "id": new_note.id}), 201


@app.route('/groups/<string:group_id>/notes/<int:note_id>', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_group_note(group_id, note_id):
    # membership check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    note = Note.query.filter_by(id=note_id, group_id=group_id).first()
    if not note:
        return jsonify({"error": "Note not found"}), 404

    if request.method == 'PUT':
        data = request.json or {}

        # update fields if present
        if 'title' in data:
            note.title = data.get('title')
        if 'note' in data:
            note.note = sanitize_html(data.get('note', note.note))
        if 'tag' in data:
            note.tag = data.get('tag')

        # folder_id handling (same semantics as personal notes)
        if 'folder_id' in data:
            folder_id = data.get('folder_id')
            if folder_id is not None:
                folder = Folder.query.filter_by(id=folder_id, group_id=group_id).first()
                if not folder:
                    return jsonify({"error": "Folder not found or does not belong to this group"}), 400
                note.folder_id = folder_id
            else:
                note.folder_id = None
        # if not present, don't change folder

        requested_attachments = set(data.get('attachments') or [])
        existing_attachments = {nu.upload_id for nu in NoteUpload.query.filter_by(note_id=note.id).all()}

        to_add = requested_attachments - existing_attachments
        to_remove = existing_attachments - requested_attachments

        # Validate additions
        for uid in list(to_add):
            up = Upload.query.get(uid)
            if not up or up.deleted:
                return jsonify({"error": f"Invalid attachment to add: {uid}"}), 400
            if NoteUpload.query.filter_by(upload_id=uid).first():
                return jsonify({"error": f"Attachment {uid} is already attached to a note."}), 400

        try:
            for uid in to_add:
                db.session.add(NoteUpload(note_id=note.id, upload_id=uid))
            for uid in to_remove:
                nu_row = NoteUpload.query.filter_by(note_id=note.id, upload_id=uid).first()
                if nu_row:
                    db.session.delete(nu_row)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.exception("DB error when updating group note attachments: %s", e)
            return jsonify({"error": "Database error updating attachments"}), 500

        # Force-delete any removed attachments (owned by anyone)
        actor_user = User.query.get(g.user_id)
        for uid in to_remove:
            try:
                ok, msg = force_delete_upload(uid, actor_user=actor_user)
                if not ok:
                    app.logger.warning("Failed to force-delete upload %s: %s", uid, msg)
            except Exception:
                app.logger.exception("Failed to force-delete upload %s", uid)

        return jsonify({"message": "Group note updated successfully!"}), 200

    elif request.method == 'DELETE':
        existing_attachments = {nu.upload_id for nu in NoteUpload.query.filter_by(note_id=note.id).all()}
        try:
            NoteUpload.query.filter_by(note_id=note.id).delete()
            db.session.delete(note)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.exception("DB error deleting group note: %s", e)
            return jsonify({"error": "Database error deleting note"}), 500

        actor_user = User.query.get(g.user_id)
        for uid in existing_attachments:
            try:
                ok, msg = force_delete_upload(uid, actor_user=actor_user)
                if not ok:
                    app.logger.warning("Failed to force-delete upload %s on note delete: %s", uid, msg)
            except Exception:
                app.logger.exception("Failed to force-delete upload %s on note delete", uid)

        return jsonify({"message": "Group note deleted successfully."}), 200
    
# -----------------------
# Group folder management (mirrors /folders but for groups)
# -----------------------
@app.route('/groups/<string:group_id>/folders', methods=['GET', 'POST'])
@require_session_key
def manage_group_folders(group_id):
    # membership check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    if request.method == 'POST':
        data = request.json or {}
        name = data.get('name')
        parent_id = data.get('parent_id')

        if not name:
            return jsonify({"error": "Folder name is required"}), 400

        # Validate parent folder if provided (must belong to same group)
        if parent_id is not None:
            parent = Folder.query.filter_by(id=parent_id, group_id=group_id).first()
            if not parent:
                return jsonify({"error": "Parent folder not found or access denied"}), 400

        new_folder = Folder(
            user_id=None,
            group_id=group_id,
            name=name,
            parent_id=parent_id
        )
        db.session.add(new_folder)
        db.session.commit()

        return jsonify({"message": "Folder created successfully!", "folder": new_folder.to_dict()}), 201

    else:
        parent_id = request.args.get("parent_id", type=int)
        query = Folder.query.filter_by(group_id=group_id)

        if parent_id is None:
            query = query.filter(Folder.parent_id == None)
        else:
            query = query.filter(Folder.parent_id == parent_id)

        folders = query.all()
        return jsonify([folder.to_dict() for folder in folders])


@app.route('/groups/<string:group_id>/folders/<int:folder_id>/parents', methods=['GET'])
@require_session_key
def get_group_parent_folders(group_id, folder_id):
    # membership check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    folder = Folder.query.filter_by(id=folder_id, group_id=group_id).first()
    if not folder:
        return jsonify({"error": "Folder not found"}), 404

    chain = []
    while folder:
        chain.append(folder.to_dict())
        if not folder.parent_id:
            break
        folder = Folder.query.filter_by(id=folder.parent_id, group_id=group_id).first()

    return jsonify(chain[::-1]), 200


@app.route('/groups/<string:group_id>/folders/<int:folder_id>', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_group_folder(group_id, folder_id):
    # membership check
    if not GroupMember.query.filter_by(user_id=g.user_id, group_id=group_id).first():
        return jsonify({"error": "Not a member of this group"}), 403

    folder = Folder.query.filter_by(id=folder_id, group_id=group_id).first()
    if not folder:
        return jsonify({"error": "Folder not found"}), 404

    if request.method == 'PUT':
        data = request.json or {}
        name = data.get('name')
        parent_id = data.get('parent_id')

        if name:
            folder.name = name

        if parent_id is not None:
            if parent_id == folder_id:
                return jsonify({"error": "Cannot set folder as its own parent"}), 400

            parent = Folder.query.filter_by(id=parent_id, group_id=group_id).first()
            if not parent:
                return jsonify({"error": "Parent folder not found or access denied"}), 400

            # Prevent circular reference: ensure parent is not a child of folder
            all_child_ids = collect_all_folder_ids(folder)
            if parent_id in all_child_ids:
                return jsonify({"error": "Cannot set a descendant as parent"}), 400

            folder.parent_id = parent_id
        else:
            folder.parent_id = None

        db.session.commit()
        return jsonify({"message": "Folder updated successfully!", "folder": folder.to_dict()}), 200

    elif request.method == 'DELETE':
        # Ensure g.user is populated for delete helpers
        if not hasattr(g, 'user'):
            g.user = User.query.get(g.user_id)

        action = request.args.get('action')  # None, "move_up", "delete_all"

        # Collect subtree and notes
        all_folder_ids = collect_all_folder_ids(folder)
        notes = collect_note_ids_in_folders(all_folder_ids, owner_group_id=group_id)

        # If no action, return summary
        if not action:
            has_subfolders = len(all_folder_ids) > 1
            notes_count = len(notes)
            if not has_subfolders and notes_count == 0:
                return jsonify({
                    "can_delete_direct": True,
                    "message": "Folder is empty and can be deleted immediately."
                }), 200

            if notes_count == 0:
                return jsonify({
                    "can_delete_empty_stack": True,
                    "message": "Folder and subfolders contain no notes and can be deleted."
                }), 200

            return jsonify({
                "requires_confirmation": True,
                "notes_count": notes_count,
                "folders_count": len(all_folder_ids),
                "message": "Folder subtree contains notes. Choose action: move_up or delete_all."
            }), 200

        # Perform action
        if action == "move_up":
            try:
                parent_id = folder.parent_id  # may be None

                # Move immediate children up one level
                children = Folder.query.filter_by(parent_id=folder.id, group_id=group_id).all()
                for c in children:
                    c.parent_id = parent_id

                # Move notes directly in folder to parent_id
                direct_notes = Note.query.filter_by(folder_id=folder.id, group_id=group_id).all()
                for n in direct_notes:
                    n.folder_id = parent_id

                db.session.delete(folder)
                db.session.commit()
                return jsonify({"message": "Folder removed and children moved up successfully."}), 200
            except Exception as e:
                app.logger.exception("Error moving children up: %s", e)
                db.session.rollback()
                return jsonify({"error": "Error while moving children up."}), 500

        elif action == "delete_all":
            try:
                ok, msg = delete_notes_and_attachments(notes, g.user, owner_group_id=group_id)
                if not ok:
                    return jsonify({"error": msg}), 500

                post_order_folders = get_recursive_folder_tree(folder)
                for f in post_order_folders:
                    if f.group_id != group_id:
                        db.session.rollback()
                        return jsonify({"error": "Permission error while deleting folders."}), 403
                    db.session.delete(f)

                db.session.commit()
                return jsonify({"message": "Folder and all subfolders and notes deleted."}), 200
            except Exception as e:
                app.logger.exception("Error deleting subtree: %s", e)
                db.session.rollback()
                return jsonify({"error": "Server error while deleting subtree."}), 500
        else:
            return jsonify({"error": "Unknown action."}), 400
    
from io import BytesIO
from flask import send_file

from io import BytesIO
from flask import send_file, send_from_directory, redirect, request, jsonify, g
import tempfile

@app.route('/uploads/<int:upload_id>/download', methods=['GET'])
@require_session_key
def download_upload_hybrid(upload_id):
    user = getattr(g, 'user', None) or User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    upload = Upload.query.get(upload_id)
    if not upload or upload.deleted:
        return jsonify({"error": "Not found"}), 404

    if upload.user_id != user.id:
        return jsonify({"error": "Forbidden"}), 403

    # Decide inline vs download
    inline = request.args.get('inline', '0') in ['1', 'true', 'yes']

    # --- Dropbox files ---
    if upload.storage_backend == "dropbox":
        if inline:
            # Proxy through Flask for inline display
            try:
                metadata, res = dbx.files_download(upload.stored_filename)
                return send_file(
                    BytesIO(res.content),
                    mimetype=upload.mimetype,
                    as_attachment=False,
                    download_name=upload.original_filename
                )
            except Exception:
                app.logger.exception("Failed to proxy Dropbox file %s", upload.stored_filename)
                return jsonify({"error": "Failed to proxy Dropbox file"}), 500
        else:
            # Direct download link for non-inline
            try:
                temp_link = dbx.files_get_temporary_link(upload.stored_filename).link
                return redirect(temp_link)
            except Exception:
                app.logger.exception("Failed to generate Dropbox download link %s", upload.stored_filename)
                return jsonify({"error": "Failed to generate Dropbox download link"}), 500

    # --- MEGA files ---
    if upload.storage_backend == "mega":
        mega_obj = getattr(upload, "mega_file_obj", None)
        # Try to use any stored public link first for direct redirects
        stored_link = upload.stored_filename if upload.stored_filename and str(upload.stored_filename).startswith("http") else None

        if not mega_obj and not stored_link:
            app.logger.error("MEGA file has no file object or stored link: upload_id=%s", upload_id)
            return jsonify({"error": "MEGA file metadata missing"}), 500

        # Non-inline: prefer redirect to public link to avoid proxying large files
        if not inline:
            # If we already stored a link, redirect to it
            if stored_link:
                return redirect(stored_link)
            # Otherwise try to generate a link and redirect
            try:
                link = mega_account.get_upload_link(mega_obj)
                return redirect(link)
            except Exception:
                app.logger.exception("Failed to generate MEGA public link for upload %s", upload_id)
                # Fall through to proxying below

        if inline:
            try:
                mega_obj_full = json.loads(upload.mega_file_obj)

                if 'f' not in mega_obj_full or not mega_obj_full['f']:
                    return jsonify({"error": "Invalid MEGA file object"}), 500

                mega_handle = mega_obj_full['f'][0].get('h')
                if not mega_handle:
                    return jsonify({"error": "MEGA handle missing"}), 500

                # Get all resolved files
                all_files = mega_account.get_files()
                resolved_file = all_files.get(mega_handle)
                if not resolved_file:
                    app.logger.error(
                        "Resolved MEGA file not found for handle %s (upload_id=%s)",
                        mega_handle,
                        upload_id,
                    )
                    return jsonify({"error": "MEGA file not accessible"}), 404

                # Let Mega write to its own temp file
                downloaded_path = mega_account._download_file(
                    None,  # file_handle
                    None,  # file_key
                    file=resolved_file,
                    is_public=False
                )

                # Serve the downloaded file via Flask
                return send_file(
                    downloaded_path,
                    mimetype=upload.mimetype,
                    as_attachment=False,
                    download_name=upload.original_filename
                )

            except Exception as e:
                app.logger.exception("Failed to proxy MEGA file %s: %s", upload_id, e)
                return jsonify({"error": "Failed to proxy MEGA file"}), 500

            finally:
                # safe deletion
                try:
                    if 'downloaded_path' in locals() and os.path.exists(downloaded_path):
                        os.remove(downloaded_path)
                except Exception:
                    pass


    # --- Local files ---
    # For local storage fallback and general local handling
    filename = upload.stored_filename
    if not filename:
        return jsonify({"error": "File not found"}), 404

    # Build full path based on new folder structure
    file_path = os.path.join(app.config['UPLOAD_FOLDER_LOCAL_FILES'], os.path.basename(filename))

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER_LOCAL_FILES'],
            os.path.basename(filename),
            as_attachment=not inline,
            download_name=upload.original_filename
        )
    except TypeError:
        # fallback for older Flask versions
        return send_from_directory(
            UPLOAD_FOLDER_LOCAL_FILES,
            os.path.basename(file_path),
            as_attachment=not inline,
            attachment_filename=upload.original_filename
        )

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
            file_path = os.path.join(app.config['UPLOAD_FOLDER_PROFILE_PICS'], filename)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER_PROFILE_PICS'], f"temp_{filename}")

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

from flask import request, session, jsonify

@app.route('/api/identify', methods=['POST'])
def identify():
    data = request.get_json() or {}
    visitor_id = data.get('visitorId')
    if not visitor_id:
        return jsonify({'error': 'visitorId missing'}), 400

    # Save in session for later linking
    session['visitor_id'] = visitor_id

    # Get real client IP (behind proxies)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip.split(',')[0].strip()  # first IP in the list

    # Upsert fingerprint record
    fp = FingerPrint.query.filter_by(visitor_id=visitor_id).first()
    if not fp:
        fp = FingerPrint(
            visitor_id=visitor_id,
            last_ip=ip
        )
        db.session.add(fp)
    else:
        fp.last_ip = ip

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
        users = User.query.with_entities(User.id, User.suspended, User.username, User.profile_picture, User.allows_sharing, User.role, User.malicious_violations).all()
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
    
@app.route('/admin/reset_violations', methods=['PUT'])
@require_session_key
@require_admin
def reset_violations():
    user = User.query.get(g.user_id)
    if not user or user.role != "admin":
        return jsonify({"error": "Insufficient permissions"}), 403

    data = request.json
    target_user_id = data.get("user_id")
    target_user = User.query.get(target_user_id)

    if not target_user:
        return jsonify({"error": "User not found"}), 404

    target_user.malicious_violations = 0
    db.session.commit()
    return jsonify({"message": f"Malicious violations reset for user {target_user_id}"}), 200

# -------------------------
# Update username
# -------------------------
@app.route('/admin/user/<int:target_user_id>/username', methods=['PUT'])
@require_session_key
@require_admin
def admin_update_username(target_user_id):
    data = request.get_json(silent=True) or {}
    new_username = (data.get("username") or "").strip()
    if not new_username:
        return jsonify({"error": "Username cannot be empty"}), 400

    target = User.query.get(target_user_id)
    if not target:
        return jsonify({"error": "User not found"}), 404

    # Optional uniqueness check (uncomment if you want uniqueness enforced)
    existing = User.query.filter(User.username == new_username, User.id != target_user_id).first()
    if existing:
        return jsonify({"error": "Username already in use"}), 409

    target.username = new_username
    db.session.commit()
    return jsonify({"message": "Username updated", "user_id": target_user_id, "username": new_username}), 200


# -------------------------
# Update allows_sharing
# -------------------------
@app.route('/admin/user/<int:target_user_id>/allows_sharing', methods=['PUT'])
@require_session_key
@require_admin
def admin_update_allows_sharing(target_user_id):
    data = request.get_json(silent=True) or {}
    if "allows_sharing" not in data:
        return jsonify({"error": "Missing 'allows_sharing' value"}), 400

    value = data.get("allows_sharing")
    # Accept booleans or string representations
    if isinstance(value, str):
        value = value.lower() in ("1", "true", "yes", "on")

    target = User.query.get(target_user_id)
    if not target:
        return jsonify({"error": "User not found"}), 404

    target.allows_sharing = bool(value)
    db.session.commit()
    return jsonify({"message": "Allows sharing updated", "user_id": target_user_id, "allows_sharing": target.allows_sharing}), 200


# -------------------------
# Update malicious_violations
# -------------------------
@app.route('/admin/user/<int:target_user_id>/violations', methods=['PUT'])
@require_session_key
@require_admin
def admin_update_violations(target_user_id):
    data = request.get_json(silent=True) or {}
    try:
        new_val = int(data.get("malicious_violations"))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid malicious_violations value"}), 400

    if new_val < 0:
        return jsonify({"error": "malicious_violations must be >= 0"}), 400

    target = User.query.get(target_user_id)
    if not target:
        return jsonify({"error": "User not found"}), 404

    target.malicious_violations = new_val
    db.session.commit()
    return jsonify({"message": "Violations updated", "user_id": target_user_id, "malicious_violations": new_val}), 200


# -------------------------
# Admin update/delete profile picture (re-uses your existing logic style)
# -------------------------
@app.route('/admin/user/<int:target_user_id>/profile_picture', methods=['POST', 'DELETE'])
@require_session_key
@require_admin
def admin_update_profile_picture(target_user_id):
    target = User.query.get(target_user_id)
    if not target:
        return jsonify({"error": "User not found"}), 404

    # POST -> upload and process new profile picture for target user
    if request.method == 'POST':
        if 'profile_picture' not in request.files:
            return jsonify({"error": "No file part in the request"}), 400

        file = request.files['profile_picture']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        if not file or not allowed_file(file.filename):
            return jsonify({"error": "Invalid or disallowed file"}), 400

        # Build filename using target username (keep .jpg), mirror your logic
        filename = secure_filename(f"{target.username}_{uuid.uuid4().hex}.jpg")
        upload_folder = app.config.get('UPLOAD_FOLDER_PROFILE_PICS')
        file_path = os.path.join(upload_folder, filename)
        temp_path = os.path.join(upload_folder, f"temp_{filename}")

        try:
            # Ensure upload folder exists
            os.makedirs(upload_folder, exist_ok=True)

            # Save temporarily
            file.save(temp_path)

            # Open and process image
            with Image.open(temp_path) as img:
                # Convert to RGB if needed (removes transparency)
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')

                # Downscale image (max dimensions: 500x500)
                img.thumbnail((500, 500), Image.LANCZOS)

                # Save compressed version with quality similar to your route
                img.save(file_path, 'JPEG', quality=45, optimize=True)

            # Remove temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)

        except Exception as e:
            app.logger.error(f"Admin image processing failed for user {target_user_id}: {e}")
            # Clean up any partial files
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass
            return jsonify({"error": "Failed to process image"}), 500

        # Delete old profile picture after successful processing
        old_picture = target.profile_picture
        if old_picture and os.path.isfile(old_picture):
            try:
                os.remove(old_picture)
            except Exception as e:
                app.logger.warning(f"Failed to delete old profile picture for user {target_user_id}: {e}")

        # Update database record
        target.profile_picture = file_path
        db.session.commit()

        return jsonify({"message": "Profile picture updated successfully", "path": file_path}), 200

    # DELETE -> remove target user's profile picture
    elif request.method == 'DELETE':
        if target.profile_picture and os.path.isfile(target.profile_picture):
            try:
                os.remove(target.profile_picture)
            except Exception as e:
                app.logger.warning(f"Failed to delete profile picture for user {target_user_id}: {e}")
                return jsonify({"error": "Failed to delete profile picture file"}), 500

            target.profile_picture = None
            db.session.commit()
            return jsonify({"message": "Profile picture deleted successfully!"}), 200

        return jsonify({"error": "No profile picture to delete"}), 400

    
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
    data = request.json or {}
    
    user_id = data.get("user_id")
    title   = data.get("title")
    message = data.get("message")
    module  = data.get("module")

    if not user_id or not message or not title or not module:
        return jsonify({"error": "All fields are required."}), 400

    if not module.startswith("/"):
        return jsonify({"error": "Module must start with a slash (/)"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found!"}), 404

    send_notification(user_id, title, message, module)
    return jsonify({"message": f"Notification sent to {bleach.clean(user.username)} ({user_id})"}), 200 # dit moet echt gecleaned worden op een admin pagina

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
def update_code_route():
    return update_code()

def update_code():
    thread = threading.Thread(target=run_update_script)
    thread.start()

    return jsonify({"status": "Update initiated"})

@app.route('/admin/scan-updates', methods=['GET'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def scan_updates_route():
    return scan_updates()

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

        # Exclude merge commits by using --no-merges
        commits_behind = sum(1 for _ in repo.iter_commits(f"{local.commit.hexsha}..{remote_ref.commit.hexsha}", no_merges=True))
        up_to_date = (commits_behind == 0)

        return jsonify({
            "update_available": not up_to_date,
            "commits_behind": commits_behind,
            "message": ("Already up-to-date" if up_to_date else f"{commits_behind} commit(s) behind")
        })

    except (GitCommandError, FileNotFoundError) as e:
        app.logger.error("Error in scan_updates: %s", str(e))
        return jsonify({"error": "Failed to scan for updates", "details": str(e)}), 500

#lets try one more time
@app.route('/admin/scan-dev-vs-master', methods=['GET'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def scan_dev_vs_master_route():
    return scan_dev_vs_master()

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
def merge_dev_into_master_route():
    return merge_dev_into_master()

def merge_dev_into_master():
    # GitHub API configuration
    GITHUB_TOKEN = app.config["GITHUB_PERSONAL_ACCESS_TOKEN"]
    try:
        load_secrets()
    except Exception as e:
        app.logger.error("Failed to load secrets: %s", str(e))
        return jsonify({"error": "Failed to load GitHub secrets", "details": str(e)}), 500
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

@app.route("/deploy/local", methods=['POST'])
@require_localhost_domain
@require_session_key
@require_admin
def deploy_local():
    # Step 1: Commit and push local changes (if any)
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True
    )

    if result.stdout.strip():
        cmds = [
            ["git", "add", "."],
            ["git", "commit", "-m", "Auto deploy"],
            ["git", "push", "origin", "dev"]
        ]
        for cmd in cmds:
            print(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)

    # Step 2: Trigger remote deploy
    DEPLOY_HASH = generate_deploy_hash()
    url = "https://bosbes.eu.pythonanywhere.com/remote/deploy"

    try:
        resp = requests.post(
            url,
            headers={"X-Deploy-Hash": DEPLOY_HASH},
            timeout=60
        )

        # Attempt to parse JSON response
        remote_payload = None
        if "application/json" in resp.headers.get("Content-Type", ""):
            remote_payload = resp.json()

        return jsonify({
            "status": "ok" if resp.ok else "error",
            "message": "Remote deploy completed" if resp.ok else "Remote deploy failed",
            "remote": {
                "http_status": resp.status_code,
                "payload": remote_payload,
                "raw": None if remote_payload else resp.text
            }
        }), resp.status_code

    except requests.Timeout:
        return jsonify({
            "status": "error",
            "message": "Remote deploy timed out",
            "remote": None
        }), 504

    except requests.RequestException as e:
        return jsonify({
            "status": "error",
            "message": "Failed to reach remote deploy endpoint",
            "details": str(e)
        }), 500
#x
def deploy_all():
    results = {}

    def safe_extract_json(resp):
        """
        Safely extract JSON data and status code from a response-like object.
        Handles:
          - Flask Response objects
          - Tuples of (data, status)
          - Plain dicts
        """
        if isinstance(resp, tuple):
            data, status = resp
            if hasattr(data, "get_json"):
                return data.get_json(), status
            return data if isinstance(data, dict) else {}, status
        if hasattr(resp, "get_json"):
            return resp.get_json(), 200
        if isinstance(resp, dict):
            return resp, 200
        # fallback for unknown types
        return {}, 500

    # Step 1: Check dev vs master
    dev_vs_master_json, status = safe_extract_json(scan_dev_vs_master())
    results['scan_dev_vs_master'] = dev_vs_master_json
    if status != 200 or not dev_vs_master_json.get('dev_ahead_of_master', False):
        return jsonify({
            "status": "Aborted",
            "reason": "Dev branch is not ahead of master",
            "details": results
        }), 400

    # Step 2: Merge dev into master
    merge_json, status = safe_extract_json(merge_dev_into_master())
    results['merge_dev_into_master'] = merge_json
    if status != 200:
        return jsonify({
            "status": "Aborted",
            "reason": "Merge failed",
            "details": results
        }), 500

    # Step 3: Scan updates (check if remote master has new commits)
    scan_json, status = safe_extract_json(scan_updates())
    results['scan_updates'] = scan_json
    if status != 200:
        return jsonify({
            "status": "Aborted",
            "reason": "Remote master branch not ahead, PR may not have merged correctly",
            "details": results
        }), 500

    # Step 4: Update code
    update_json, status = safe_extract_json(update_code())
    results['update_code'] = update_json
    if status != 200:
        return jsonify({
            "status": "Completed with errors",
            "details": results
        }), 500

    # Step 5: Everything succeeded
    return jsonify({
        "status": "Deployment completed successfully",
        "details": results
    }), 200

@app.route('/remote/deploy', methods=['POST'])
def remote_deploy():
    provided_hash = request.headers.get("X-Deploy-Hash") or request.args.get("hash")
    if not provided_hash:
        return {"error": "Missing hash"}, 401

    expected_hash = generate_deploy_hash()
    if provided_hash != expected_hash:
        return {"error": "Invalid hash"}, 403

    print("REMOTE DEPLOY HIT")

    # Call your existing deploy_all function
    return deploy_all()

@app.route('/admin/versions', methods=['GET', 'POST'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def versions():
    if request.method == 'GET':
        versions = Version.query.order_by(Version.created_at.desc()).all()
        return jsonify([{
            'id': v.id,
            'version': v.version_number,
            'description': v.description,
            'date': v.created_at.isoformat(),
            'is_production': v.is_production
        } for v in versions])
    
    data = request.json
    repo = get_repo(REPO_PATH)
    new_tag = repo.create_tag(data['version'], message=data['description'])
    version = Version(
        version_number=data['version'],
        description=data['description'],
        git_tag=new_tag.name,
        commit_sha=new_tag.commit.hexsha
    )
    db.session.add(version)
    db.session.commit()
    return jsonify({"status": "Version created"}), 201

@app.route('/admin/versions/<int:vid>/deploy', methods=['POST'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def deploy_version(vid):
    version = Version.query.get(vid)
    Version.query.update({'is_production': False})
    version.is_production = True
    db.session.commit()
    
    # Reset to this version in production
    subprocess.run(['git', 'reset', '--hard', version.git_tag], cwd=REPO_PATH)
    return jsonify({"status": f"Version {version.version_number} deployed"})

@app.route('/admin/commits', methods=['GET'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def get_commits():
    repo = get_repo(REPO_PATH)
    branch = request.args.get('branch', 'master')
    limit = request.args.get('limit', default=None, type=int)
    
    # Handle invalid limit values
    if limit is not None and limit < 0:
        return jsonify({"error": "Limit must be non-negative"}), 400

    try:
        # First try to get commits normally
        if limit is not None:
            commit_generator = repo.iter_commits(branch, max_count=limit)
        else:
            commit_generator = repo.iter_commits(branch)
            
    except GitCommandError as e:
        if "bad revision" in str(e).lower():
            # Branch doesn't exist locally - fetch from remote
            try:
                repo.remotes.origin.fetch()
                # Retry with the same branch after fetching
                if limit is not None:
                    commit_generator = repo.iter_commits(branch, max_count=limit)
                else:
                    commit_generator = repo.iter_commits(branch)
            except GitCommandError as fetch_error:
                # Handle case where branch doesn't exist even after fetch
                if "bad revision" in str(fetch_error).lower():
                    return jsonify({"error": f"Revision/branch '{branch}' not found"}), 404
                # Handle other fetch errors
                app.logger.error(f"Git fetch error: {str(fetch_error)}")
                return jsonify({"error": "Error fetching from remote repository"}), 500
        else:
            # Handle other Git errors
            app.logger.error(f"Git command error: {str(e)}")
            return jsonify({"error": "Error accessing repository"}), 500

    commits = []
    for commit in commit_generator:
        commits.append({
            "sha": commit.hexsha[:7],
            "full_sha": commit.hexsha,
            "author": commit.author.name,
            "date": commit.authored_datetime.isoformat(),
            "message": commit.message
        })
    return jsonify(commits)

@app.route('/admin/commits/revert', methods=['POST'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def revert_commit():
    data = request.json
    headers = {
        "Authorization": f"token {app.config['GITHUB_PERSONAL_ACCESS_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/commits/{data['sha']}/revert"
    response = requests.post(url, headers=headers, json={"maintainer_can_modify": True})
    return jsonify(response.json()), response.status_code

@app.route('/admin/pull-requests', methods=['GET'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def pull_requests():
    headers = {
        "Authorization": f"token {app.config['GITHUB_PERSONAL_ACCESS_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls?state=all"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())

@app.route('/admin/pull-requests/create', methods=['POST'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def create_pr():
    data = request.json
    headers = {
        "Authorization": f"token {app.config['GITHUB_PERSONAL_ACCESS_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls"
    payload = {
        "title": data['title'],
        "head": data['head'],
        "base": data['base'],
        "body": data.get('body', '')
    }
    response = requests.post(url, headers=headers, json=payload)
    return jsonify(response.json()), response.status_code

@app.route('/admin/pull-requests/<int:pr_number>/merge', methods=['POST'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def merge_pr(pr_number):
    headers = {
        "Authorization": f"token {app.config['GITHUB_PERSONAL_ACCESS_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls/{pr_number}/merge"
    response = requests.put(url, headers=headers)
    return jsonify(response.json()), response.status_code


# Additional backend endpoints
@app.route('/admin/versions/<int:version_id>', methods=['DELETE'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def delete_version(version_id):
    version = Version.query.get(version_id)
    if not version:
        return jsonify({"error": "Version not found"}), 404
        
    # Delete git tag
    try:
        repo = get_repo(REPO_PATH)
        repo.delete_tag(version.git_tag)
    except Exception as e:
        app.logger.error(f"Error deleting tag: {str(e)}")
    
    db.session.delete(version)
    db.session.commit()
    return jsonify({"status": "Version deleted"})

@app.route('/admin/pull-requests/<int:pr_number>/close', methods=['POST'])
@require_pythonanywhere_domain
@require_session_key
@require_admin
def close_pr(pr_number):
    headers = {
        "Authorization": f"token {app.config['GITHUB_PERSONAL_ACCESS_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/pulls/{pr_number}"
    response = requests.patch(url, headers=headers, json={"state": "closed"})
    return jsonify(response.json()), response.status_code


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
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_ip = user_ip.split(',')[0].strip()  # first IP in the list

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
# Replace the body of create_user_from_signup_session with this version
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
            "Thank you for creating an account on Future Notes! Need some help? Visit our help centre by clicking on this notification",
            "/help"
        )

        # after commit and ip_record saved
        _redeem_referral_for_user(user, signup_session)

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
    """Finalize verification from link click and set auth cookies, then redirect."""
    code = request.args.get('code')
    if not code:
        return "Missing verification code", 400

    signup_session = SignupSession.query.filter_by(
        verification_code=code
    ).first()

    if not signup_session:
        return "Invalid verification code", 400

    # Keep complete_signup_internal unchanged; it returns a dict with session_key, lasting_key, user_id
    result = complete_signup_internal(signup_session)

    # Defensive: ensure we got the expected shape (keep previous error bubbling behavior otherwise)
    if not isinstance(result, dict) or "session_key" not in result or "lasting_key" not in result or "user_id" not in result:
        current_app.logger.error("complete_signup_internal returned unexpected result")
        return "Signup failed", 500

    session_key = result["session_key"]
    lasting_key = result["lasting_key"]
    user_id = result["user_id"]

    # Build redirect response and set cookies (do NOT return plaintext body)
    resp = make_response(redirect(url_for('index')))  # redirect to /index

    # Security flags (tweak for local dev if needed via config)
    secure_flag = current_app.config.get("SESSION_COOKIE_SECURE", True)

    # Cookie lifetimes (seconds) — adjust if you have app-level policy
    session_max_age = current_app.config.get("SESSION_COOKIE_MAX_AGE", 60 * 60 * 24)        # default 1 day
    lasting_max_age  = current_app.config.get("LASTING_KEY_MAX_AGE", 60 * 60 * 24 * 30)    # default 30 days

    # Write cookies: HttpOnly so JS cannot read sensitive tokens
    resp.set_cookie(
        "session_key",
        session_key,
        max_age=session_max_age,
        httponly=True,
        secure=secure_flag,
        samesite="Lax",
        path="/"
    )
    resp.set_cookie(
        "lasting_key",
        lasting_key,
        max_age=lasting_max_age,
        httponly=True,
        secure=secure_flag,
        samesite="Lax",
        path="/"
    )
    # user_id is non-sensitive enough, but keep HttpOnly unless frontend needs it accessible
    resp.set_cookie(
        "user_id",
        str(user_id),
        max_age=lasting_max_age,
        httponly=True,
        secure=secure_flag,
        samesite="Lax",
        path="/"
    )

    return resp

# Shared signup completion logic
def complete_signup_internal(signup_session):
    """Shared signup completion logic"""
    try:
        # Create user
        skip_email = False if signup_session.email else True
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
        initialize_user_storage(user.id)

        # Send welcome notification
        send_notification(
            user.id, "Welcome!",
            "Thank you for creating an account on Future Notes! Click for a quick guide.",
            "/guide_page"
        )

        _redeem_referral_for_user(user.id, signup_session)

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
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_ip = user_ip.split(',')[0].strip()  # first IP in the list
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

    # 1) lasting_key auto-login
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

        # Check 2FA requirement
        user_has_2fa = bool(user.twofa_enabled)
        new_ip = False
        if user_has_2fa and REQUIRE_2FA_ON_NEW_IP:
            user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
            if not IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first():
                new_ip = True

        if user_has_2fa and (REQUIRE_2FA_ALWAYS or new_ip):
            login_token = secrets.token_urlsafe(32)
            login_tokens[login_token] = {
                "user_id": user.id,
                "expires_at": datetime.now() + timedelta(minutes=5),
                "ip": request.headers.get('X-Forwarded-For', request.remote_addr)
            }
            login_2fa_attempts[login_token] = 0

            resp = make_response(jsonify({
                "2fa_required": True,
                "message": "2FA required"
            }), 200)
            resp.set_cookie(
                "pending_login_token", login_token,
                httponly=False,
                secure=not _is_local_request(),
                samesite="Strict",
                max_age=60*5
            )
            return resp

        # No 2FA required → issue session_key
        session_key = generate_session_key(user.id)

        # log IP if new
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        if not IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first():
            db.session.add(IpAddres(user_id=user.id, ip=user_ip))
            db.session.commit()

        payload = {
            "message": "Login successful!",
            "session_key": session_key,
            "user_id": user.id,
            "lasting_key": user.lasting_key,
            "startpage": user.startpage
        }
        resp = make_response(jsonify(payload), 200)
        resp.set_cookie(
            "session_key", session_key,
            httponly=True,
            secure=not _is_local_request(),
            samesite="Strict",
            max_age=60*60*24
        )
        resp.set_cookie(
            "lasting_key", user.lasting_key,
            httponly=True,
            secure=not _is_local_request(),
            samesite="Strict",
            max_age=60*60*24*30
        )
        return resp

    # 2) username/password login
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 400
    if user.suspended:
        return jsonify({"error": "Account is suspended"}), 403

    # 2FA check
    user_has_2fa = bool(user.twofa_enabled)
    new_ip = False
    if user_has_2fa and REQUIRE_2FA_ON_NEW_IP:
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        if not IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first():
            new_ip = True

    if user_has_2fa and (REQUIRE_2FA_ALWAYS or new_ip):
        login_token = secrets.token_urlsafe(32)
        login_tokens[login_token] = {
            "user_id": user.id,
            "expires_at": datetime.now() + timedelta(minutes=5),
            "ip": request.headers.get('X-Forwarded-For', request.remote_addr)
        }
        login_2fa_attempts[login_token] = 0
        return jsonify({
            "2fa_required": True,
            "login_token": login_token,
            "message": "2FA code required"
        }), 200

    # Issue session
    session_key = generate_session_key(user.id)
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if not IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first():
        db.session.add(IpAddres(user_id=user.id, ip=user_ip))
        db.session.commit()

    payload = {
        "message": "Login successful!",
        "session_key": session_key,
        "user_id": user.id,
        "startpage": user.startpage
    }

    # Lasting key if requested
    if data.get('keep_login'):
        if not user.lasting_key:
            user.lasting_key = secrets.token_hex(32)
            db.session.commit()
        payload["lasting_key"] = user.lasting_key

    resp = make_response(jsonify(payload), 200)
    resp.set_cookie(
        "session_key", session_key,
        httponly=True,
        secure=not _is_local_request(),
        samesite="Strict",
        max_age=60*60*24
    )
    if data.get('keep_login'):
        resp.set_cookie(
            "lasting_key", user.lasting_key,
            httponly=True,
            secure=not _is_local_request(),
            samesite="Strict",
            max_age=60*60*24*30
        )
    return resp

@app.route('/2fa/setup', methods=['POST'])
@require_session_key
def twofa_setup():
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    if user.twofa_enabled:
        return jsonify({"error": "2FA already enabled"}), 400

    # generate a secret
    secret = pyotp.random_base32()  # keep server-side until confirm
    # store temporarily
    pending_twofa[user.id] = {"secret": secret, "created_at": datetime.now()}

    issuer = f"Future Notes"
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=f"{issuer}:{user.username}", issuer_name=issuer
    )
    qr_data_uri = make_qr_data_uri(provisioning_uri)

    return jsonify({
        "qr": qr_data_uri,
        "secret": secret  # optional: user can copy-paste into authenticator
    }), 200

@app.route('/2fa/confirm', methods=['POST'])
@require_session_key
def twofa_confirm():
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json() or {}
    code = (data.get('code') or "").strip()
    tmp = pending_twofa.get(user.id)
    if not tmp:
        return jsonify({"error": "No pending 2FA setup"}), 400

    secret = tmp['secret']
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid 2FA code"}), 400

    # enable and persist encrypted secret
    user.twofa_enabled = True
    user.twofa_secret = encrypt_secret(secret)
    # optionally generate backup codes (store hashed)
    backup_codes = []
    for _ in range(8):
        code_plain = secrets.token_hex(5)
        backup_codes.append(code_plain)
    # store hashed backup codes in DB (sha256 or bcrypt)
    import hashlib
    hashed = [hashlib.sha256(c.encode()).hexdigest() for c in backup_codes]
    user.backup_codes_hash = ",".join(hashed)
    db.session.commit()

    # cleanup
    pending_twofa.pop(user.id, None)

    return jsonify({
        "message": "2FA enabled",
        "backup_codes": backup_codes  # show once to the user
    }), 200

@app.route('/2fa/disable', methods=['POST'])
@require_session_key
def twofa_disable():
    """
    Disable 2FA for the currently authenticated user.
    Body JSON: { "password": "<password>" } OR { "code": "<TOTP or backup code>" }
    """
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    password = data.get('password')
    code = data.get('code')

    if not password and not code:
        return jsonify({"error": "Provide password or 2FA code to disable 2FA"}), 400

    ok, used_backup, reason = _verify_password_or_2fa(user, password=password, code=code)
    if not ok:
        return jsonify({"error": "Authentication failed"}), 400

    # Disable 2FA fields
    user.twofa_enabled = False
    user.twofa_secret = None
    user.backup_codes_hash = None
    db.session.commit()

    # Invalidate other sessions for this user (keep current session)
    current_key = request.cookies.get('session_key')
    for sk in list(session_keys.keys()):
        meta = session_keys.get(sk)
        if meta and meta.get('user_id') == user.id and sk != current_key:
            session_keys.pop(sk, None)

    # Optional: inform client to refresh cookies (we do NOT delete current session cookie here)
    resp = make_response(jsonify({"message": "2FA disabled"}), 200)
    # If you prefer to fully sign out everywhere, delete cookies instead:
    # resp.delete_cookie('session_key'); resp.delete_cookie('lasting_key')

    # TODO: write an audit log entry here (user.id, ip, timestamp, reason)
    return resp

@app.route('/2fa/backup/regenerate', methods=['POST'])
@require_session_key
def twofa_backup_regenerate():
    """
    Regenerate backup codes for the current user (returns plaintext codes once).
    Body JSON: { "password": "<password>" } OR { "code": "<TOTP or backup code>" }
    Requires that 2FA is currently enabled for the user.
    """
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    if not user.twofa_enabled:
        return jsonify({"error": "Two-factor authentication is not enabled"}), 400

    data = request.get_json(silent=True) or {}
    password = data.get('password')
    code = data.get('code')

    if not password and not code:
        return jsonify({"error": "Provide password or 2FA code to confirm"}), 400

    ok, used_backup, reason = _verify_password_or_2fa(user, password=password, code=code)
    if not ok:
        return jsonify({"error": "Authentication failed"}), 400

    # Generate new backup codes (plaintext for user, store only hashed)
    new_plain = []
    new_hashed = []
    for _ in range(8):
        p = secrets.token_urlsafe(9)  # ~12 chars, URL-safe; you can change format
        new_plain.append(p)
        new_hashed.append(hashlib.sha256(p.encode()).hexdigest())

    user.backup_codes_hash = ','.join(new_hashed)
    db.session.commit()

    # TODO: log the regeneration event (audit)
    return jsonify({"backup_codes": new_plain}), 200

@app.route('/login/2fa', methods=['POST'])
def login_2fa():
    data = request.get_json() or {}
    token = data.get('login_token')
    code = (data.get('code') or "").strip()
    keep_login = bool(data.get('keep_login'))

    if not token or not code:
        return jsonify({"error": "Missing token or code"}), 400

    tmeta = login_tokens.get(token)
    if not tmeta or tmeta['expires_at'] < datetime.now():
        login_tokens.pop(token, None)
        return jsonify({"error": "Invalid or expired login token"}), 400

    user = User.query.get(tmeta['user_id'])
    if not user:
        return jsonify({"error": "Invalid token"}), 400

    # rate limiting attempts
    attempts = login_2fa_attempts.get(token, 0)
    if attempts >= 5:
        login_tokens.pop(token, None)
        login_2fa_attempts.pop(token, None)
        return jsonify({"error": "Too many attempts"}), 429

    # verify TOTP or backup codes
    secret = decrypt_secret(user.twofa_secret) if user.twofa_secret else None
    verified = False
    if secret:
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            verified = True

    # fallback: check backup codes (hashed)
    if not verified and user.backup_codes_hash:
        import hashlib
        hashed_codes = user.backup_codes_hash.split(",")
        if hashlib.sha256(code.encode()).hexdigest() in hashed_codes:
            verified = True
            # remove used code from DB
            hashed_codes.remove(hashlib.sha256(code.encode()).hexdigest())
            user.backup_codes_hash = ",".join(hashed_codes) if hashed_codes else None
            db.session.commit()

    if not verified:
        login_2fa_attempts[token] = attempts + 1
        return jsonify({"error": "Invalid 2FA code"}), 400

    # Verified: issue session_key and optionally lasting_key and persist IP
    session_key = generate_session_key(user.id)

    # persist IP
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if not IpAddres.query.filter_by(user_id=user.id, ip=user_ip).first():
        db.session.add(IpAddres(user_id=user.id, ip=user_ip))
        db.session.commit()

    payload = {
        "message": "Login successful!",
        "session_key": session_key,
        "user_id": user.id,
        "startpage": user.startpage
    }
    resp = make_response(jsonify(payload), 200)
    resp.set_cookie("session_key", session_key, httponly=True, secure=not _is_local_request(), samesite="Strict", max_age=60*60*24)
    if keep_login:
        if not user.lasting_key:
            user.lasting_key = secrets.token_hex(32)
            db.session.commit()
        resp.set_cookie("lasting_key", user.lasting_key, httponly=True, secure=not _is_local_request(), samesite="Strict", max_age=60*60*24*30)
        payload["lasting_key"] = user.lasting_key

    # cleanup
    login_tokens.pop(token, None)
    login_2fa_attempts.pop(token, None)

    return resp

# GET /2fa/status
@app.route('/2fa/status', methods=['GET'])
@require_session_key
def twofa_status():
    """
    Returns simple information about the current user's 2FA state.

    Response (200):
    {
      "twofa_enabled": bool,
      "has_backup_codes": bool,
      "recent_auth": bool
    }

    401 if not authenticated.
    """
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    # Optionally enforce a "recent authentication" check.
    # This helps the UI decide whether to ask for password/2FA before performing
    # sensitive actions (e.g. disable/regenerate).
    # Adjust window as needed (minutes).
    RECENT_AUTH_WINDOW_MINUTES = 15

    recent = False
    session_key = request.cookies.get("session_key")
    if session_key:
        meta = session_keys.get(session_key)
        if meta:
            last_active = meta.get("last_active")
            # last_active expected to be a datetime object; be defensive
            if isinstance(last_active, datetime):
                if datetime.now() - last_active < timedelta(minutes=RECENT_AUTH_WINDOW_MINUTES):
                    recent = True

    payload = {
        "twofa_enabled": bool(user.twofa_enabled),
        "has_backup_codes": bool(user.backup_codes_hash),
        "recent_auth": recent
    }

    resp = make_response(jsonify(payload), 200)
    # Sensitive info — do not cache in intermediaries or client
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
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

# --- POST and GET /notes ---
@app.route('/notes', methods=['GET', 'POST'])
@require_session_key
def manage_notes():
    if request.method == 'POST':
        data = request.json
        note_html = sanitize_html(data['note'])
        folder_id = data.get('folder_id')

        # Validate folder
        if folder_id:
            folder = Folder.query.filter_by(id=folder_id, user_id=g.user_id).first()
            if not folder:
                return jsonify({"error": "Folder not found or access denied"}), 400

        # Handle attachments
        attachments = data.get('attachments') or []
        valid_attachments = []
        for uid in attachments:
            up = Upload.query.get(uid)
            if not up or up.user_id != g.user_id or up.deleted:
                return jsonify({"error": f"Invalid attachment id: {uid}"}), 400
            valid_attachments.append(up.id)

        # Create note
        new_note = Note(
            user_id=g.user_id,
            title=data.get('title'),
            note=note_html,
            tag=data.get('tag'),
            folder_id=folder_id
        )
        db.session.add(new_note)
        db.session.commit()

        # Attach uploads
        for uid in valid_attachments:
            db.session.add(NoteUpload(note_id=new_note.id, upload_id=uid))
        db.session.commit()

        # Propagate shares from ancestor folders
        if folder_id:
            parent_folder = Folder.query.get(folder_id)
            while parent_folder:
                for share in parent_folder.shares:
                    db.session.add(Share(
                        token=share.token,
                        note_id=new_note.id,
                        folder_id=None,
                        user_id=g.user_id,
                        expires_at=share.expires_at
                    ))
                parent_folder = Folder.query.get(parent_folder.parent_id) if parent_folder.parent_id else None
            db.session.commit()

        # --- Create initial note version ---
        try:
            create_note_version(new_note, editor_id=g.user_id)
        except Exception:
            current_app.logger.exception(f"Failed to create version for note {new_note.id}")

        return jsonify({"message": "Note added successfully!"}), 201

    else:
        # GET notes
        folder_id = request.args.get('folder_id', type=int)
        query = Note.query.filter_by(user_id=g.user_id)
        query = query.filter_by(folder_id=folder_id) if folder_id else query.filter_by(folder_id=None)

        notes = query.order_by(Note.pinned.desc(), Note.id.desc()).all()
        sanitized_notes = []
        for note in notes:
            attachments = []
            for nu in NoteUpload.query.filter_by(note_id=note.id).all():
                up = Upload.query.get(nu.upload_id)
                if up and not up.deleted:
                    attachments.append({
                        "upload_id": up.id,
                        "filename": up.original_filename,
                        "size_bytes": up.size_bytes,
                        "mimetype": up.mimetype
                    })
            sanitized_notes.append({
                "id": note.id,
                "title": note.title,
                "note": note.note,
                "tag": note.tag,
                "folder_id": note.folder_id,
                "attachments": attachments
            })
        return jsonify(sanitized_notes)
    
@app.route("/search_notes", methods=["GET"])
@require_session_key
def search_notes():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])

    # Wrap query for SQL LIKE matching
    like_query = f"%{query}%"

    # Search notes for the current user
    results = Note.query.filter(
        Note.user_id == g.user_id,
        or_(
            Note.title.ilike(like_query),
            Note.note.ilike(like_query),
            Note.tag.ilike(like_query)
        )
    ).limit(50).all()  # Limit for efficiency

    # Convert to dict
    return jsonify([
        {
            "id": note.id,
            "title": note.title,
            "tag": note.tag,
            "folder_id": note.folder_id
        } for note in results
    ])

@app.route("/toggle_pin", methods=["POST"])
@require_session_key
def toggle_pin():
    """
    Toggle the pinned state of either a folder or a note.
    Expects JSON payload:
    {
        "folder_id": <int|null>,
        "note_id": <int|null>
    }
    Only one of folder_id or note_id should be non-null.
    """
    data = request.get_json() or {}
    folder_id = data.get("folder_id")
    note_id = data.get("note_id")

    if not folder_id and not note_id:
        return jsonify({"error": "Missing folder_id or note_id"}), 400

    # Handle folder toggle
    if folder_id:
        folder = Folder.query.filter_by(id=folder_id, user_id=g.user_id).first()
        if not folder:
            return jsonify({"error": "Folder not found"}), 404
        folder.pinned = not folder.pinned
        db.session.commit()
        return jsonify(folder.to_dict()), 200

    # Handle note toggle
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=g.user_id).first()
        if not note:
            return jsonify({"error": "Note not found"}), 404
        note.pinned = not note.pinned
        db.session.commit()
        return jsonify(note.to_dict()), 200

# --- PUT and DELETE /notes/<id> ---
@app.route('/notes/<int:note_id>', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_note(note_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != g.user_id:
        return jsonify({"error": "Note not found"}), 404

    def current_attachment_ids(note_id):
        return {nu.upload_id for nu in NoteUpload.query.filter_by(note_id=note_id).all()}

    if request.method == 'PUT':
        data = request.json

        if 'title' in data:
            note.title = data.get('title')
        if 'note' in data:
            note.note = sanitize_html(data.get('note', note.note))
        if 'tag' in data:
            note.tag = data.get('tag')
        if 'folder_id' in data:
            folder_id = data.get('folder_id')
            if folder_id is not None:
                folder = Folder.query.filter_by(id=folder_id, user_id=g.user_id).first()
                if not folder:
                    return jsonify({"error": "Folder not found or access denied"}), 400
                note.folder_id = folder_id
            else:
                note.folder_id = None

        if 'attachments' in data:
            requested_attachments = set(data.get('attachments') or [])
            existing_attachments = current_attachment_ids(note.id)

            to_add = requested_attachments - existing_attachments
            to_remove = existing_attachments - requested_attachments

            for uid in list(to_add):
                up = Upload.query.get(uid)
                if not up or up.user_id != g.user_id or up.deleted:
                    return jsonify({"error": f"Invalid attachment to add: {uid}"}), 400

            try:
                for uid in to_add:
                    db.session.add(NoteUpload(note_id=note.id, upload_id=uid))
                for uid in to_remove:
                    NoteUpload.query.filter_by(note_id=note.id, upload_id=uid).delete()

                db.session.commit()
            except Exception:
                db.session.rollback()
                return jsonify({"error": "Database error on updating note attachments."}), 500

            for uid in to_remove:
                try:
                    remove_upload_if_orphan(uid)
                except Exception:
                    pass

        # --- Create version after update ---
        try:
            create_note_version(note, editor_id=g.user_id)
        except Exception:
            current_app.logger.exception(f"Failed to create version for note {note.id}")

        return jsonify({"message": "Note updated successfully!"}), 200

    elif request.method == 'DELETE':
        delete_shares(note.id)
        delete_version_history(note.id)
        existing_attachments = current_attachment_ids(note.id)
        try:
            NoteUpload.query.filter_by(note_id=note.id).delete()
            db.session.delete(note)
            db.session.commit()
        except Exception as e:
            current_app.logger.exception(e)
            db.session.rollback()
            return jsonify({"error": "Database error on deleting note."}), 500

        for uid in existing_attachments:
            try:
                remove_upload_if_orphan(uid)
            except Exception:
                pass

        return jsonify({"message": "Note deleted successfully."}), 200

@app.route('/notes/<int:note_id>/versions', methods=['GET'])
@require_session_key
def list_note_versions(note_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != g.user_id:
        return jsonify({"error": "Note not found"}), 404

    # Check if there are existing versions for the note
    versions = NoteVersion.query.filter_by(note_id=note.id).order_by(NoteVersion.version_number.asc()).all()
    if not versions:
        # If no versions exist, create the first version with the current content of the note
        try:
            create_note_version(note, editor_id=g.user_id)
            versions = NoteVersion.query.filter_by(note_id=note.id).order_by(NoteVersion.version_number.asc()).all()
        except Exception as e:
            current_app.logger.exception("Failed to create initial version for note")
            return jsonify({"error": "Failed to create initial version"}), 500

    result = []
    prev = None
    for v in versions:
        uploads = []
        for vu in v.uploads:
            present = False
            up = None
            if vu.upload_id:
                up = Upload.query.get(vu.upload_id)
                present = (up is not None and not getattr(up, "deleted", False))
            uploads.append({
                "version_upload_id": vu.id,
                "upload_id": vu.upload_id,
                "filename": vu.filename,
                "size": vu.size,
                "mime_type": vu.mime_type,
                "upload_deleted_at_snapshot": bool(vu.upload_deleted),
                "present_now": present
            })

        # Compute field-level changes compared to the previous version
        changes = []
        if prev:
            # Compare fields to detect changes
            if (prev.title or "") != (v.title or ""):
                changes.append({"field": "title", "from": prev.title, "to": v.title})
            if (prev.tag or "") != (v.tag or ""):
                changes.append({"field": "tag", "from": prev.tag, "to": v.tag})
            if (prev.folder_id) != (v.folder_id):
                changes.append({"field": "folder_id", "from": prev.folder_id, "to": v.folder_id})
            if bool(prev.pinned) != bool(v.pinned):
                changes.append({"field": "pinned", "from": bool(prev.pinned), "to": bool(v.pinned)})

            # Compare attachments
            prev_uploads = [(x.upload_id, x.filename) for x in prev.uploads]
            cur_uploads = [(x.upload_id, x.filename) for x in v.uploads]
            if prev_uploads != cur_uploads:
                changes.append({"field": "attachments", "from": prev_uploads, "to": cur_uploads})

            # Compute note content diff
            prev_text = _strip_html_tags(prev.note)
            cur_text = _strip_html_tags(v.note)
            if prev_text != cur_text:
                ud = '\n'.join(difflib.unified_diff(
                    prev_text.splitlines(), cur_text.splitlines(),
                    fromfile=f"v{prev.version_number}", tofile=f"v{v.version_number}",
                    lineterm=''
                ))
                if len(ud) > 4000:
                    ud = ud[:4000] + "\n... (truncated)\n"
            else:
                ud = ""
        else:
            # First version — everything is 'from' None
            changes = []
            if v.title:
                changes.append({"field": "title", "from": None, "to": v.title})
            if v.tag:
                changes.append({"field": "tag", "from": None, "to": v.tag})
            if v.folder_id:
                changes.append({"field": "folder_id", "from": None, "to": v.folder_id})
            if v.pinned:
                changes.append({"field": "pinned", "from": None, "to": bool(v.pinned)})
            ud = _strip_html_tags(v.note)  # Include note text as 'diff' for the first version

        result.append({
            "version_id": v.id,
            "version_number": v.version_number,
            "created_at": v.created_at.isoformat(),
            "editor_id": v.editor_id,
            "title": v.title,
            "note": v.note,
            "tag": v.tag,
            "folder_id": v.folder_id,
            "pinned": v.pinned,
            "uploads": uploads,
            "changes": changes,        # Field-level changes from previous version
            "note_diff": ud           # Unified diff (plain text) or note text for first version
        })
        prev = v

    # Return in descending order (most recent first)
    result.reverse()
    return jsonify(result), 200

@app.route('/notes/<int:note_id>/versions/<int:version_id>/restore', methods=['POST'])
@require_session_key
def restore_note_version(note_id, version_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != g.user_id:
        return jsonify({"error": "Note not found"}), 404

    def current_attachment_ids(note_id):
        return {nu.upload_id for nu in NoteUpload.query.filter_by(note_id=note_id).all()}

    v = NoteVersion.query.filter_by(id=version_id, note_id=note.id).first()
    if not v:
        return jsonify({"error": "Version not found"}), 404

    content_only = request.args.get('content_only', 'false').lower() == 'true'

    # check uploads
    missing = []
    version_upload_ids = []
    for vu in v.uploads:
        version_upload_ids.append(vu.upload_id)
        if vu.upload_id is not None:
            up = Upload.query.get(vu.upload_id)
            if not up or up.deleted or up.user_id != g.user_id:
                missing.append({
                    "upload_id": vu.upload_id,
                    "filename": vu.filename
                })

    if missing and not content_only:
        return jsonify({
            "error": "Some files referenced by this version are missing or deleted. Cannot restore attachments.",
            "missing_files": missing
        }), 400

    # proceed to restore note fields
    try:
        note.title = v.title
        note.note = v.note
        note.tag = v.tag
        note.folder_id = v.folder_id
        note.pinned = v.pinned

        # handle attachments: if content_only we skip attachments; else replace attachments to match version
        if not content_only:
            requested_attachments = set([uid for uid in version_upload_ids if uid is not None])
            existing_attachments = current_attachment_ids(note.id)

            to_add = requested_attachments - existing_attachments
            to_remove = existing_attachments - requested_attachments

            for uid in list(to_add):
                up = Upload.query.get(uid)
                if not up or up.user_id != g.user_id or up.deleted:
                    raise ValueError(f"Invalid attachment to add during restore: {uid}")
                db.session.add(NoteUpload(note_id=note.id, upload_id=uid))

            for uid in to_remove:
                NoteUpload.query.filter_by(note_id=note.id, upload_id=uid).delete()

        db.session.commit()
        # create a new version for this restore operation
        create_note_version(note, editor_id=g.user_id)
        return jsonify({"message": "Note restored from version"}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception(e)
        return jsonify({"error": "Database error on restoring version."}), 500

    
@app.route('/folders', methods=['GET', 'POST'])
@require_session_key
def manage_folders():
    if request.method == 'POST':
        data = request.json
        name = data.get('name')
        parent_id = data.get('parent_id')

        if not name:
            return jsonify({"error": "Folder name is required"}), 400

        # Validate parent folder
        if parent_id:
            parent = Folder.query.filter_by(id=parent_id, user_id=g.user_id).first()
            if not parent:
                return jsonify({"error": "Parent folder not found or access denied"}), 400

        # Create folder
        new_folder = Folder(user_id=g.user_id, name=name, parent_id=parent_id)
        db.session.add(new_folder)
        db.session.commit()

        # Propagate shares from ancestor folders
        if parent_id:
            parent_folder = Folder.query.get(parent_id)
            while parent_folder:
                for share in parent_folder.shares:
                    db.session.add(Share(
                        token=share.token,
                        note_id=None,
                        folder_id=new_folder.id,
                        user_id=g.user_id,
                        expires_at=share.expires_at
                    ))
                parent_folder = Folder.query.get(parent_folder.parent_id) if parent_folder.parent_id else None
            db.session.commit()

        return jsonify({"message": "Folder created successfully!", "folder": new_folder.to_dict()}), 201

    else:
        # GET folders (unchanged)
        parent_id = request.args.get("parent_id", type=int)
        query = Folder.query.filter_by(user_id=g.user_id)
        query = query.filter(Folder.parent_id == parent_id) if parent_id is not None else query.filter(Folder.parent_id == None)
        folders = query.order_by(Folder.pinned.desc(), Folder.id.desc()).all()
        return jsonify([folder.to_dict() for folder in folders])

@app.route('/folders/<int:folder_id>/parents', methods=['GET'])
@require_session_key
def get_parent_folders(folder_id):
    folder = Folder.query.filter_by(id=folder_id, user_id=g.user_id).first()
    if not folder:
        return jsonify({"error": "Folder not found"}), 404

    # Build chain from current folder upwards
    chain = []
    while folder:
        chain.append(folder.to_dict())
        if not folder.parent_id:
            break
        folder = Folder.query.filter_by(id=folder.parent_id, user_id=g.user_id).first()
    
    # Reverse so it goes Root → … → Current
    return jsonify(chain[::-1]), 200

@app.route('/folders/<int:folder_id>', methods=['PUT', 'DELETE'])
@require_session_key
def update_delete_folder(folder_id):
    folder = Folder.query.filter_by(id=folder_id, user_id=g.user_id).first()
    if not folder:
        return jsonify({"error": "Folder not found"}), 404

    if request.method == 'PUT':
        data = request.json
        name = data.get('name')
        parent_id = data.get('parent_id')
        
        if name:
            folder.name = name
            
        if parent_id:
            # Prevent circular references
            if parent_id == folder_id:
                return jsonify({"error": "Cannot set folder as its own parent"}), 400
                
            parent = Folder.query.filter_by(id=parent_id, user_id=g.user_id).first()
            if not parent:
                return jsonify({"error": "Parent folder not found or access denied"}), 400
            folder.parent_id = parent_id
        else:
            folder.parent_id = None

        db.session.commit()
        return jsonify({"message": "Folder updated successfully!", "folder": folder.to_dict()}), 200

    elif request.method == 'DELETE':
        # Ensure g.user is populated for delete_upload calls
        if not hasattr(g, 'user'):
            g.user = User.query.get(g.user_id)

        action = request.args.get('action')  # possible values: None, "move_up", "delete_all"

        # Collect all folder ids under this folder (including itself)
        all_folder_ids = collect_all_folder_ids(folder)
        # Collect all notes in those folders
        notes = collect_note_ids_in_folders(all_folder_ids)

        # If no action specified, return summary for frontend decision
        if not action:
            has_subfolders = len(all_folder_ids) > 1
            notes_count = len(notes)
            if not has_subfolders and notes_count == 0:
                # completely empty folder - can delete directly
                return jsonify({
                    "can_delete_direct": True,
                    "message": "Folder is empty and can be deleted immediately."
                }), 200

            if notes_count == 0:
                # has subfolders but none of them contain notes -> can safely delete the entire subtree
                return jsonify({
                    "can_delete_empty_stack": True,
                    "message": "Folder and subfolders contain no notes and can be deleted."
                }), 200

            # notes exist somewhere in subtree -> require user decision
            return jsonify({
                "requires_confirmation": True,
                "notes_count": notes_count,
                "folders_count": len(all_folder_ids),
                "message": "Folder subtree contains notes. Choose action: move_up or delete_all."
            }), 200

        # If action is provided, perform it
        if action == "move_up":
            try:
                parent_id = folder.parent_id  # may be None

                # Move immediate child folders up one level (their parent becomes folder.parent_id)
                children = Folder.query.filter_by(parent_id=folder.id, user_id=g.user_id).all()
                for c in children:
                    c.parent_id = parent_id

                # Move notes directly inside the folder to parent_id
                direct_notes = Note.query.filter_by(folder_id=folder.id, user_id=g.user_id).all()
                for n in direct_notes:
                    n.folder_id = parent_id  # `None` if parent is root

                # Now delete the folder itself
                db.session.delete(folder)
                db.session.commit()
                return jsonify({"message": "Folder removed and children moved up successfully."}), 200
            except Exception as e:
                app.logger.exception("Error moving children up: %s", e)
                db.session.rollback()
                return jsonify({"error": "Error while moving children up."}), 500

        elif action == "delete_all":
            # delete all notes and attachments in subtree, then delete folders in post-order
            try:
                # 1) delete notes and attachments
                ok, msg = delete_notes_and_attachments(notes, g.user)
                if not ok:
                    return jsonify({"error": msg}), 500

                # 2) delete folders in post-order to avoid FK issues (children first)
                post_order_folders = get_recursive_folder_tree(folder)
                # post_order_folders is a list of Folder objects in order children->parent
                for f in post_order_folders:
                    # double-check f belongs to user
                    if f.user_id != g.user_id:
                        # Shouldn't happen, but guard
                        db.session.rollback()
                        return jsonify({"error": "Permission error while deleting folders."}), 403
                    db.session.delete(f)

                db.session.commit()
                return jsonify({"message": "Folder and all subfolders and notes deleted."}), 200
            except Exception as e:
                app.logger.exception("Error deleting subtree: %s", e)
                db.session.rollback()
                return jsonify({"error": "Server error while deleting subtree."}), 500
        else:
            return jsonify({"error": "Unknown action."}), 400
    
@app.route('/uploads', methods=['POST'])
@require_session_key
def uploads_post():
    # Expecting multipart/form-data with key 'file'
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    # file is a FileStorage instance
    # If you only have g.user_id, load user object:
    if not hasattr(g, 'user'):
        g.user = User.query.get(g.user_id)
    ok, result = verify_and_record_upload(file, g.user)
    if not ok:
        return jsonify({"error": result}), 400

    upload = result
    return jsonify({
        "upload_id": upload.id,
        "filename": upload.original_filename,
        "size_bytes": upload.size_bytes,
        "mimetype": upload.mimetype,
        "created_at": upload.created_at.isoformat()
    }), 201

@app.route('/uploads/<int:upload_id>', methods=['DELETE'])
@require_session_key
def uploads_delete(upload_id):
    user = g.user if hasattr(g, 'user') else User.query.get(g.user_id)
    ok, msg = delete_upload(upload_id, user)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"message": msg}), 200

@app.route('/user/storage', methods=['GET'])
@require_session_key
def get_user_storage():
    user = g.user if hasattr(g, 'user') else User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    raw_quota = get_user_quota_bytes(user)
    unlimited = raw_quota == float('inf')

    # Handle storage_used_bytes (NULL, strings, garbage)
    raw_used = getattr(user, 'storage_used_bytes', None)
    persist_null_to_zero = True

    if raw_used is None:
        used_bytes = 0
        if persist_null_to_zero:
            try:
                user.storage_used_bytes = 0
                db.session.add(user)
                db.session.commit()
            except Exception:
                db.session.rollback()
    else:
        try:
            used_bytes = int(raw_used)
        except (ValueError, TypeError):
            # sanitize: keep digits only
            s = re.sub(r'\D', '', str(raw_used or ''))
            used_bytes = int(s) if s else 0

    # Compute remaining storage
    if unlimited:
        total_bytes = None          # None indicates unlimited
        remaining_bytes = None
    else:
        total_bytes = int(raw_quota)
        remaining_bytes = max(total_bytes - used_bytes, 0)

    # Special message for frontend if unlimited
    response = {
        "total_bytes": total_bytes,
        "used_bytes": used_bytes,
        "remaining_bytes": remaining_bytes,
        "unlimited": unlimited,
        "message": "Unlimited storage" if unlimited else None
    }

    return jsonify(response), 200


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

#AIIIIIIII

@app.route("/api/notes/<int:note_id>/improve", methods=["POST"])
@require_session_key
def improve_note(note_id):
    # load the note regardless of ownership, then enforce access control
    note = Note.query.filter_by(id=note_id).first()
    if not note:
        return jsonify({"error": "Note not found"}), 404

    user_id = g.user_id
    can_access = False

    # direct owner
    if getattr(note, "user_id", None) == user_id:
        can_access = True
    else:
        # group-owned note -> check membership
        group_id = getattr(note, "group_id", None)
        if group_id:
            # Try the most common pattern: GroupMember model with group_id and user_id

            if GroupMember:
                membership = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
                if membership:
                    can_access = True
            else:
                # fallback: maybe Group has owner/admins; check owner as a last-resort convenience
                try:
                    group = Group.query.filter_by(id=group_id).first()
                    if group and getattr(group, "owner_id", None) == user_id:
                        can_access = True
                except Exception:
                    # couldn't check group membership - deny by default
                    can_access = False

    if not can_access:
        return jsonify({"error": "Note not found or you don't have access to it"}), 404

    if len(note.note) > MAX_NOTE_LENGTH:
        return jsonify({"error": f"Note too long (max {MAX_NOTE_LENGTH} characters)"}), 400

    if check("ai_notes_development_return_input", "Nee") == "Ja":
        print("AI Notes Development Mode: returning input as output")
        return jsonify({
            "id": note.id,
            "title": note.title,
            "original": note.note,
            "improved": note.note + " (development mode, no changes made)"
        })

    messages = [
        {
            "role": "system",
            "content": (
                "You are an AI assistant that improves user-submitted HTML notes. "
                "Only return the improved HTML. "
                "Do not include any instructions, explanations, or extra text. "
                "Use only these HTML tags: <p>, <b>, <i>, <u>, <ul>, <ol>, <li>, <h1>, <h2>, <h3>. "
                "Do not use checkboxes or unsupported tags. "
                "You must not use any previous notes or memory; always use only the provided note as input. "
                "If the note contains an existing structure (like headings or lists), preserve and enhance it. "
                "If the note does not contain any structure, add appropriate HTML structure to improve readability. "
                "If the note is very short (e.g., a single sentence), enhance it by adding relevant details or context to make it more informative, but only if you have the necessary context to do so."
            )
        },
        {
            "role": "user",
            "content": note.note
        }
    ]

    try:
        response = co.chat(
            model="command-a-03-2025",
            messages=messages,
            temperature=0.3,
            max_tokens=400
        )

        improved_html = _extract_text_from_cohere_response(response)

        if not improved_html:
            return jsonify({"error": f"Cohere Chat SDK returned empty output", "debug": str(response)}), 500

    except Exception as e:
        return jsonify({"error": f"Cohere request failed: {str(e)}"}), 500

    improved_text = sanitize_html(improved_html)

    return jsonify({
        "id": note.id,
        "title": note.title,
        "original": note.note,
        "improved": improved_text
    })


@app.route("/api/notes/improve-temp", methods=["POST"])
def improve_temp_note():
    data = request.get_json() or {}
    note_html = data.get("note", "")

    if not isinstance(note_html, str) or not note_html.strip():
        return jsonify({"error": "Empty note"}), 400

    if len(note_html) > MAX_NOTE_LENGTH:
        return jsonify({"error": f"Note too long (max {MAX_NOTE_LENGTH} characters)"}), 400
    
    if check("ai_notes_development_return_input", "Nee") == "Ja":
        print("AI Notes Development Mode: returning input as output")
        return jsonify({
            "improved": note_html + " (development mode, no changes made)"
        })

    messages = [
        {
            "role": "system",
            "content": (
                "You are an AI assistant that improves user-submitted HTML notes. "
                "Only return the improved HTML. "
                "Do not include any instructions, explanations, or extra text. "
                "Use only these HTML tags: <p>, <b>, <i>, <u>, <ul>, <ol>, <li>, <h1>, <h2>, <h3>. "
                "Do not use checkboxes or unsupported tags. "
                "You must not use any previous notes or memory; always use only the provided note as input. "
                "If the note contains an existing structure (like headings or lists), preserve and enhance it. "
                "If the note does not contain any structure, add appropriate HTML structure to improve readability. "
                "If the note is very short (e.g., a single sentence), enhance it by adding relevant details or context to make it more informative, but only if you have the necessary context to do so."
            )
        },
        {
            "role": "user",
            "content": note_html
        }
    ]

    try:
        response = co.chat(
            model="command-a-03-2025",
            messages=messages,
            temperature=0.3,
            max_tokens=400
        )

        improved_html = _extract_text_from_cohere_response(response)

        if not improved_html:
            return jsonify({"error": f"Cohere Chat SDK returned empty output", "debug": str(response)}), 500

    except Exception as e:
        return jsonify({"error": f"Cohere request failed: {str(e)}"}), 500

    improved_html = sanitize_html(improved_html)

    return jsonify({"improved": improved_html})

    
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
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        # For form data or query parameters
        data = request.form or request.args
    
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