import os
import datetime as dt
from functools import wraps
from uuid import uuid4

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import ForeignKey

# Load env
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'data.db')}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

API_TOKEN = os.getenv('API_TOKEN', 'changeme-token')
# Support a comma-separated list of allowed API tokens via ALLOWED_API_TOKENS env var.
# This lets you add the mobile app token on the server without changing code.
raw_allowed = os.getenv('ALLOWED_API_TOKENS', '')
ALLOWED_API_TOKENS = set([t.strip() for t in ([API_TOKEN] + raw_allowed.split(',')) if t and t.strip()])

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True, nullable=False)
    imei = db.Column(db.String(64), default='')
    registered_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    last_seen = db.Column(db.DateTime)
    last_lat = db.Column(db.Float)
    last_lng = db.Column(db.Float)
    last_acc = db.Column(db.Float)
    last_sos = db.Column(db.Boolean, default=False)
    sos_cancel_requested = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=True)

class Heartbeat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=dt.datetime.utcnow)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    acc = db.Column(db.Float)
    sos = db.Column(db.Boolean, default=False)

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    camera = db.Column(db.String(16))  # front/back
    path = db.Column(db.String(256))   # relative to static/uploads

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Init DB and default admin
with app.app_context():
    db.create_all()
    if User.query.count() == 0:
        u = User(username='admin', is_admin=True)
        u.set_password(os.getenv('ADMIN_PASSWORD', 'admin'))
        db.session.add(u)
        db.session.commit()

# Token auth decorator
def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Try several places for the token: standard Authorization header,
        # WSGI environ passthroughs, alternate header X-API-Token, query or json/form body.
        auth = request.headers.get('Authorization') or request.environ.get('HTTP_AUTHORIZATION') or ''
        alt_token = None
        # Some proxies strip Authorization; many clients/apps can send X-API-Token instead
        xapi = request.headers.get('X-API-Token') or request.headers.get('X-Api-Token')
        if xapi:
            alt_token = xapi
        # allow token in query string ?api_token=...
        if not alt_token:
            alt_token = request.args.get('api_token')
        # allow token in JSON body or form field 'api_token'
        if not alt_token:
            try:
                data = request.get_json(silent=True) or {}
                alt_token = data.get('api_token') if isinstance(data, dict) else None
            except Exception:
                alt_token = None
        if not alt_token:
            alt_token = request.form.get('api_token') if request.form else None
    parts = auth.split() if auth else []
        # Log header (truncated) for debugging
        try:
            app.logger.debug(f"Authorization header: {auth[:200]}")
        except Exception:
            pass
        # First, allow the mobile app which sends a Bearer token
        token = None
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            token = parts[1]
        # fallback to alternate token locations
        if not token and alt_token:
            token = alt_token
            try:
                app.logger.debug(f"Received token (truncated): {token[:48]}")
            except Exception:
                pass
            if token in ALLOWED_API_TOKENS:
                app.logger.info('Auth: bearer token accepted')
                return f(*args, **kwargs)
        # Fallback: allow a logged-in web session (Flask-Login) so the dashboard
        # can call the same endpoints without requiring changes on the app side.
        # This keeps mobile behavior unchanged and permits browser requests
        # authenticated via session cookies.
        if current_user.is_authenticated:
            try:
                app.logger.info(f"Auth: session accepted for user_id={current_user.get_id()}")
            except Exception:
                app.logger.info("Auth: session accepted")
            return f(*args, **kwargs)
        # Not authenticated by token or session
        app.logger.info('Auth: unauthorized')
        return jsonify({'error': 'Unauthorized'}), 401
    return wrapper

# API endpoints
@app.post('/register_device')
@require_token
def register_device():
    data = request.get_json(silent=True) or {}
    device_id = data.get('device_id')
    imei = data.get('imei', '')
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    d = Device.query.filter_by(device_id=device_id).first()
    if not d:
        d = Device(device_id=device_id, imei=imei)
        db.session.add(d)
    else:
        d.imei = imei or d.imei
    db.session.commit()
    return ('', 204)

# Dashboard action for cancel (no API token; requires login)
@app.post('/dashboard/flag_cancel')
@login_required
def dashboard_flag_cancel():
    device_id = request.form.get('device_id')
    if not device_id:
        flash('device_id required', 'danger')
        return redirect(url_for('dashboard'))
    d = Device.query.filter_by(device_id=device_id).first()
    if not d:
        flash('Device not found', 'danger')
        return redirect(url_for('dashboard'))
    d.sos_cancel_requested = True
    db.session.commit()
    flash('Cancel flag set. Device will stop on next heartbeat.', 'success')
    return redirect(url_for('device_detail', device_id=device_id))

@app.post('/update_heartbeat')
@require_token
def update_heartbeat():
    data = request.get_json(silent=True) or {}
    device_id = data.get('device_id')
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    lat = float(data.get('latitude', 0.0))
    lng = float(data.get('longitude', 0.0))
    acc = float(data.get('accuracy', 0.0))
    ts_ms = int(data.get('timestamp', int(dt.datetime.utcnow().timestamp()*1000)))
    sos = bool(data.get('sos', False))

    hb = Heartbeat(device_id=device_id, lat=lat, lng=lng, acc=acc, sos=sos, timestamp=dt.datetime.fromtimestamp(ts_ms/1000.0))
    db.session.add(hb)

    d = Device.query.filter_by(device_id=device_id).first()
    if not d:
        d = Device(device_id=device_id)
        db.session.add(d)
    d.last_seen = dt.datetime.utcnow()
    d.last_lat = lat
    d.last_lng = lng
    d.last_acc = acc
    d.last_sos = sos
    cancel = d.sos_cancel_requested
    if cancel and not sos:
        # reset cancel flag if device reports not in SOS
        d.sos_cancel_requested = False

    db.session.commit()
    return jsonify({'cancel': bool(cancel)})

@app.post('/upload_snapshot')
@require_token
def upload_snapshot():
    device_id = request.form.get('device_id')
    camera = request.form.get('camera', 'unknown')
    file = request.files.get('image')
    if not device_id or not file:
        return jsonify({'error': 'device_id and image required'}), 400
    # Prepare dir
    dev_dir = os.path.join(UPLOAD_DIR, secure_filename(device_id))
    os.makedirs(dev_dir, exist_ok=True)
    # Save file
    ts = dt.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"{ts}_{secure_filename(camera)}.jpg"
    path = os.path.join(dev_dir, filename)
    file.save(path)
    rel = os.path.relpath(path, os.path.join(BASE_DIR, 'static'))
    rel = rel.replace('\\', '/')

    # Record
    p = Photo(device_id=device_id, camera=camera, path=rel)
    db.session.add(p)
    db.session.commit()
    return ('', 204)

@app.post('/cancel_sos')
@require_token
def cancel_sos():
    data = request.get_json(silent=True) or {}
    device_id = data.get('device_id')
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    d = Device.query.filter_by(device_id=device_id).first()
    if not d:
        return jsonify({'error': 'device not found'}), 404
    d.sos_cancel_requested = True
    db.session.commit()
    return ('', 204)

# Utility: allow logged-in users to view the API token to configure the app
@app.get('/api_token')
@login_required
def api_token_view():
    return jsonify({ 'api_token': API_TOKEN })

# Temporary debug endpoint to echo request headers and show what the server receives.
@app.route('/debug_headers', methods=['GET', 'POST'])
def debug_headers():
    try:
        hdrs = {k: v for k, v in request.headers.items()}
    except Exception:
        hdrs = {}
    # Log a truncated view for quick inspection
    try:
        app.logger.info(f"Debug headers received: {list(hdrs.items())[:10]}")
    except Exception:
        pass
    return jsonify({'headers': hdrs})

# Auth & dashboard
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password):
            login_user(u)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    q = Device.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)
    devices = q.order_by(Device.last_seen.desc().nullslast()).all()
    return render_template('dashboard.html', devices=devices)

@app.route('/device/<device_id>')
@login_required
def device_detail(device_id):
    d = Device.query.filter_by(device_id=device_id).first_or_404()
    if (not current_user.is_admin) and (d.user_id is not None) and (d.user_id != current_user.id):
        flash('Not authorized to view this device', 'danger')
        return redirect(url_for('dashboard'))
    hbs = Heartbeat.query.filter_by(device_id=device_id).order_by(Heartbeat.timestamp.desc()).limit(200).all()
    photos = Photo.query.filter_by(device_id=device_id).order_by(Photo.created_at.desc()).limit(50).all()
    return render_template('device.html', device=d, heartbeats=hbs, photos=photos)

# Registration flow: open from app with device_id to create account and link
@app.route('/register/start', methods=['GET', 'POST'])
def register_start():
    device_id = request.args.get('device_id') or request.form.get('device_id')
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password required', 'danger')
            return render_template('register_start.html', device_id=device_id)
        if action == 'signup':
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return render_template('register_start.html', device_id=device_id)
            u = User(username=username)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            login_user(u)
        elif action == 'login':
            u = User.query.filter_by(username=username).first()
            if not u or not u.check_password(password):
                flash('Invalid credentials', 'danger')
                return render_template('register_start.html', device_id=device_id)
            login_user(u)
        # link device if provided
        if device_id:
            d = Device.query.filter_by(device_id=device_id).first()
            if not d:
                d = Device(device_id=device_id)
                db.session.add(d)
            d.user_id = current_user.id
            db.session.commit()
            flash('Device linked to your account', 'success')
            return redirect(url_for('device_detail', device_id=device_id))
        return redirect(url_for('dashboard'))
    # GET
    return render_template('register_start.html', device_id=device_id)

# Static uploads (already under /static/uploads)
@app.route('/uploads/<path:filename>')
@login_required
def uploads(filename):
    return send_from_directory(os.path.join(BASE_DIR, 'static'), filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '8000')), debug=True)
