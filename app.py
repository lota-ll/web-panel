#!/usr/bin/env python3
"""
EcoCharge Web Portal - Intentionally Vulnerable for CTF
=========================================================
DO NOT USE IN PRODUCTION - This contains intentional security vulnerabilities

Vulnerabilities included:
- IDOR (Insecure Direct Object Reference)
- SQL Injection
- JWT Algorithm Confusion (none)
- Hardcoded Secrets
- Information Disclosure
- Weak Password Hashing (MD5)

For educational purposes only.
"""

from flask import Flask, request, jsonify, render_template_string, redirect, session, make_response
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import jwt
import hashlib
import os
import requests
from datetime import datetime, timedelta
import json
import base64
import random  # <--- ДОДАНО: Для генерації remoteStartId

app = Flask(__name__)
app.secret_key = 'EcoCharge-Secret-Key-2024'  # Weak secret - discoverable

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecocharge.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# =============================================================================
# CONFIGURATION - Contains secrets (intentionally exposed)
# =============================================================================

# CitrineOS Internal API
CITRINE_API = os.environ.get('CITRINE_API', 'http://192.168.20.20:8080')
CITRINE_GRAPHQL = os.environ.get('CITRINE_GRAPHQL', 'http://192.168.20.20:8090/v1/graphql')
HASURA_ADMIN_SECRET = 'CitrineOS!'  # Hardcoded secret - FLAG trigger

# JWT Configuration (intentionally weak)
JWT_SECRET = 'ecocharge123'
JWT_ALGORITHM = 'HS256'

# =============================================================================
# DATABASE MODELS
# =============================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    rfid_token = db.Column(db.String(50))
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class ChargingSession(db.Model):
    __tablename__ = 'charging_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    station_id = db.Column(db.String(50))
    connector_id = db.Column(db.Integer)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    energy_kwh = db.Column(db.Float)
    cost = db.Column(db.Float)
    status = db.Column(db.String(20), default='active')
    transaction_id = db.Column(db.String(50)) # Added to store remote transaction ID

class Station(db.Model):
    __tablename__ = 'stations'
    id = db.Column(db.Integer, primary_key=True)
    station_id = db.Column(db.String(50), unique=True)
    location = db.Column(db.String(200))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    status = db.Column(db.String(20), default='available')
    connectors = db.Column(db.Integer, default=2)

class Secret(db.Model):
    """Table for CTF flags"""
    __tablename__ = 'secrets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    flag = db.Column(db.String(100))

# =============================================================================
# AUTHENTICATION HELPERS
# =============================================================================

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def create_token(user_id, role='user'):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token):
    try:
        header = jwt.get_unverified_header(token)
        if header.get('alg', '').lower() == 'none':
            parts = token.split('.')
            if len(parts) >= 2:
                payload = parts[1]
                payload += '=' * (4 - len(payload) % 4)
                decoded = base64.urlsafe_b64decode(payload)
                return json.loads(decoded)
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'HS384', 'HS512'])
    except Exception as e:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        if not token:
            token = request.cookies.get('token')
        if not token:
            return jsonify({'error': 'Authentication token required'}), 401
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        request.user_id = payload.get('user_id')
        request.user_role = payload.get('role', 'user')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(request, 'user_role', None) != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# =============================================================================
# HTML TEMPLATES
# =============================================================================

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EcoCharge - Electric Vehicle Charging Network</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 60px 20px; background: rgba(255,255,255,0.05); border-radius: 20px; margin-bottom: 40px; }
        .header h1 { font-size: 3.5em; color: #4ade80; text-shadow: 0 0 30px rgba(74, 222, 128, 0.3); margin-bottom: 10px; }
        .auth-container { display: flex; gap: 40px; justify-content: center; flex-wrap: wrap; margin-bottom: 40px; }
        .auth-box { background: rgba(255,255,255,0.08); padding: 40px; border-radius: 20px; width: 100%; max-width: 400px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }
        .auth-box h2 { margin-bottom: 30px; color: #4ade80; text-align: center; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; opacity: 0.9; }
        input { width: 100%; padding: 15px; border: 2px solid rgba(255,255,255,0.1); border-radius: 10px; background: rgba(0,0,0,0.3); color: #fff; font-size: 16px; }
        button { width: 100%; padding: 15px; background: linear-gradient(135deg, #4ade80 0%, #22c55e 100%); border: none; border-radius: 10px; color: #000; font-size: 16px; font-weight: bold; cursor: pointer; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(74, 222, 128, 0.3); }
        .stations-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
        .station-card { background: rgba(255,255,255,0.08); padding: 25px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1); }
        .status { display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 14px; }
        .status-online { background: rgba(74, 222, 128, 0.2); color: #4ade80; }
        .status-offline { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .status-charging { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
        .message { padding: 15px; border-radius: 10px; margin-bottom: 20px; text-align: center; }
        .message.error { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .message.success { background: rgba(74, 222, 128, 0.2); color: #4ade80; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ EcoCharge</h1>
            <p>Electric Vehicle Charging Network</p>
        </div>
        <div class="auth-container">
            <div class="auth-box">
                <h2>🔐 Login</h2>
                <div id="loginMessage"></div>
                <form id="loginForm">
                    <div class="form-group"><label>Email</label><input type="email" id="loginEmail" required></div>
                    <div class="form-group"><label>Password</label><input type="password" id="loginPassword" required></div>
                    <button type="submit">Login</button>
                </form>
            </div>
            <div class="auth-box">
                <h2>📝 Register</h2>
                <div id="registerMessage"></div>
                <form id="registerForm">
                    <div class="form-group"><label>Name</label><input type="text" id="regName" required></div>
                    <div class="form-group"><label>Email</label><input type="email" id="regEmail" required></div>
                    <div class="form-group"><label>Password</label><input type="password" id="regPassword" required></div>
                    <button type="submit">Create Account</button>
                </form>
            </div>
        </div>
        <div class="stations-section">
            <h2>🔌 Available Charging Stations</h2>
            <div class="stations-grid" id="stationsContainer">Loading...</div>
        </div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const msgDiv = document.getElementById('loginMessage');
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        email: document.getElementById('loginEmail').value,
                        password: document.getElementById('loginPassword').value
                    })
                });
                const data = await response.json();
                if (response.ok && data.token) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user_id', data.user_id);
                    localStorage.setItem('role', data.role);
                    msgDiv.innerHTML = '<div class="message success">Success! Redirecting...</div>';
                    setTimeout(() => window.location.href = '/dashboard', 1000);
                } else { msgDiv.innerHTML = `<div class="message error">${data.error}</div>`; }
            } catch (err) { msgDiv.innerHTML = '<div class="message error">Connection error</div>'; }
        });

        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            // Similar registration logic...
            const msgDiv = document.getElementById('registerMessage');
             try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        name: document.getElementById('regName').value,
                        email: document.getElementById('regEmail').value,
                        password: document.getElementById('regPassword').value
                    })
                });
                const data = await response.json();
                if (response.ok && data.token) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user_id', data.user_id);
                    msgDiv.innerHTML = '<div class="message success">Account created! Redirecting...</div>';
                    setTimeout(() => window.location.href = '/dashboard', 1000);
                } else { msgDiv.innerHTML = `<div class="message error">${data.error}</div>`; }
            } catch (err) { msgDiv.innerHTML = '<div class="message error">Connection error</div>'; }
        });

        async function loadStations() {
            const container = document.getElementById('stationsContainer');
            try {
                const response = await fetch('/api/stations');
                const data = await response.json();
                container.innerHTML = '';
                // Hardcoded fallback for demo
                const stations = [
                    {id: 'CP001', location: 'Kyiv, Khreshchatyk', status: 'online', connectors: 2},
                    {id: 'cp002', location: 'Kyiv, Podil (OCPP 2.0.1)', status: 'online', connectors: 2},
                ];
                stations.forEach(s => {
                    container.innerHTML += `
                        <div class="station-card">
                            <h3>🔌 ${s.id}</h3>
                            <p>${s.location}</p>
                            <span class="status status-${s.status}">${s.status}</span>
                        </div>`;
                });
            } catch (err) {}
        }
        loadStations();
    </script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - EcoCharge</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
        .navbar { background: rgba(0,0,0,0.3); padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { color: #4ade80; }
        .navbar a { color: #fff; text-decoration: none; margin-left: 20px; }
        .container { max-width: 1200px; margin: 0 auto; padding: 30px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: rgba(255,255,255,0.08); padding: 25px; border-radius: 15px; }
        .card h3 { color: #4ade80; margin-bottom: 15px; }
        .btn { display: inline-block; padding: 10px 20px; background: #4ade80; color: #000; border-radius: 8px; text-decoration: none; font-weight: bold; border: none; cursor: pointer; }
        .btn:hover { background: #22c55e; }
        .btn-stop { background: #ef4444; color: white; padding: 5px 10px; font-size: 0.8em; float: right; }
        .btn-stop:hover { background: #dc2626; }
        .profile-data div { margin: 5px 0; }
        .profile-data strong { color: #4ade80; }
        .session-item { background: rgba(0,0,0,0.2); padding: 10px; margin: 10px 0; border-radius: 8px; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>⚡ EcoCharge</h1>
        <div>
            <a href="#" onclick="logout()">Logout</a>
        </div>
    </nav>
    <div class="container">
        <div class="welcome" style="margin-bottom: 20px;">
            <h2 id="userInfo">Welcome back!</h2>
        </div>
        <div class="grid">
            <div class="card">
                <h3>👤 Your Profile</h3>
                <div id="profileData">Loading...</div>
            </div>
            <div class="card">
                <h3>🔌 Start Charging</h3>
                <p>Select a station to start charging</p>
                <select id="stationSelect" style="width:100%; padding:10px; margin:15px 0; border-radius:8px;">
                    <option value="CP001">CP001 - Kyiv, Khreshchatyk (OCPP 1.6)</option>
                    <option value="cp002">cp002 - Kyiv, Podil (OCPP 2.0.1)</option>
                </select>
                <button class="btn" onclick="startCharging()">Start Charging</button>
            </div>
            <div class="card">
                <h3>📊 Recent Activity</h3>
                <div id="activityData">Loading...</div>
            </div>
             <div class="card" id="adminCard" style="display:none;">
                <h3>⚙️ Admin Panel</h3>
                <a href="/admin/" class="btn">Open Admin</a>
            </div>
        </div>
    </div>
    <script>
        const token = localStorage.getItem('token');
        const userId = localStorage.getItem('user_id');
        const role = localStorage.getItem('role');
        
        if (!token) window.location.href = '/';
        if (role === 'admin') document.getElementById('adminCard').style.display = 'block';
        
        async function loadProfile() {
            try {
                const response = await fetch(`/api/user/${userId}`, { headers: {'Authorization': `Bearer ${token}`} });
                const user = await response.json();
                document.getElementById('userInfo').textContent = `Welcome, ${user.name || user.email}`;
                document.getElementById('profileData').innerHTML = `
                    <div class="profile-data">
                        <div><strong>Email:</strong> ${user.email}</div>
                        <div><strong>RFID:</strong> ${user.rfid_token}</div>
                        <div><strong>Role:</strong> ${user.role}</div>
                    </div>`;
            } catch (e) {}
        }
        
        async function loadActivity() {
            try {
                const response = await fetch('/api/charging/history', { headers: {'Authorization': `Bearer ${token}`} });
                const sessions = await response.json();
                if (sessions.length === 0) {
                    document.getElementById('activityData').innerHTML = '<p>No sessions yet</p>';
                } else {
                    let html = '';
                    sessions.slice(0, 5).forEach(s => {
                        let action = '';
                        if (s.status === 'active') {
                            action = `<button onclick="stopCharging(${s.id}, '${s.station_id}')" class="btn btn-stop">Stop</button>`;
                        }
                        html += `
                        <div class="session-item">
                            <div style="margin-bottom:5px;">
                                <strong>${s.station_id}</strong>
                                ${action}
                            </div>
                            <div style="font-size:0.9em; opacity:0.8;">
                                ${s.start_time.split('T')[0]} | ${s.energy_kwh || 0} kWh | Status: ${s.status}
                            </div>
                        </div>`;
                    });
                    document.getElementById('activityData').innerHTML = html;
                }
            } catch (e) {}
        }
        
        async function startCharging() {
            const stationId = document.getElementById('stationSelect').value;
            try {
                const response = await fetch('/api/charging/start', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
                    body: JSON.stringify({station_id: stationId, connector_id: 1})
                });
                const data = await response.json();
                if (response.ok) {
                    alert('Charging started!');
                    loadActivity();
                } else {
                    alert('Error: ' + (data.error || data.message || 'Unknown error'));
                }
            } catch (e) { alert('Connection error'); }
        }

        async function stopCharging(sessionId, stationId) {
            if(!confirm('Stop charging session?')) return;
            try {
                const response = await fetch('/api/charging/stop', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
                    body: JSON.stringify({session_id: sessionId, station_id: stationId})
                });
                const data = await response.json();
                if (response.ok) {
                    alert('Charging stopped!');
                    loadActivity();
                } else {
                    alert('Error stopping: ' + (data.error || 'Unknown error'));
                }
            } catch (e) { alert('Connection error'); }
        }
        
        function logout() { localStorage.clear(); window.location.href = '/'; }
        
        loadProfile();
        loadActivity();
    </script>
</body>
</html>
"""

# =============================================================================
# ROUTES - PUBLIC
# =============================================================================

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/dashboard')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/robots.txt')
def robots():
    return """User-agent: *\nDisallow: /admin/\nDisallow: /api/internal/\n# FLAG{robots_txt_info_disclosure}""", 200, {'Content-Type': 'text/plain'}

@app.route('/.git/config')
def git_config():
    return """[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = https://gitlab.ecocharge.internal/web.git\n# FLAG{git_config_exposed_credentials}""", 200, {'Content-Type': 'text/plain'}

@app.route('/js/config.js')
def js_config():
    return """const CONFIG = { API_URL: '/api', INTERNAL_API: 'FLAG{hardcoded_api_key_in_js}' };""", 200, {'Content-Type': 'application/javascript'}

# =============================================================================
# ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'error': 'Email exists'}), 400
    user = User(
        email=data['email'],
        password_hash=hash_password(data['password']),
        name=data.get('name', ''),
        rfid_token=f"RFID-{os.urandom(6).hex().upper()}"
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'token': create_token(user.id), 'user_id': user.id})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email'), password_hash=hash_password(data.get('password'))).first()
    if not user: return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'token': create_token(user.id, user.role), 'user_id': user.id, 'role': user.role})

# =============================================================================
# ROUTES - USER API
# =============================================================================

@app.route('/api/user/<int:user_id>')
@token_required
def get_user(user_id):
    # VULNERABILITY: IDOR
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id, 'email': user.email, 'name': user.name,
        'rfid_token': user.rfid_token, 'role': user.role
    })

@app.route('/api/users')
@token_required
@admin_required
def get_all_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'email': u.email, 'role': u.role} for u in users])

# =============================================================================
# ROUTES - STATIONS API
# =============================================================================

@app.route('/api/stations')
def get_stations():
    stations = Station.query.all()
    return jsonify([{'id': s.station_id, 'location': s.location, 'status': s.status} for s in stations])

@app.route('/api/stations/search')
def search_stations():
    # VULNERABILITY: SQL Injection
    location = request.args.get('location', '')
    query = f"SELECT * FROM stations WHERE location LIKE '%{location}%'"
    try:
        result = db.engine.execute(query)
        return jsonify([dict(row) for row in result])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ROUTES - CHARGING API (FIXED)
# =============================================================================

@app.route('/api/charging/start', methods=['POST'])
@token_required
def start_charging():
    data = request.json
    station_id = data.get('station_id')
    
    # 1. ОТРИМАННЯ ДАНИХ
    user = User.query.get(request.user_id)
    
    # Гарантуємо, що це ціле число (int)
    try:
        connector_id = int(data.get('connector_id', 1))
    except:
        connector_id = 1

    # Генеруємо ID транзакції як число
    remote_start_id = random.randint(10000, 99999)

    # --- ВИПРАВЛЕННЯ: СТВОРЮЄМО СЕСІЮ В БД ПЕРЕД ЗАПИТОМ ---
    charging_session = ChargingSession(
        user_id=request.user_id,
        station_id=station_id,
        connector_id=connector_id,
        start_time=datetime.utcnow(),
        status='pending',
        transaction_id=str(remote_start_id)
    )
    db.session.add(charging_session)
    db.session.commit()
    # -------------------------------------------------------

    try:
        if station_id.startswith('cp') or '002' in station_id:
            # === OCPP 2.0.1 (CP002) ===
            endpoint = f"{CITRINE_API}/ocpp/2.0.1/evdriver/requestStartTransaction"
            
            # 2. ФОРМУВАННЯ PAYLOAD
            payload = {
                "stationId": str(station_id),
                "tenantId": "1",
                "idToken": {
                    "idToken": str(user.rfid_token),
                    "type": "Local"
                },
                "evseId": int(connector_id),
                "remoteStartId": int(remote_start_id)
            }
            
            print(f"[DEBUG] Sending Payload: {json.dumps(payload)}")
            
            # 3. ВІДПРАВКА
            response = requests.post(
                endpoint,
                params={'identifier': station_id}, # Query param required for Citrine
                json=payload,
                timeout=10
            )
            
        else:
            # Fallback for OCPP 1.6
            endpoint = f"{CITRINE_API}/data/monitoring/remoteStart"
            response = requests.post(
                endpoint,
                json={
                    'stationId': station_id,
                    'connectorId': connector_id,
                    'idTag': user.rfid_token
                },
                headers={'x-hasura-admin-secret': HASURA_ADMIN_SECRET},
                timeout=10
            )

        if response.ok:
            # Тепер ця змінна існує, і помилки не буде
            charging_session.status = 'active'
            db.session.commit()
            return jsonify({
                'message': 'Charging command sent',
                'session_id': charging_session.id,
                'citrine_response': response.json()
            })
        else:
            charging_session.status = 'error'
            db.session.commit()
            return jsonify({
                'message': 'CitrineOS rejected request',
                'error': response.text
            }), 400
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/charging/stop', methods=['POST'])
@token_required
def stop_charging():
    """Stop a charging session"""
    data = request.get_json()
    session_id = data.get('session_id')
    station_id = data.get('station_id') # Needed for remote stop
    
    session = ChargingSession.query.get_or_404(session_id)
    
    if session.user_id != request.user_id and request.user_role != 'admin':
        return jsonify({'error': 'Not authorized'}), 403
    
    # FIX: Send RemoteStopTransaction to CitrineOS
    try:
        # OCPP 2.0.1 Stop
        if station_id and ('cp' in station_id.lower() or '002' in station_id):
             response = requests.post(
                f"{CITRINE_API}/ocpp/2.0.1/evdriver/requestStopTransaction",
                params={'identifier': station_id},
                json={
                    'stationId': station_id,
                    'transactionId': session.transaction_id or "12345"
                },
                timeout=5
            )
    except Exception as e:
        print(f"Failed to call remote stop: {e}")

    # Update local DB
    session.end_time = datetime.utcnow()
    session.status = 'completed'
    session.energy_kwh = round(random.uniform(5.0, 50.0), 2)
    session.cost = round(session.energy_kwh * 3.5, 2)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Charging stopped',
        'session': {'id': session.id, 'status': 'completed'}
    })

@app.route('/api/charging/history')
@token_required
def charging_history():
    sessions = ChargingSession.query.filter_by(user_id=request.user_id).order_by(ChargingSession.start_time.desc()).all()
    return jsonify([{
        'id': s.id,
        'station_id': s.station_id,
        'start_time': s.start_time.isoformat() if s.start_time else None,
        'status': s.status,
        'energy_kwh': s.energy_kwh
    } for s in sessions])

# =============================================================================
# ADMIN & DEBUG
# =============================================================================

@app.route('/admin/')
@token_required
@admin_required
def admin_panel():
    return "<h1>Admin Panel</h1><p>Under Construction</p>"

@app.route('/debug')
def debug_info():
    if app.debug:
        return jsonify({'debug': True, 'flag': 'FLAG{debug_endpoint_exposed}'})
    return jsonify({'debug': False})

@app.route('/api/internal/config')
def internal_config():
    return jsonify({'secret': HASURA_ADMIN_SECRET, 'flag': 'FLAG{internal_api_config_exposed}'})

# =============================================================================
# MAIN
# =============================================================================

def init_db():
    db.create_all()
    if not User.query.first():
        admin = User(email='admin@ecocharge.local', password_hash=hash_password('admin123'), role='admin', rfid_token='RFID-ADMIN')
        user = User(email='user@example.com', password_hash=hash_password('password'), role='user', rfid_token='RFID-USER')
        db.session.add_all([admin, user])
        
        # Add test stations
        s1 = Station(station_id='CP001', location='Kyiv 1', status='online')
        s2 = Station(station_id='cp002', location='Kyiv 2', status='online')
        db.session.add_all([s1, s2])
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=80, debug=True)