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
    """
    VULNERABILITY: Weak hashing - MD5 without salt
    Real apps should use bcrypt/argon2 with salt
    """
    return hashlib.md5(password.encode()).hexdigest()

def create_token(user_id, role='user'):
    """Create JWT token"""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token):
    """
    VULNERABILITY: JWT Algorithm Confusion
    Accepts 'none' algorithm which allows signature bypass
    """
    try:
        # Get header without verification
        header = jwt.get_unverified_header(token)
        
        # VULNERABILITY: Accept 'none' algorithm
        if header.get('alg', '').lower() == 'none':
            # Decode without signature verification
            parts = token.split('.')
            if len(parts) >= 2:
                payload = parts[1]
                # Add padding if needed
                payload += '=' * (4 - len(payload) % 4)
                decoded = base64.urlsafe_b64decode(payload)
                return json.loads(decoded)
        
        # Normal verification for other algorithms
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'HS384', 'HS512'])
    except Exception as e:
        app.logger.error(f"Token verification failed: {e}")
        return None

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        
        # Check cookie
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
    """Decorator to require admin role"""
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
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header { 
            text-align: center; 
            padding: 60px 20px;
            background: rgba(255,255,255,0.05);
            border-radius: 20px;
            margin-bottom: 40px;
        }
        .header h1 { 
            font-size: 3.5em; 
            color: #4ade80;
            text-shadow: 0 0 30px rgba(74, 222, 128, 0.3);
            margin-bottom: 10px;
        }
        .header p { font-size: 1.2em; opacity: 0.8; }
        
        /* Login Form */
        .auth-container {
            display: flex;
            gap: 40px;
            justify-content: center;
            flex-wrap: wrap;
            margin-bottom: 40px;
        }
        .auth-box { 
            background: rgba(255,255,255,0.08);
            padding: 40px;
            border-radius: 20px;
            width: 100%;
            max-width: 400px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .auth-box h2 { 
            margin-bottom: 30px; 
            color: #4ade80;
            text-align: center;
        }
        .form-group { margin-bottom: 20px; }
        .form-group label { 
            display: block; 
            margin-bottom: 8px; 
            opacity: 0.9;
        }
        input[type="email"], input[type="password"], input[type="text"] { 
            width: 100%; 
            padding: 15px;
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            background: rgba(0,0,0,0.3);
            color: #fff;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #4ade80;
        }
        button { 
            width: 100%; 
            padding: 15px;
            background: linear-gradient(135deg, #4ade80 0%, #22c55e 100%);
            border: none;
            border-radius: 10px;
            color: #000;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(74, 222, 128, 0.3);
        }
        
        /* Stations Grid */
        .stations-section h2 {
            text-align: center;
            margin-bottom: 30px;
            color: #4ade80;
        }
        .stations-grid { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }
        .station-card { 
            background: rgba(255,255,255,0.08);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.3s;
        }
        .station-card:hover {
            transform: translateY(-5px);
        }
        .station-card h3 { 
            color: #4ade80;
            margin-bottom: 15px;
        }
        .status { 
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 14px;
        }
        .status-online { background: rgba(74, 222, 128, 0.2); color: #4ade80; }
        .status-offline { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .status-charging { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
        
        /* Messages */
        .message {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .message.error { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .message.success { background: rgba(74, 222, 128, 0.2); color: #4ade80; }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 40px;
            opacity: 0.6;
            margin-top: 60px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ EcoCharge</h1>
            <p>Electric Vehicle Charging Network</p>
            <p style="margin-top: 10px; font-size: 0.9em;">500+ charging stations across Eastern Europe</p>
        </div>
        
        <div class="auth-container">
            <div class="auth-box">
                <h2>🔐 Login</h2>
                <div id="loginMessage"></div>
                <form id="loginForm">
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" id="loginEmail" placeholder="your@email.com" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" id="loginPassword" placeholder="••••••••" required>
                    </div>
                    <button type="submit">Login</button>
                </form>
            </div>
            
            <div class="auth-box">
                <h2>📝 Register</h2>
                <div id="registerMessage"></div>
                <form id="registerForm">
                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" id="regName" placeholder="John Doe" required>
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" id="regEmail" placeholder="your@email.com" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" id="regPassword" placeholder="••••••••" required>
                    </div>
                    <button type="submit">Create Account</button>
                </form>
            </div>
        </div>
        
        <div class="stations-section">
            <h2>🔌 Available Charging Stations</h2>
            <div class="stations-grid" id="stationsContainer">
                <div class="station-card">
                    <h3>Loading stations...</h3>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>&copy; 2024 EcoCharge Energy. All rights reserved.</p>
            <p style="margin-top: 10px;">Powered by CitrineOS</p>
        </div>
    </div>
    
    <!-- Configuration (intentionally exposed) -->
    <script src="/js/config.js"></script>
    
    <script>
        // Login handler
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
                    msgDiv.innerHTML = '<div class="message success">Login successful! Redirecting...</div>';
                    setTimeout(() => window.location.href = '/dashboard', 1000);
                } else {
                    msgDiv.innerHTML = `<div class="message error">${data.error || 'Login failed'}</div>`;
                }
            } catch (err) {
                msgDiv.innerHTML = '<div class="message error">Connection error</div>';
            }
        });
        
        // Register handler
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
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
                } else {
                    msgDiv.innerHTML = `<div class="message error">${data.error || 'Registration failed'}</div>`;
                }
            } catch (err) {
                msgDiv.innerHTML = '<div class="message error">Connection error</div>';
            }
        });
        
        // Load stations
        async function loadStations() {
            const container = document.getElementById('stationsContainer');
            try {
                const response = await fetch('/api/stations');
                const data = await response.json();
                
                container.innerHTML = '';
                
                // Show local stations
                const stations = [
                    {id: 'CP001', location: 'Kyiv, Khreshchatyk St.', status: 'online', connectors: 2},
                    {id: 'cp002', location: 'Kyiv, Podil District', status: 'online', connectors: 2},
                    {id: 'CP003', location: 'Lviv, Market Square', status: 'offline', connectors: 2},
                    {id: 'CP004', location: 'Odesa, Deribasivska St.', status: 'charging', connectors: 4},
                ];
                
                stations.forEach(station => {
                    const statusClass = station.status === 'online' ? 'status-online' : 
                                       station.status === 'charging' ? 'status-charging' : 'status-offline';
                    container.innerHTML += `
                        <div class="station-card">
                            <h3>🔌 Station ${station.id}</h3>
                            <p style="opacity: 0.8; margin-bottom: 10px;">${station.location}</p>
                            <p>Connectors: ${station.connectors}</p>
                            <p style="margin-top: 10px;">
                                <span class="status ${statusClass}">${station.status.toUpperCase()}</span>
                            </p>
                        </div>
                    `;
                });
            } catch (err) {
                container.innerHTML = '<div class="station-card"><h3>Error loading stations</h3></div>';
            }
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
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
        }
        .navbar {
            background: rgba(0,0,0,0.3);
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .navbar h1 { color: #4ade80; }
        .navbar a { color: #fff; text-decoration: none; margin-left: 20px; }
        .navbar a:hover { color: #4ade80; }
        .container { max-width: 1200px; margin: 0 auto; padding: 30px; }
        .welcome {
            background: rgba(255,255,255,0.08);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
        }
        .welcome h2 { color: #4ade80; margin-bottom: 10px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card {
            background: rgba(255,255,255,0.08);
            padding: 25px;
            border-radius: 15px;
        }
        .card h3 { color: #4ade80; margin-bottom: 15px; }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #4ade80;
            color: #000;
            border-radius: 8px;
            text-decoration: none;
            font-weight: bold;
            margin-top: 15px;
        }
        .btn:hover { background: #22c55e; }
        .profile-data { margin: 10px 0; }
        .profile-data strong { color: #4ade80; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>⚡ EcoCharge</h1>
        <div>
            <a href="/dashboard">Dashboard</a>
            <a href="/api/charging/history">History</a>
            <a href="#" onclick="logout()">Logout</a>
        </div>
    </nav>
    
    <div class="container">
        <div class="welcome">
            <h2>Welcome back!</h2>
            <p id="userInfo">Loading user information...</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>👤 Your Profile</h3>
                <div id="profileData">Loading...</div>
            </div>
            
            <div class="card">
                <h3>🔌 Start Charging</h3>
                <p>Select a station to start charging your vehicle</p>
                <select id="stationSelect" style="width:100%; padding:10px; margin-top:15px; border-radius:8px;">
                    <option value="CP001">CP001 - Kyiv, Khreshchatyk</option>
                    <option value="cp002">cp002 - Kyiv, Podil</option>
                </select>
                <a href="#" class="btn" onclick="startCharging()">Start Charging</a>
            </div>
            
            <div class="card">
                <h3>📊 Recent Activity</h3>
                <div id="activityData">Loading...</div>
            </div>
            
            <div class="card" id="adminCard" style="display:none;">
                <h3>⚙️ Admin Panel</h3>
                <p>Manage stations and users</p>
                <a href="/admin/" class="btn">Open Admin</a>
            </div>
        </div>
    </div>
    
    <script>
        const token = localStorage.getItem('token');
        const userId = localStorage.getItem('user_id');
        const role = localStorage.getItem('role');
        
        if (!token) {
            window.location.href = '/';
        }
        
        // Show admin panel for admins
        if (role === 'admin') {
            document.getElementById('adminCard').style.display = 'block';
        }
        
        // Load user profile
        async function loadProfile() {
            try {
                const response = await fetch(`/api/user/${userId}`, {
                    headers: {'Authorization': `Bearer ${token}`}
                });
                const user = await response.json();
                
                document.getElementById('userInfo').textContent = `Logged in as ${user.name || user.email}`;
                document.getElementById('profileData').innerHTML = `
                    <div class="profile-data"><strong>Email:</strong> ${user.email}</div>
                    <div class="profile-data"><strong>Name:</strong> ${user.name || 'Not set'}</div>
                    <div class="profile-data"><strong>Phone:</strong> ${user.phone || 'Not set'}</div>
                    <div class="profile-data"><strong>RFID Token:</strong> ${user.rfid_token || 'Not assigned'}</div>
                    <div class="profile-data"><strong>Role:</strong> ${user.role}</div>
                `;
            } catch (err) {
                document.getElementById('profileData').textContent = 'Error loading profile';
            }
        }
        
        // Load activity
        async function loadActivity() {
            try {
                const response = await fetch('/api/charging/history', {
                    headers: {'Authorization': `Bearer ${token}`}
                });
                const sessions = await response.json();
                
                if (sessions.length === 0) {
                    document.getElementById('activityData').innerHTML = '<p>No charging sessions yet</p>';
                } else {
                    let html = '';
                    sessions.slice(0, 5).forEach(s => {
                        html += `<div style="margin:10px 0; padding:10px; background:rgba(0,0,0,0.2); border-radius:8px;">
                            <strong>${s.station_id}</strong> - ${s.energy_kwh || 0} kWh
                        </div>`;
                    });
                    document.getElementById('activityData').innerHTML = html;
                }
            } catch (err) {
                document.getElementById('activityData').textContent = 'Error loading activity';
            }
        }
        
        async function startCharging() {
            const stationId = document.getElementById('stationSelect').value;
            try {
                const response = await fetch('/api/charging/start', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({station_id: stationId, connector_id: 1})
                });
                const data = await response.json();
                alert(data.message || 'Charging started!');
            } catch (err) {
                alert('Error starting charging session');
            }
        }
        
        function logout() {
            localStorage.clear();
            window.location.href = '/';
        }
        
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
    """
    FLAG #1: Information Disclosure via robots.txt
    Reveals internal paths and even a flag
    """
    return """User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /backup/
Disallow: /.git/
Disallow: /debug

# Development notes:
# Internal API: http://192.168.20.20:8090/console
# Hasura GraphQL endpoint available
# TODO: Remove before production

# FLAG{robots_txt_info_disclosure}
""", 200, {'Content-Type': 'text/plain'}

@app.route('/.git/config')
def git_config():
    """
    FLAG #2: Exposed Git Configuration
    Contains repository URL and potential credentials
    """
    return """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallaliases = false
[remote "origin"]
    url = https://gitlab.ecocharge.internal/development/web-portal.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
[user]
    name = developer
    email = dev@ecocharge.local
# Deployment credentials (remove before commit!)
# deploy_key: FLAG{git_config_exposed_credentials}
# db_password: citrine
""", 200, {'Content-Type': 'text/plain'}

@app.route('/js/config.js')
def js_config():
    """
    FLAG #3: Hardcoded API keys in JavaScript
    Common mistake - exposing secrets in client-side code
    """
    return """
// EcoCharge Frontend Configuration
// Generated: 2024-01-15

const CONFIG = {
    APP_NAME: 'EcoCharge',
    APP_VERSION: '2.1.0',
    
    // API Endpoints
    API_URL: '/api',
    API_VERSION: 'v1',
    
    // External Services
    MAPS_API_KEY: 'AIzaSyB-fake-maps-api-key-for-ctf',
    ANALYTICS_ID: 'UA-12345678-1',
    
    // Backend Configuration
    CITRINE_WS: 'ws://192.168.20.20:8092',
    CITRINE_WS_201: 'ws://192.168.20.20:8081',
    
    // Development settings (TODO: Remove before production!)
    DEBUG: true,
    INTERNAL_API_KEY: 'FLAG{hardcoded_api_key_in_js}',
    HASURA_ENDPOINT: 'http://192.168.20.20:8090/v1/graphql',
    
    // Feature flags
    FEATURES: {
        LIVE_MAP: true,
        PAYMENT: false,
        RESERVATIONS: false
    }
};

// Export for modules
if (typeof module !== 'undefined') {
    module.exports = CONFIG;
}
""", 200, {'Content-Type': 'application/javascript'}

# =============================================================================
# ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/api/register', methods=['POST'])
def register():
    """User registration endpoint"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    
    # Check if user exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    # Create user
    user = User(
        email=data['email'],
        password_hash=hash_password(data['password']),
        name=data.get('name', ''),
        phone=data.get('phone', ''),
        rfid_token=f"RFID-{os.urandom(6).hex().upper()}",
        role='user'
    )
    
    db.session.add(user)
    db.session.commit()
    
    token = create_token(user.id, user.role)
    
    return jsonify({
        'message': 'Registration successful',
        'token': token,
        'user_id': user.id,
        'role': user.role
    })

@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    
    user = User.query.filter_by(
        email=data['email'],
        password_hash=hash_password(data['password'])
    ).first()
    
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401
    
    token = create_token(user.id, user.role)
    
    response = jsonify({
        'message': 'Login successful',
        'token': token,
        'user_id': user.id,
        'role': user.role
    })
    
    # Also set cookie for convenience
    response.set_cookie('token', token, httponly=False, max_age=86400)
    
    return response

# =============================================================================
# ROUTES - USER API
# =============================================================================

@app.route('/api/user/<int:user_id>')
@token_required
def get_user(user_id):
    """
    FLAG #5: IDOR Vulnerability
    No authorization check - any authenticated user can access any profile
    Should verify: request.user_id == user_id
    """
    user = User.query.get_or_404(user_id)
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'name': user.name,
        'phone': user.phone,
        'rfid_token': user.rfid_token,  # Sensitive data!
        'role': user.role,
        'created_at': user.created_at.isoformat() if user.created_at else None
    })

@app.route('/api/users')
@token_required
@admin_required
def get_all_users():
    """Admin endpoint - list all users"""
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'email': u.email,
        'name': u.name,
        'role': u.role,
        'rfid_token': u.rfid_token,
        'created_at': u.created_at.isoformat() if u.created_at else None
    } for u in users])

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile():
    """Update own profile"""
    data = request.get_json()
    user = User.query.get(request.user_id)
    
    if data.get('name'):
        user.name = data['name']
    if data.get('phone'):
        user.phone = data['phone']
    
    db.session.commit()
    
    return jsonify({'message': 'Profile updated'})

# =============================================================================
# ROUTES - STATIONS API
# =============================================================================

@app.route('/api/stations')
def get_stations():
    """Get list of charging stations"""
    # Try to fetch from CitrineOS
    try:
        query = """
        query {
            ChargingStations {
                id
                isOnline
                locationId
            }
        }
        """
        response = requests.post(
            CITRINE_GRAPHQL,
            json={'query': query},
            headers={'x-hasura-admin-secret': HASURA_ADMIN_SECRET},
            timeout=5
        )
        return jsonify(response.json())
    except Exception as e:
        # Fallback to local database
        stations = Station.query.all()
        return jsonify({
            'data': {
                'ChargingStations': [{
                    'id': s.station_id,
                    'isOnline': s.status == 'available',
                    'location': s.location
                } for s in stations]
            }
        })

@app.route('/api/stations/search')
def search_stations():
    """
    FLAG #7: SQL Injection Vulnerability
    Direct string interpolation allows SQL injection
    """
    location = request.args.get('location', '')
    
    # VULNERABLE: Direct string interpolation
    # Safe version would use parameterized queries
    query = f"SELECT * FROM stations WHERE location LIKE '%{location}%'"
    
    try:
        result = db.engine.execute(query)
        stations = [dict(row) for row in result]
        return jsonify(stations)
    except Exception as e:
        return jsonify({'error': str(e), 'query': query}), 500

@app.route('/api/stations/<station_id>')
def get_station(station_id):
    """Get single station details"""
    station = Station.query.filter_by(station_id=station_id).first_or_404()
    return jsonify({
        'station_id': station.station_id,
        'location': station.location,
        'status': station.status,
        'connectors': station.connectors,
        'latitude': station.latitude,
        'longitude': station.longitude
    })

# =============================================================================
# ROUTES - CHARGING API
# =============================================================================

@app.route('/api/charging/start', methods=['POST'])
@token_required
def start_charging():
    """Start a charging session"""
    data = request.get_json()
    station_id = data.get('station_id')
    connector_id = data.get('connector_id', 1)
    
    if not station_id:
        return jsonify({'error': 'station_id required'}), 400
    
    # Create local session record
    session = ChargingSession(
        user_id=request.user_id,
        station_id=station_id,
        connector_id=connector_id,
        start_time=datetime.utcnow(),
        status='active'
    )
    db.session.add(session)
    db.session.commit()
    
    # Try to send command to CitrineOS
    try:
        response = requests.post(
            f"{CITRINE_API}/ocpp/remoteStart",
            json={
                'stationId': station_id,
                'connectorId': connector_id,
                'idToken': str(request.user_id)
            },
            headers={'x-hasura-admin-secret': HASURA_ADMIN_SECRET},
            timeout=10
        )
        return jsonify({
            'message': 'Charging session started',
            'session_id': session.id,
            'citrine_response': response.json() if response.ok else None
        })
    except Exception as e:
        return jsonify({
            'message': 'Charging session started (local only)',
            'session_id': session.id,
            'warning': str(e)
        })

@app.route('/api/charging/stop', methods=['POST'])
@token_required
def stop_charging():
    """Stop a charging session"""
    data = request.get_json()
    session_id = data.get('session_id')
    
    session = ChargingSession.query.get_or_404(session_id)
    
    # Basic authorization check
    if session.user_id != request.user_id and request.user_role != 'admin':
        return jsonify({'error': 'Not authorized'}), 403
    
    session.end_time = datetime.utcnow()
    session.status = 'completed'
    session.energy_kwh = 15.5  # Simulated
    session.cost = 45.00  # Simulated
    
    db.session.commit()
    
    return jsonify({
        'message': 'Charging stopped',
        'session': {
            'id': session.id,
            'energy_kwh': session.energy_kwh,
            'cost': session.cost
        }
    })

@app.route('/api/charging/history')
@token_required
def charging_history():
    """Get user's charging history"""
    sessions = ChargingSession.query.filter_by(user_id=request.user_id).order_by(
        ChargingSession.start_time.desc()
    ).limit(50).all()
    
    return jsonify([{
        'id': s.id,
        'station_id': s.station_id,
        'connector_id': s.connector_id,
        'start_time': s.start_time.isoformat() if s.start_time else None,
        'end_time': s.end_time.isoformat() if s.end_time else None,
        'energy_kwh': s.energy_kwh,
        'cost': s.cost,
        'status': s.status
    } for s in sessions])

# =============================================================================
# ROUTES - INTERNAL API (Should be protected but isn't)
# =============================================================================

@app.route('/api/internal/config')
def internal_config():
    """
    FLAG #4: Exposed Internal Configuration
    This endpoint should be restricted but is accessible
    """
    return jsonify({
        'app_name': 'EcoCharge Portal',
        'version': '2.1.0',
        'environment': 'development',
        'citrine_api': CITRINE_API,
        'citrine_graphql': CITRINE_GRAPHQL,
        'hasura_secret': HASURA_ADMIN_SECRET,  # CRITICAL EXPOSURE!
        'jwt_secret': JWT_SECRET,  # CRITICAL EXPOSURE!
        'database': str(app.config['SQLALCHEMY_DATABASE_URI']),
        'debug_mode': app.debug,
        'flag': 'FLAG{internal_api_config_exposed}'
    })

@app.route('/api/internal/health')
def internal_health():
    """
    FLAG #10: More credential exposure
    Health check with too much debug information
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'services': {
            'database': 'connected',
            'citrine': 'connected',
            'rabbitmq': 'connected',
            'minio': 'connected'
        },
        'debug_info': {
            'rabbitmq_url': 'amqp://guest:guest@192.168.20.20:5672',
            'rabbitmq_management': 'http://guest:guest@192.168.20.20:15672',
            'minio_endpoint': 'http://minioadmin:minioadmin@192.168.20.20:9000',
            'minio_console': 'http://192.168.20.20:9001',
            'postgresql': 'postgresql://citrine:citrine@192.168.20.20:5432/citrine',
            'flag': 'FLAG{internal_health_credentials_exposed}'
        }
    })

@app.route('/api/internal/stats')
def internal_stats():
    """Internal statistics endpoint"""
    return jsonify({
        'users_count': User.query.count(),
        'sessions_today': ChargingSession.query.filter(
            ChargingSession.start_time >= datetime.utcnow().date()
        ).count(),
        'active_sessions': ChargingSession.query.filter_by(status='active').count()
    })

# =============================================================================
# ROUTES - DEBUG (Should be disabled in production)
# =============================================================================

@app.route('/debug')
def debug_info():
    """
    FLAG #11: Debug endpoint exposed
    Should be disabled but app.debug is True
    """
    if app.debug:
        return jsonify({
            'debug_enabled': True,
            'app_secret': app.secret_key,
            'database_uri': str(app.config['SQLALCHEMY_DATABASE_URI']),
            'jwt_secret': JWT_SECRET,
            'hasura_secret': HASURA_ADMIN_SECRET,
            'all_routes': [str(rule) for rule in app.url_map.iter_rules()],
            'flag': 'FLAG{debug_endpoint_exposed}'
        })
    return jsonify({'debug_enabled': False}), 403

# =============================================================================
# ROUTES - ADMIN
# =============================================================================

@app.route('/admin/')
@token_required
@admin_required
def admin_panel():
    """Admin panel main page"""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Admin - EcoCharge</title></head>
    <body style="background:#1a1a2e;color:#fff;font-family:Arial;padding:20px;">
        <h1 style="color:#4ade80;">⚙️ EcoCharge Admin Panel</h1>
        <nav style="margin:20px 0;">
            <a href="/admin/users" style="color:#4ade80;margin-right:20px;">Users</a>
            <a href="/admin/stations" style="color:#4ade80;margin-right:20px;">Stations</a>
            <a href="/admin/sessions" style="color:#4ade80;margin-right:20px;">Sessions</a>
            <a href="/admin/system" style="color:#4ade80;">System</a>
        </nav>
        <div style="background:rgba(255,255,255,0.1);padding:20px;border-radius:10px;">
            <h2>Quick Links</h2>
            <ul style="line-height:2;">
                <li><a href="http://192.168.20.20:3000" style="color:#4ade80;">CitrineOS UI</a></li>
                <li><a href="http://192.168.20.20:8090/console" style="color:#4ade80;">Hasura Console</a></li>
                <li><a href="http://192.168.20.20:15672" style="color:#4ade80;">RabbitMQ</a></li>
                <li><a href="http://192.168.20.20:9001" style="color:#4ade80;">MinIO Console</a></li>
            </ul>
        </div>
    </body>
    </html>
    """

@app.route('/admin/stations')
@token_required
@admin_required
def admin_stations():
    """Admin stations management"""
    return jsonify({
        'stations': [
            {
                'id': 'CP001',
                'ip': '172.16.0.40',
                'protocol': 'OCPP 1.6',
                'status': 'online',
                'ui': 'http://172.16.0.40:1880',
                'logs': 'http://172.16.0.40:8888'
            },
            {
                'id': 'cp002',
                'ip': '172.16.0.60',
                'protocol': 'OCPP 2.0.1',
                'status': 'online',
                'ui': 'http://172.16.0.60:1881',
                'logs': 'http://172.16.0.60:8889'
            }
        ],
        'csms': {
            'url': 'http://192.168.20.20:3000',
            'api': 'http://192.168.20.20:8080',
            'graphql': 'http://192.168.20.20:8090/v1/graphql'
        }
    })

@app.route('/admin/system')
@token_required
@admin_required  
def admin_system():
    """Admin system information"""
    return jsonify({
        'system': {
            'portal_version': '2.1.0',
            'citrine_version': 'diploma-v1',
            'everest_version': '0.0.23'
        },
        'connections': {
            'citrine_api': CITRINE_API,
            'citrine_graphql': CITRINE_GRAPHQL,
            'hasura_secret': HASURA_ADMIN_SECRET,
            'ocpp_16_ws': 'ws://192.168.20.20:8092',
            'ocpp_201_ws': 'ws://192.168.20.20:8081',
            'postgresql': 'postgresql://citrine:citrine@192.168.20.20:5432/citrine',
            'rabbitmq': 'amqp://guest:guest@192.168.20.20:5672',
            'minio': 'http://minioadmin:minioadmin@192.168.20.20:9000'
        }
    })

# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

def init_database():
    """Initialize database with test data"""
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(email='admin@ecocharge.local').first():
        admin = User(
            email='admin@ecocharge.local',
            password_hash=hash_password('admin123'),  # Weak password
            name='Administrator',
            phone='+380501234567',
            role='admin',
            rfid_token='RFID-ADMIN-000001'
        )
        db.session.add(admin)
        print("[+] Created admin user: admin@ecocharge.local / admin123")
    
    # Create test users
    test_users = [
        ('john.doe@example.com', 'password123', 'John Doe', '+380501111111', 'FLAG{idor_user_data_leaked}'),
        ('jane.smith@example.com', 'qwerty', 'Jane Smith', '+380502222222', 'RFID-USER-000002'),
        ('bob.wilson@example.com', '123456', 'Bob Wilson', '+380503333333', 'RFID-USER-000003'),
        ('alice.johnson@example.com', 'alice2024', 'Alice Johnson', '+380504444444', 'RFID-USER-000004'),
    ]
    
    for email, password, name, phone, rfid in test_users:
        if not User.query.filter_by(email=email).first():
            user = User(
                email=email,
                password_hash=hash_password(password),
                name=name,
                phone=phone,
                rfid_token=rfid
            )
            db.session.add(user)
            print(f"[+] Created test user: {email} / {password}")
    
    # Create stations
    stations_data = [
        ('CP001', 'Kyiv, Khreshchatyk St. 1', 50.4501, 30.5234, 'available', 2),
        ('cp002', 'Kyiv, Podil District', 50.4651, 30.5160, 'available', 2),
        ('CP003', 'Lviv, Market Square', 49.8397, 24.0297, 'offline', 2),
        ('CP004', 'Odesa, Deribasivska St.', 46.4825, 30.7233, 'charging', 4),
    ]
    
    for sid, loc, lat, lng, status, conn in stations_data:
        if not Station.query.filter_by(station_id=sid).first():
            station = Station(
                station_id=sid,
                location=loc,
                latitude=lat,
                longitude=lng,
                status=status,
                connectors=conn
            )
            db.session.add(station)
            print(f"[+] Created station: {sid}")
    
    # Create secrets table with flags
    secrets_data = [
        ('sqli_flag', 'FLAG{sql_injection_database_dump}'),
        ('jwt_flag', 'FLAG{jwt_algorithm_none_bypass}'),
        ('admin_secret', 'The admin password is admin123'),
    ]
    
    for name, flag in secrets_data:
        if not Secret.query.filter_by(name=name).first():
            secret = Secret(name=name, flag=flag)
            db.session.add(secret)
            print(f"[+] Created secret: {name}")
    
    db.session.commit()
    print("[+] Database initialized successfully!")

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    with app.app_context():
        init_database()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║           EcoCharge Web Portal - CTF Version                   ║
    ║═══════════════════════════════════════════════════════════════║
    ║  WARNING: This application contains intentional vulnerabilities ║
    ║           DO NOT USE IN PRODUCTION                             ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    Starting server on http://0.0.0.0:80
    
    Test credentials:
      Admin: admin@ecocharge.local / admin123
      User:  john.doe@example.com / password123
    
    Vulnerable endpoints:
      - /robots.txt (info disclosure)
      - /.git/config (credential exposure)
      - /js/config.js (hardcoded secrets)
      - /api/internal/config (config exposure)
      - /api/user/<id> (IDOR)
      - /api/stations/search?location= (SQLi)
      - JWT with alg:none accepted
      - /debug (debug info)
    """)
    
    app.run(host='0.0.0.0', port=80, debug=True)
