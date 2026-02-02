#!/usr/bin/env python3
"""
EcoCharge Web Portal - CTF Version (FINAL FIXED)
"""

from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import jwt
import hashlib
import os
import requests
from datetime import datetime, timedelta
import json
import base64
import random

app = Flask(__name__)
app.secret_key = 'EcoCharge-Secret-Key-2024'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecocharge.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# =============================================================================
# CONFIGURATION
# =============================================================================

CITRINE_API = os.environ.get('CITRINE_API', 'http://192.168.20.20:8080')
CITRINE_GRAPHQL = os.environ.get('CITRINE_GRAPHQL', 'http://192.168.20.20:8090/v1/graphql')
HASURA_ADMIN_SECRET = 'CitrineOS!'
JWT_SECRET = 'ecocharge123'
JWT_ALGORITHM = 'HS256'

# =============================================================================
# MODELS
# =============================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    name = db.Column(db.String(100))
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
    transaction_id = db.Column(db.String(50))

class Station(db.Model):
    __tablename__ = 'stations'
    id = db.Column(db.Integer, primary_key=True)
    station_id = db.Column(db.String(50), unique=True)
    location = db.Column(db.String(200))
    status = db.Column(db.String(20), default='available')

# =============================================================================
# AUTH HELPERS
# =============================================================================

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def create_token(user_id, role='user'):
    payload = {
        'user_id': user_id, 'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token):
    try:
        header = jwt.get_unverified_header(token)
        if header.get('alg', '').lower() == 'none':
            parts = token.split('.')
            if len(parts) >= 2:
                payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
                return json.loads(base64.urlsafe_b64decode(payload))
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except: return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token: token = request.cookies.get('token')
        if not token: return jsonify({'error': 'Token required'}), 401
        payload = verify_token(token)
        if not payload: return jsonify({'error': 'Invalid token'}), 401
        request.user_id = payload.get('user_id')
        request.user_role = payload.get('role', 'user')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(request, 'user_role', None) != 'admin':
            return jsonify({'error': 'Admin required'}), 403
        return f(*args, **kwargs)
    return decorated

# =============================================================================
# HTML TEMPLATES
# =============================================================================

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>EcoCharge</title>
    <style>
        body { font-family: sans-serif; background: #1a1a2e; color: #fff; padding: 20px; }
        .box { background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; max-width: 400px; margin: 0 auto; }
        input, button { width: 100%; padding: 10px; margin: 5px 0; }
        button { background: #4ade80; border: none; cursor: pointer; font-weight: bold; }
    </style>
</head>
<body>
    <div style="text-align:center"><h1>⚡ EcoCharge</h1></div>
    <div class="box">
        <h2>Login</h2>
        <form id="loginForm">
            <input type="email" id="email" placeholder="Email" required>
            <input type="password" id="pass" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const res = await fetch('/api/login', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email: document.getElementById('email').value, password: document.getElementById('pass').value})
            });
            const data = await res.json();
            if(res.ok) { localStorage.setItem('token', data.token); localStorage.setItem('user_id', data.user_id); localStorage.setItem('role', data.role); window.location.href = '/dashboard'; }
            else alert(data.error);
        });
    </script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Dashboard</title>
    <style>
        body { font-family: sans-serif; background: #1a1a2e; color: #fff; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        .card { background: rgba(255,255,255,0.1); padding: 20px; margin: 20px 0; border-radius: 10px; }
        button { background: #4ade80; border: none; padding: 10px 20px; cursor: pointer; font-weight: bold; border-radius: 5px;}
        .btn-stop { background: #ef4444; color: white; float: right; padding: 5px 10px;}
        select { padding: 10px; width: 70%; }
        .log { font-family: monospace; background: #000; padding: 10px; font-size: 0.8em; color: #0f0; margin-top:10px; white-space: pre-wrap;}
    </style>
</head>
<body>
    <div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <h1>Dashboard</h1>
            <a href="#" onclick="localStorage.clear(); window.location.href='/'" style="color:#aaa">Logout</a>
        </div>
        
        <div class="card">
            <h3>👤 User: <span id="userEmail">...</span></h3>
            <p>RFID Token: <strong id="rfidToken">...</strong></p>
        </div>

        <div class="card">
            <h3>🔌 Start Charging</h3>
            <select id="stationSelect">
                <option value="CP001">CP001 (OCPP 1.6)</option>
                <option value="CP002">CP002 (OCPP 2.0.1)</option>
            </select>
            <button onclick="startCharging()">Start</button>
        </div>

        <div class="card">
            <h3>📊 Active Sessions</h3>
            <div id="sessions">Loading...</div>
        </div>
        
        <div class="card">
            <h3>📜 Debug Log (Last Action)</h3>
            <div id="debugLog" class="log">No actions yet</div>
        </div>
    </div>
    <script>
        const token = localStorage.getItem('token');
        if(!token) window.location.href = '/';
        const userId = localStorage.getItem('user_id');

        async function loadData() {
            // Profile
            const uRes = await fetch(`/api/user/${userId}`, {headers: {'Authorization': `Bearer ${token}`}});
            const user = await uRes.json();
            document.getElementById('userEmail').innerText = user.email;
            document.getElementById('rfidToken').innerText = user.rfid_token;

            // Sessions
            const sRes = await fetch('/api/charging/history', {headers: {'Authorization': `Bearer ${token}`}});
            const sessions = await sRes.json();
            const list = document.getElementById('sessions');
            list.innerHTML = '';
            sessions.slice(0, 5).forEach(s => {
                if (s.status === 'active' || s.status === 'pending') {
                    list.innerHTML += `<div style="padding:10px; background:rgba(0,0,0,0.3); margin:5px 0; border-radius:5px;">
                        Station: <b>${s.station_id}</b> | ID: ${s.id} 
                        <button class="btn-stop" onclick="stopCharging(${s.id}, '${s.station_id}')">STOP</button>
                    </div>`;
                }
            });
            if (list.innerHTML === '') list.innerHTML = '<p>No active sessions</p>';
        }

        async function startCharging() {
            const station = document.getElementById('stationSelect').value;
            const log = document.getElementById('debugLog');
            log.innerText = "Sending request to " + station + "...";
            
            try {
                const res = await fetch('/api/charging/start', {
                    method: 'POST',
                    headers: {'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json'},
                    body: JSON.stringify({station_id: station, connector_id: 1})
                });
                const data = await res.json();
                
                log.innerText = JSON.stringify(data, null, 2);
                
                if(res.ok) {
                    alert('Command Sent!');
                    loadData();
                } else {
                    alert('Error: ' + (data.error || 'Check debug log'));
                }
            } catch(e) { log.innerText = "Error: " + e; }
        }

        async function stopCharging(sessionId, stationId) {
            if(!confirm("Stop charging?")) return;
            const log = document.getElementById('debugLog');
            log.innerText = "Stopping...";
            try {
                const res = await fetch('/api/charging/stop', {
                    method: 'POST',
                    headers: {'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json'},
                    body: JSON.stringify({session_id: sessionId, station_id: stationId})
                });
                const data = await res.json();
                
                log.innerText = JSON.stringify(data, null, 2);
                
                if(res.ok) {
                    if (data.warning) {
                        alert("Session closed locally, BUT remote error: " + data.warning);
                    } else {
                        alert("Charging stopped successfully!");
                    }
                    loadData(); 
                } else {
                    alert("Error: " + data.error);
                }
            } catch(e) { 
                log.innerText = "JS Error: " + e; 
                alert("JS Error: " + e);
            }
        }

        loadData();
    </script>
</body>
</html>
"""

# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/')
def index(): return render_template_string(INDEX_HTML)

@app.route('/dashboard')
def dashboard(): return render_template_string(DASHBOARD_HTML)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email'), password_hash=hash_password(data.get('password'))).first()
    if not user: return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'token': create_token(user.id, user.role), 'user_id': user.id, 'role': user.role})

@app.route('/api/user/<int:user_id>')
@token_required
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({'email': user.email, 'rfid_token': user.rfid_token})

@app.route('/api/charging/history')
@token_required
def history():
    sessions = ChargingSession.query.filter_by(user_id=request.user_id).order_by(ChargingSession.start_time.desc()).all()
    return jsonify([{'id': s.id, 'station_id': s.station_id, 'status': s.status} for s in sessions])

# =============================================================================
# HELPER: Get Real Transaction ID from CitrineOS DB
# =============================================================================
def get_citrine_transaction_id(station_id):
    """
    Запитує у CitrineOS через GraphQL реальний transactionId останньої сесії.
    """
    try:
        query = """
        query GetLastTransaction($stationId: String!) {
            transactions(
                where: {
                    stationId: {_eq: $stationId}
                }, 
                order_by: {createdAt: desc}, 
                limit: 1
            ) {
                transactionId
                isActive
                evseId
            }
        }
        """
        response = requests.post(
            CITRINE_GRAPHQL,
            json={
                'query': query,
                'variables': {'stationId': station_id}
            },
            headers={'x-hasura-admin-secret': HASURA_ADMIN_SECRET},
            timeout=5
        )
        data = response.json()
        print(f"[DEBUG] GraphQL Response: {json.dumps(data)}")
        transactions = data.get('data', {}).get('transactions', [])
        if transactions:
            return transactions[0]['transactionId']
    except Exception as e:
        print(f"[ERROR] Failed to fetch transaction ID via GraphQL: {e}")
    return None

# =============================================================================
# START CHARGING (FIXED)
# =============================================================================
@app.route('/api/charging/start', methods=['POST'])
@token_required
def start_charging():
    data = request.json
    station_id = data.get('station_id')
    user = User.query.get(request.user_id)
    
    try:
        connector_id = int(data.get('connector_id', 1))
    except:
        connector_id = 1

    remote_start_id = random.randint(10000, 99999)

    # === ВИПРАВЛЕННЯ: Створюємо сесію тут, щоб уникнути NameError ===
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
    # ================================================================

    try:
        if station_id and ('cp' in station_id.lower() or '002' in station_id):
            # === OCPP 2.0.1 (CP002) ===
            endpoint = f"{CITRINE_API}/ocpp/2.0.1/evdriver/requestStartTransaction"
            
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
            
            response = requests.post(
                endpoint,
                params={'identifier': station_id},
                json=payload,
                timeout=10
            )
            
        else:
            # === OCPP 1.6 ===
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

# =============================================================================
# STOP CHARGING (FIXED & ROBUST)
# =============================================================================
@app.route('/api/charging/stop', methods=['POST'])
@token_required
def stop_charging():
    data = request.json
    sid = data.get('session_id')
    station_id = data.get('station_id')
    
    sess = ChargingSession.query.get(sid)
    if not sess: return jsonify({'error': 'Session not found'}), 404
    
    if sess.user_id != request.user_id and request.user_role != 'admin':
        return jsonify({'error': 'Not authorized'}), 403

    print(f"\n[DEBUG] Stopping session {sid} on {station_id}")
    warning = None

    try:
        if station_id and ('cp' in station_id.lower() or '002' in station_id):
            # 1. Отримуємо реальний UUID через GraphQL
            real_transaction_id = get_citrine_transaction_id(station_id)
            
            if not real_transaction_id:
                print("[WARN] Could not find transaction in CitrineDB. Using local fallback.")
                real_transaction_id = sess.transaction_id 
            else:
                print(f"[DEBUG] Found REAL Transaction ID: {real_transaction_id}")

            # 2. Відправляємо запит
            endpoint = f"{CITRINE_API}/ocpp/2.0.1/evdriver/requestStopTransaction"
            payload = {
                'stationId': str(station_id),
                'transactionId': str(real_transaction_id)
            }
            
            print(f"[DEBUG] Sending Stop Payload: {json.dumps(payload)}")
            
            r = requests.post(
                endpoint,
                params={'identifier': station_id},
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            try:
                response_json = r.json()
            except:
                response_json = {} # Якщо відповідь не JSON

            print(f"[DEBUG] Citrine Response: {json.dumps(response_json)}")
            
            # === ВИПРАВЛЕННЯ ТУТ ===
            # Якщо API повертає список [{}], беремо перший елемент
            response_data = {}
            if isinstance(response_json, list):
                if len(response_json) > 0:
                    response_data = response_json[0]
            elif isinstance(response_json, dict):
                response_data = response_json
            
            # Тепер безпечно використовуємо .get() на словнику response_data
            if r.ok and response_data.get('status') == 'Rejected':
                warning = f"Station Rejected stop. (Sent ID: {real_transaction_id})"
            elif not r.ok:
                warning = f"Network error: {r.text}"

    except Exception as e: 
        import traceback
        traceback.print_exc() # Друкуємо повний стек помилки в консоль для дебагу
        print(f"Stop error: {e}")
        warning = str(e)

    # === ЛОКАЛЬНЕ ЗАВЕРШЕННЯ (Примусове) ===
    sess.status = 'completed'
    sess.end_time = datetime.utcnow()
    sess.energy_kwh = round(random.uniform(5.0, 50.0), 2)
    sess.cost = round(sess.energy_kwh * 4.0, 2)
    db.session.commit()
    
    response_payload = {
        'message': 'Session stopped',
        'session': {'id': sess.id, 'status': 'completed'}
    }
    if warning: response_payload['warning'] = warning
        
    return jsonify(response_payload)

# =============================================================================
# INIT DB
# =============================================================================
def init_db():
    db.create_all()
    if not User.query.filter_by(email='admin@ecocharge.local').first():
        admin = User(
            email='admin@ecocharge.local', 
            password_hash=hash_password('admin123'), 
            role='admin', 
            rfid_token='ABC12345'
        )
        db.session.add(admin)
        if not Station.query.filter_by(station_id='CP002').first():
            db.session.add(Station(station_id='CP002', location='Kyiv Podil', status='online'))
        db.session.commit()
        print("[+] Database Initialized.")

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=80, debug=True)