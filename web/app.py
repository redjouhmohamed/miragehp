from flask import Flask, render_template, jsonify, request
import os
import json
from datetime import datetime

# Import configuration first
try:
    from config import CONFIG
except ImportError:
    # Default configuration if config.py is not found
    CONFIG = {
        'LOG_DIR': os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs"),
        'HONEYPOT_HOST': "0.0.0.0",
        'HONEYPOT_PORT': 8080,
        'WEB_HOST': "0.0.0.0",
        'WEB_PORT': 5000,
        'DEBUG': True,
    }

# Use configuration
LOG_DIR = CONFIG['LOG_DIR']
HONEYPOT_HOST = CONFIG['HONEYPOT_HOST']
HONEYPOT_PORT = CONFIG['HONEYPOT_PORT']

# Fix the import based on your environment
try:
    from web.logger import HoneypotLogger  # For Windows development
except ImportError:
    from logger import HoneypotLogger  # For Linux deployment

app = Flask(__name__)

# Initialize the logger with the correct LOG_DIR
logger = HoneypotLogger(LOG_DIR)

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
    # Create an initial empty log file
    with open(os.path.join(LOG_DIR, "honeypot.json"), "w") as f:
        json.dump([], f)

@app.route("/")
def dashboard():
    return render_template("dashboard.html", 
                         honeypot_host=HONEYPOT_HOST,
                         honeypot_port=HONEYPOT_PORT)

@app.route("/logs")
def logs():
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    all_logs = []
    for log_file in log_files:
        with open(os.path.join(LOG_DIR, log_file), "r") as f:
            logs = json.load(f)
            all_logs.extend(logs)
    return render_template("logs.html", logs=all_logs)

@app.route("/settings")
def settings():
    return render_template("settings.html")

@app.route("/api/logs")  # This is correct
def api_logs():
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    all_logs = []
    for log_file in log_files:
        with open(os.path.join(LOG_DIR, log_file), "r") as f:
            logs = json.load(f)
            all_logs.extend(logs)
    return jsonify(all_logs)

@app.route("/api/settings", methods=["POST"])
def api_settings():
    data = request.get_json()
    # Update configuration (e.g., write to config.py or a database)
    print(f"Updated settings: {data}")
    return jsonify({"status": "success"}), 200

@app.route("/honeypot")
def honeypot_monitor():
    return render_template("honeypot.html", 
                         honeypot_host=HONEYPOT_HOST,
                         honeypot_port=HONEYPOT_PORT)

@app.route("/api/honeypot/activity")
def honeypot_activity():
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    all_logs = []
    for log_file in log_files:
        with open(os.path.join(LOG_DIR, log_file), "r") as f:
            logs = json.load(f)
            all_logs.extend(logs)
    
    # Sort by timestamp in descending order and get the latest 20 entries
    all_logs.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify(all_logs[:20])

@app.route("/api/honeypot/login-attempts")
def honeypot_login_attempts():
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    login_attempts = []
    
    for log_file in log_files:
        with open(os.path.join(LOG_DIR, log_file), "r") as f:
            logs = json.load(f)
            # Filter for login attempts (include both regular and SSH login attempts)
            attempts = [log for log in logs if log.get('type') in ['login_attempt', 'ssh_login_attempt']]
            login_attempts.extend(attempts)
    
    # Sort by timestamp in descending order and get the latest 10 entries
    login_attempts.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify(login_attempts[:10])

@app.route("/api/honeypot/web-login-attempts")
def web_login_attempts():
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    login_attempts = []
    
    for log_file in log_files:
        with open(os.path.join(LOG_DIR, log_file), "r") as f:
            logs = json.load(f)
            # Filter for web login attempts only
            attempts = [log for log in logs if log.get('type') == 'login_attempt']
            login_attempts.extend(attempts)
    
    # Sort by timestamp in descending order and get the latest 10 entries
    login_attempts.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify(login_attempts[:10])

@app.route("/api/honeypot/ssh-login-attempts")
def ssh_login_attempts():
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    login_attempts = []
    
    for log_file in log_files:
        with open(os.path.join(LOG_DIR, log_file), "r") as f:
            logs = json.load(f)
            # Filter for SSH login attempts only
            attempts = [log for log in logs if log.get('type') == 'ssh_login_attempt']
            login_attempts.extend(attempts)
    
    # Sort by timestamp in descending order and get the latest 10 entries
    login_attempts.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify(login_attempts[:10])

# Add a new endpoint to log attempts directly from the honeypot
@app.route("/api/log", methods=["POST"])
def log_attempt():
    data = request.get_json()
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    # Extract required fields
    ip = data.get("ip", request.remote_addr)
    port = data.get("port", 0)
    attempt_type = data.get("type", "access")
    
    # Extract optional fields
    username = data.get("username")
    password = data.get("password")
    raw_data = data.get("raw_data")
    
    # Log the attempt
    log_entry = logger.log_attempt(
        ip=ip,
        port=port,
        attempt_type=attempt_type,
        username=username,
        password=password,
        raw_data=raw_data
    )
    
    return jsonify({"status": "success", "log": log_entry}), 200

if __name__ == "__main__":
    app.run(host=CONFIG['WEB_HOST'], port=CONFIG['WEB_PORT'], debug=CONFIG['DEBUG'])