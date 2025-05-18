import json
import os
from datetime import datetime
import ipaddress

class HoneypotLogger:
    def __init__(self, log_dir="../logs"):
        self.log_dir = log_dir
        # Ensure log directory exists
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Default log file
        self.log_file = os.path.join(log_dir, "honeypot.json")
        
        # Create log file if it doesn't exist
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as f:
                json.dump([], f)
    
    def _load_logs(self):
        """Load existing logs from file"""
        try:
            with open(self.log_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    
    def _save_logs(self, logs):
        """Save logs to file"""
        with open(self.log_file, "w") as f:
            json.dump(logs, f, indent=2)
    
    def log_attempt(self, ip, port, attempt_type, username=None, password=None, data=None, raw_data=None):
        """Log a honeypot access attempt"""
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            ip = "0.0.0.0"  # Use a placeholder for invalid IPs
        
        # Create log entry
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "port": port,
            "type": attempt_type
        }
        
        # Add optional fields if provided
        if username:
            log_entry["username"] = username
        if password:
            log_entry["password"] = password
        if data:
            log_entry["data"] = data
        if raw_data:
            log_entry["raw_data"] = raw_data
            
        # Load existing logs, add new entry, and save
        logs = self._load_logs()
        logs.append(log_entry)
        self._save_logs(logs)
        
        return log_entry
    
    def log_login_attempt(self, ip, port, username, password, service="web"):
        """Log a login attempt (web or SSH)"""
        attempt_type = "ssh_login_attempt" if service == "ssh" else "login_attempt"
        return self.log_attempt(
            ip=ip,
            port=port,
            attempt_type=attempt_type,
            username=username,
            password=password
        )
    
    def log_access(self, ip, port, data=None, raw_data=None):
        """Log a general access attempt"""
        return self.log_attempt(
            ip=ip,
            port=port,
            attempt_type="access",
            data=data,
            raw_data=raw_data
        )