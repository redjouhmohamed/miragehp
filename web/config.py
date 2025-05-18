import os

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Configuration settings
CONFIG = {
    # Log directory - can be relative to project or absolute
    'LOG_DIR': os.environ.get('HONEYPOT_LOG_DIR', os.path.join(BASE_DIR, "logs")),
    
    # Honeypot settings
    'HONEYPOT_HOST': os.environ.get('HONEYPOT_HOST', "0.0.0.0"),
    'HONEYPOT_PORT': int(os.environ.get('HONEYPOT_PORT', 8080)),
    
    # Web interface settings
    'WEB_HOST': os.environ.get('HONEYPOT_WEB_HOST', "0.0.0.0"),
    'WEB_PORT': int(os.environ.get('HONEYPOT_WEB_PORT', 5000)),
    'DEBUG': os.environ.get('HONEYPOT_DEBUG', "True").lower() in ('true', '1', 't'),
    
    # Security settings
    'SECRET_KEY': os.environ.get('HONEYPOT_SECRET_KEY', 'default-secret-key-change-in-production'),
}