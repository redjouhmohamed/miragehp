import json
import os
from datetime import datetime

# Use absolute path to ensure logs are saved in a consistent location
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")

def save_log(entry):
    """Save a log entry to a JSON file."""
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, f"{datetime.now().strftime('%Y-%m-%d')}.json")
    
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            # Handle corrupted JSON file
            logs = []
    else:
        logs = []

    logs.append(entry)

    with open(log_file, "w") as f:
        json.dump(logs, f, indent=4)
    
    # Debug output to confirm log was saved
    print(f"Log saved: {entry.get('type', 'access')} from {entry.get('ip', 'unknown')} at {entry['timestamp']}")