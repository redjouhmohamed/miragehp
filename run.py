import threading
from honeypot.honeypot import Honeypot
from honeypot.ssh_honeypot import SSHHoneypot
from web.app import app
from config import HONEYPOT_HOST, HONEYPOT_PORT, WEB_APP_HOST, WEB_APP_PORT

def start_honeypot():
    honeypot = Honeypot(host=HONEYPOT_HOST, port=HONEYPOT_PORT)
    honeypot.start()

def start_ssh_honeypot():
    # Using port 2222 to avoid requiring admin privileges
    ssh_honeypot = SSHHoneypot(host=HONEYPOT_HOST, port=2222)
    ssh_honeypot.start()

def start_web_app():
    app.run(host=WEB_APP_HOST, port=WEB_APP_PORT)

if __name__ == "__main__":
    # Start HTTP honeypot in a thread
    threading.Thread(target=start_honeypot, daemon=True).start()
    
    # Start SSH honeypot in a thread
    threading.Thread(target=start_ssh_honeypot, daemon=True).start()
    
    # Start web app in main thread
    start_web_app()