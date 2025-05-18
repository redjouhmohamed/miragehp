import socket
import threading
import logging
import os
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
# Change this line
from .utils import save_log  # Changed from 'from utils import save_log'

# To this
try:
    from .utils import save_log
except ImportError:
    from utils import save_log

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class HoneypotHTTPHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            # Update path to point to the honeypot.html in the same directory
            self.path = '/honeypot.html'
        
        try:
            # Get the file extension
            _, ext = os.path.splitext(self.path)
            
            # Set the appropriate content type based on file extension
            content_type = 'text/html'
            if ext == '.css':
                content_type = 'text/css'
            elif ext == '.js':
                content_type = 'text/javascript'
            elif ext == '.png':
                content_type = 'image/png'
            elif ext == '.jpg' or ext == '.jpeg':
                content_type = 'image/jpeg'
            
            # Try to serve the file from the current directory
            current_dir = os.path.dirname(__file__)
            
            # Improved static file handling
            if self.path.startswith('/static/'):
                # For static files, look in the static subdirectory
                static_dir = os.path.join(current_dir, 'static')
                # Get the part of the path after /static/
                file_name = self.path[8:]  # Remove '/static/' prefix
                file_path = os.path.join(static_dir, file_name)
            else:
                # For other files, look directly in the current directory
                file_path = os.path.join(current_dir, self.path[1:])
                
            file_to_open = open(file_path, 'rb')
            self.send_response(200)
            self.send_header('Content-type', content_type)
            self.end_headers()
            self.wfile.write(file_to_open.read())
            file_to_open.close()
            
            # Log the access
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": self.client_address[0],
                "port": self.client_address[1],
                "data": f"HTTP GET {self.path}"
            }
            save_log(log_entry)
            
        except FileNotFoundError:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'File not found')
            logging.error(f"File not found: {self.path}")
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse the form data
        form_data = {}
        for item in post_data.split('&'):
            if '=' in item:
                key, value = item.split('=', 1)
                form_data[key] = value
        
        # Create a more structured log entry
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": self.client_address[0],
            "port": self.client_address[1],
            "type": "login_attempt",
            "path": self.path,
            "username": form_data.get('username', ''),
            "password": form_data.get('password', ''),
            "raw_data": post_data
        }
        
        # Log the attempt
        save_log(log_entry)
        logging.info(f"Login attempt from {self.client_address[0]}: username='{form_data.get('username', '')}', password='{form_data.get('password', '')}'")
        
        # Send a response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Login attempt recorded')

class Honeypot:
    def __init__(self, host="0.0.0.0", port=8080, http_port=80):
        self.host = host
        self.port = port
        self.http_port = http_port

    def start(self):
        # Start the TCP socket server in a separate thread
        tcp_thread = threading.Thread(target=self.start_tcp_server)
        tcp_thread.daemon = True
        tcp_thread.start()
        
        # Start the HTTP server in the main thread
        self.start_http_server()
    
    def start_tcp_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        logging.info(f"TCP Honeypot listening on {self.host}:{self.port}")
        
        while True:
            client, addr = server.accept()
            logging.info(f"TCP Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client, addr)).start()

    def start_http_server(self):
        http_server = HTTPServer((self.host, self.http_port), HoneypotHTTPHandler)
        logging.info(f"HTTP Honeypot listening on {self.host}:{self.http_port}")
        http_server.serve_forever()

    def handle_client(self, client, addr):
        try:
            # Simulate a service response
            client.send(b"Welcome to the service!\n")
            data = client.recv(1024).decode('utf-8')
            logging.info(f"Received data from {addr}: {data}")

            # Log the interaction
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": addr[0],
                "port": addr[1],
                "data": data
            }
            save_log(log_entry)

            # Close the connection
            client.close()
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")

if __name__ == "__main__":
    # Changed HTTP port to 8081
    honeypot = Honeypot(port=8080, http_port=80)
    honeypot.start()