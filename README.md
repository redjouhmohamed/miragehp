## Features
- HTTP Honeypot : Simulates a web server with a fake login page to capture web-based attack attempts
- SSH Honeypot : Simulates an SSH server to capture SSH login attempts and commands
- Web Dashboard : Provides real-time monitoring and visualization of attack attempts
- Logging System : Records all access attempts with detailed information including IP, timestamp, credentials, etc.
- Configurable : Easy to configure through environment variables or configuration files
## Requirements
Here's the content for your requirements.txt file:

## Installation
1. Clone the repository:
2. Install dependencies:
3. Run the setup script:
## Usage
1. Start the honeypot system:
2. Access the web dashboard at http://localhost:5000 (port 5000 is for develpment and tests only you may consider changing it).
3. The honeypot services will be running at:
   
   - HTTP Honeypot: Port 80 (requires admin privileges) or configured port
   - SSH Honeypot: Port 2222 
## Configuration
You can configure the honeypot by editing config.py or setting environment variables:

- HONEYPOT_HOST : IP address to bind the honeypot (default: 0.0.0.0)
- HONEYPOT_PORT : Port for the TCP honeypot (default: 8080)
- HONEYPOT_LOG_DIR : Directory for storing logs (default: ./logs)
- HONEYPOT_WEB_HOST : IP address for the web dashboard (default: 0.0.0.0)
- HONEYPOT_WEB_PORT : Port for the web dashboard (default: 5000)
## Dashboard
The web dashboard provides:

- Real-time monitoring of attack attempts
- Statistics on attack types, sources, and credentials
- Detailed logs with filtering capabilities
- Settings configuration
## Security Considerations
- This honeypot is designed for research and educational purposes
- Do not deploy on production systems without proper isolation
- Consider running in a dedicated VM or container
- The web interface should be properly secured if exposed to the internet


## Disclaimer
This tool is provided for educational and research purposes only. Users are responsible for complying with applicable laws and regulations when using this software.
