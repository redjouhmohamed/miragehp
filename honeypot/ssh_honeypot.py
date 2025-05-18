import socket
import threading
import paramiko
import logging
import os
import time
from datetime import datetime, timedelta  # Import timedelta directly
import sys

# Add the parent directory to the path to import utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from honeypot.utils import save_log
except ImportError:
    from utils import save_log

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.client_address = client_address
        self.event = threading.Event()
        self.username = None
        self.password = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Log the authentication attempt
        self.username = username
        self.password = password
        
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": self.client_address[0],
            "port": self.client_address[1],
            "type": "ssh_login_attempt",
            "username": username,
            "password": password,
            "protocol": "SSH"
        }
        
        save_log(log_entry)
        logging.info(f"SSH login attempt from {self.client_address[0]}: username='{username}', password='{password}'")
        
        # Always return success - this is a honeypot
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        # Log the command execution attempt
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": self.client_address[0],
            "port": self.client_address[1],
            "type": "ssh_command",
            "username": self.username,
            "password": self.password,
            "command": command.decode('utf-8'),
            "protocol": "SSH"
        }
        
        save_log(log_entry)
        logging.info(f"SSH command from {self.client_address[0]}: '{command.decode('utf-8')}'")
        
        # Simulate command execution
        channel.send(f"Command '{command.decode('utf-8')}' executed.\r\n")
        channel.send("$ ")
        return True

class SSHHoneypot:
    def __init__(self, host="0.0.0.0", port=2222):
        self.host = host
        self.port = port
        
        # Create SSH key if it doesn't exist
        key_path = os.path.join(os.path.dirname(__file__), 'ssh_key')
        if not os.path.exists(key_path):
            logging.info("Generating new SSH host key...")
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(key_path)
            logging.info(f"SSH host key generated and saved to {key_path}")
            self.host_key = key
        else:
            self.host_key = paramiko.RSAKey(filename=key_path)

    def start(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            logging.info(f"SSH Honeypot listening on {self.host}:{self.port}")
            
            while True:
                client, addr = server_socket.accept()
                logging.info(f"SSH Connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client, addr)).start()
                
        except Exception as e:
            logging.error(f"Error starting SSH honeypot: {e}")
        finally:
            server_socket.close()

    def handle_client(self, client_socket, client_address):
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            server_handler = SSHServer(client_address)
            transport.start_server(server=server_handler)
            
            channel = transport.accept(20)
            if channel is None:
                logging.info(f"No channel established with {client_address}")
                return
            
            server_handler.event.wait(10)
            
            # Create a fake environment
            hostname = "prod-server"
            username = server_handler.username or "user"
            
            # Send a welcome message
            channel.send(f"\r\nWelcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-146-generic x86_64)\r\n\r\n")
            channel.send(f" * Documentation:  https://help.ubuntu.com\r\n")
            channel.send(f" * Management:     https://landscape.canonical.com\r\n")
            channel.send(f" * Support:        https://ubuntu.com/advantage\r\n\r\n")
            channel.send(f"  System information as of {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}\r\n\r\n")
            channel.send(f"  System load:  0.08              Processes:             128\r\n")
            channel.send(f"  Usage of /:   42.6% of 30.88GB   Users logged in:       1\r\n")
            channel.send(f"  Memory usage: 38%                IPv4 address for eth0: 10.0.2.15\r\n\r\n")
            channel.send(f"Last login: {(datetime.now() - timedelta(days=2)).strftime('%a %b %d %H:%M:%S %Y')} from 192.168.1.5\r\n")
            channel.send(f"{username}@{hostname}:~$ ")
            
            # Handle commands
            buffer = ""
            while True:
                data = channel.recv(1024)
                if not data:
                    break
                
                # Convert to text and handle special characters
                text = data.decode('utf-8')
                for char in text:
                    if char == '\r' or char == '\n':
                        command = buffer.strip()
                        if command:
                            # Log the command
                            log_entry = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "ip": client_address[0],
                                "port": client_address[1],
                                "type": "ssh_command",
                                "username": server_handler.username,
                                "password": server_handler.password,
                                "command": command,
                                "protocol": "SSH"
                            }
                            
                            save_log(log_entry)
                            logging.info(f"SSH command from {client_address[0]}: '{command}'")
                            
                            # Process commands
                            self.process_command(channel, command, username, hostname)
                        
                        buffer = ""
                        channel.send(f"{username}@{hostname}:~$ ")
                    elif char == '\x03':  # Ctrl+C
                        channel.send("^C\r\n")
                        buffer = ""
                        channel.send(f"{username}@{hostname}:~$ ")
                    elif char == '\x7f' or char == '\x08':  # Backspace
                        if buffer:
                            buffer = buffer[:-1]
                            channel.send("\b \b")  # Move back, erase, move back
                    else:
                        buffer += char
                        channel.send(char)  # Echo the character
            
            channel.close()
            
        except Exception as e:
            logging.error(f"Error handling SSH client {client_address}: {e}")
        finally:
            client_socket.close()
    
    def process_command(self, channel, command, username, hostname):
        """Process and respond to shell commands"""
        cmd = command.lower().strip()
        
        # Exit commands
        if cmd in ['exit', 'logout', 'quit']:
            channel.send("logout\r\n")
            channel.send(f"Connection to {hostname} closed.\r\n")
            return
        
        # Basic commands
        elif cmd == 'whoami':
            channel.send(f"{username}\r\n")
        
        elif cmd == 'hostname':
            channel.send(f"{hostname}\r\n")
        
        elif cmd == 'id':
            channel.send(f"uid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)\r\n")
        
        elif cmd.startswith('cd '):
            # Just acknowledge the cd command
            pass
        
        elif cmd == 'pwd':
            channel.send(f"/home/{username}\r\n")
        
        elif cmd == 'ls' or cmd == 'ls -la' or cmd == 'ls -l':
            channel.send("total 32\r\n")
            channel.send(f"drwxr-xr-x 4 {username} {username} 4096 Apr 18 09:14 .\r\n")
            channel.send(f"drwxr-xr-x 3 root     root     4096 Jan 15 12:32 ..\r\n")
            channel.send(f"-rw------- 1 {username} {username}  220 Jan 15 12:32 .bash_history\r\n")
            channel.send(f"-rw-r--r-- 1 {username} {username} 3771 Jan 15 12:32 .bashrc\r\n")
            channel.send(f"drwx------ 2 {username} {username} 4096 Jan 15 12:34 .cache\r\n")
            channel.send(f"-rw-r--r-- 1 {username} {username}  807 Jan 15 12:32 .profile\r\n")
            channel.send(f"drwxrwxr-x 2 {username} {username} 4096 Apr 18 09:14 .ssh\r\n")
            channel.send(f"-rw-r--r-- 1 {username} {username}    0 Jan 15 12:34 .sudo_as_admin_successful\r\n")
            channel.send(f"-rw------- 1 {username} {username}  945 Apr 18 09:10 .viminfo\r\n")
        
        elif cmd == 'uname -a':
            channel.send("Linux prod-server 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n")
        
        elif cmd == 'ps aux' or cmd == 'ps -ef':
            channel.send(f"USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n")
            channel.send(f"root           1  0.0  0.2 168860 11492 ?        Ss   Apr17   0:04 /sbin/init\r\n")
            channel.send(f"root           2  0.0  0.0      0     0 ?        S    Apr17   0:00 [kthreadd]\r\n")
            channel.send(f"root         546  0.0  0.6  72172 25868 ?        Ss   Apr17   0:00 /usr/sbin/sshd -D\r\n")
            channel.send(f"root         565  0.0  0.3 235520 14120 ?        Ssl  Apr17   0:00 /usr/sbin/rsyslogd -n\r\n")
            channel.send(f"root         566  0.0  0.0   6812  2972 tty1     Ss+  Apr17   0:00 /sbin/agetty -o -p -- \\u --noclear tty1 linux\r\n")
            channel.send(f"{username}      1328  0.0  0.1  19216  5144 pts/0    Ss   09:10   0:00 -bash\r\n")
            channel.send(f"{username}      1392  0.0  0.1  36084  3704 pts/0    R+   09:15   0:00 ps aux\r\n")
        
        elif cmd == 'cat /etc/passwd':
            channel.send("root:x:0:0:root:/root:/bin/bash\r\n")
            channel.send("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n")
            channel.send("bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n")
            channel.send("sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n")
            channel.send(f"{username}:x:1000:1000:{username.capitalize()}:/home/{username}:/bin/bash\r\n")
            channel.send("sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\r\n")
        
        elif cmd == 'ifconfig' or cmd == '/sbin/ifconfig':
            channel.send("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n")
            channel.send("        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\r\n")
            channel.send("        inet6 fe80::a00:27ff:fe73:60cf  prefixlen 64  scopeid 0x20<link>\r\n")
            channel.send("        ether 08:00:27:73:60:cf  txqueuelen 1000  (Ethernet)\r\n")
            channel.send("        RX packets 963  bytes 91521 (91.5 KB)\r\n")
            channel.send("        RX errors 0  dropped 0  overruns 0  frame 0\r\n")
            channel.send("        TX packets 649  bytes 96318 (96.3 KB)\r\n")
            channel.send("        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n")
            channel.send("\r\n")
            channel.send("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n")
            channel.send("        inet 127.0.0.1  netmask 255.0.0.0\r\n")
            channel.send("        inet6 ::1  prefixlen 128  scopeid 0x10<host>\r\n")
            channel.send("        loop  txqueuelen 1000  (Local Loopback)\r\n")
            channel.send("        RX packets 182  bytes 13832 (13.8 KB)\r\n")
            channel.send("        RX errors 0  dropped 0  overruns 0  frame 0\r\n")
            channel.send("        TX packets 182  bytes 13832 (13.8 KB)\r\n")
            channel.send("        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n")
        
        elif cmd.startswith('cat '):
            # Simulate file not found for most files
            filename = cmd[4:].strip()
            if filename in ['/etc/passwd', '/etc/hostname', '/etc/hosts']:
                # These files are handled in their specific commands
                if filename == '/etc/hostname':
                    channel.send(f"{hostname}\r\n")
                elif filename == '/etc/hosts':
                    channel.send("127.0.0.1 localhost\r\n")
                    channel.send(f"127.0.1.1 {hostname}\r\n")
                    channel.send("\r\n")
                    channel.send("# The following lines are desirable for IPv6 capable hosts\r\n")
                    channel.send("::1     ip6-localhost ip6-loopback\r\n")
                    channel.send("fe00::0 ip6-localnet\r\n")
                    channel.send("ff00::0 ip6-mcastprefix\r\n")
                    channel.send("ff02::1 ip6-allnodes\r\n")
                    channel.send("ff02::2 ip6-allrouters\r\n")
            else:
                channel.send(f"cat: {filename}: No such file or directory\r\n")
        
        elif cmd == 'uptime':
            # Generate a random uptime
            days = 15
            hours = 7
            minutes = 23
            channel.send(f" 09:15:27 up {days} days, {hours}:{minutes}, 1 user, load average: 0.00, 0.01, 0.05\r\n")
        
        elif cmd == 'w' or cmd == 'who':
            current_time = datetime.now().strftime('%H:%M:%S')
            channel.send(f" {current_time} up 15 days, 7:23, 1 user, load average: 0.00, 0.01, 0.05\r\n")
            channel.send(f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n")
            channel.send(f"{username}    pts/0    10.0.2.2          09:10    0.00s  0.04s  0.00s w\r\n")
        
        # For any other command, just acknowledge it
        else:
            if cmd:
                if cmd.startswith('sudo '):
                    channel.send(f"[sudo] password for {username}: ")
                    # Wait for a moment to simulate password entry
                    time.sleep(1)
                    channel.send("\r\n")
                    channel.send(f"{username} is not in the sudoers file. This incident will be reported.\r\n")
                else:
                    channel.send(f"bash: {command.split()[0]}: command not found\r\n")

if __name__ == "__main__":
    # Use a non-privileged port for testing
    ssh_honeypot = SSHHoneypot(port=2222)
    ssh_honeypot.start()