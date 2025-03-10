import asyncio
import socket
import json
import time
from typing import Dict, Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os
from dotenv import load_dotenv
import zlib
import threading
from datetime import datetime, timedelta
import ipaddress
import subprocess
import csv
import hashlib
from pathlib import Path

class SPAServer:
    def __init__(self, tcp_port: int, udp_port: int):
        # Load environment variables
        load_dotenv()
        
        # Server configuration
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.host = '0.0.0.0'  # Listen on all interfaces
        
        # Encryption configuration
        self.key = self.load_encryption_key()
        self.block_size = 16
        
        # Session management
        self.pending_auth = {}  # {client_ip: {'timestamp': float, 'symmetric_key': bytes, 'username': str}}
        self.authenticated_ips = set()
        self.auth_timeout = 15  # seconds
        
        # Socket setup
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Setup cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions, daemon=True)
        
        # Firewall configuration
        self.firewall_rules = {}  # {client_ip: expiration_time}
        
        # Load fingerprint database
        self.fingerprint_db = self.load_fingerprint_db()

    def load_encryption_key(self) -> bytes:
        """Load the Rijndael key from environment."""
        env_key = os.getenv('RIJNDAEL_KEY')
        if not env_key:
            raise ValueError("RIJNDAEL_KEY not found in environment variables")
        return base64.b64decode(env_key)

    def decrypt_message(self, encrypted_data: bytes, iv: bytes) -> bytes:
        """Decrypt message using Rijndael (AES) algorithm."""
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(encrypted_data)
        return unpad(padded_data, self.block_size)

    def decompress_data(self, data: bytes) -> bytes:
        """Decompress received data."""
        return zlib.decompress(data)

    def load_fingerprint_db(self) -> Dict[str, str]:
        """Load fingerprint hashes from CSV database."""
        db_path = Path(__file__).parent / 'data' / 'fingerprint_db.csv'
        fingerprint_db = {}
        
        try:
            if not db_path.exists():
                print(f"Warning: Fingerprint database not found at {db_path}")
                return {}
                
            with open(db_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    fingerprint_db[row['username']] = row['fingerprint_hash']
            
            print(f"Loaded {len(fingerprint_db)} fingerprint records")
            return fingerprint_db
            
        except Exception as e:
            print(f"Error loading fingerprint database: {e}")
            return {}

    def hash_fingerprint(self, fingerprint_data: bytes) -> str:
        """Generate hash of fingerprint data."""
        return hashlib.sha256(fingerprint_data).hexdigest()

    def verify_fingerprint(self, fingerprint_data: bytes, username: str) -> bool:
        """Verify fingerprint against database."""
        try:
            # Get stored hash for username
            stored_hash = self.fingerprint_db.get(username)
            if not stored_hash:
                print(f"No fingerprint hash found for user: {username}")
                return False
            
            # Generate hash of provided fingerprint
            provided_hash = self.hash_fingerprint(fingerprint_data)
            
            # Compare hashes
            if provided_hash == stored_hash:
                print(f"Fingerprint verified for user: {username}")
                return True
            else:
                print(f"Fingerprint verification failed for user: {username}")
                return False
                
        except Exception as e:
            print(f"Error during fingerprint verification: {e}")
            return False

    def update_firewall(self, client_ip: str, allow: bool = True):
        """Update firewall rules for client IP."""
        try:
            if allow:
                # Add firewall rule to allow client IP
                cmd = f'netsh advfirewall firewall add rule name="SPA_{client_ip}" dir=in action=allow remoteip={client_ip}'
                self.firewall_rules[client_ip] = datetime.now() + timedelta(hours=1)
            else:
                # Remove firewall rule
                cmd = f'netsh advfirewall firewall delete rule name="SPA_{client_ip}"'
                self.firewall_rules.pop(client_ip, None)
            
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error updating firewall: {e}")

    def _cleanup_expired_sessions(self):
        """Cleanup expired authentication sessions and firewall rules."""
        while True:
            current_time = time.time()
            # Cleanup pending authentications
            expired_auths = [
                ip for ip, data in self.pending_auth.items()
                if current_time - data['timestamp'] > self.auth_timeout
            ]
            for ip in expired_auths:
                self.pending_auth.pop(ip, None)
                print(f"Expired authentication for {ip}")
                self.update_firewall(ip, allow=False)

            # Cleanup expired firewall rules
            current_datetime = datetime.now()
            expired_rules = [
                ip for ip, expiry in self.firewall_rules.items()
                if current_datetime > expiry
            ]
            for ip in expired_rules:
                self.update_firewall(ip, allow=False)

            time.sleep(1)  # Check every second

    async def handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming TCP connections from Intermediate Server."""
        try:
            client_addr = writer.get_extra_info('peername')
            data = await reader.read(4096)
            
            if not data:
                return

            # Parse received packet
            packet = json.loads(data.decode())
            iv = base64.b64decode(packet['iv'])
            encrypted_data = base64.b64decode(packet['data'])
            
            # Decrypt data
            decrypted_data = self.decrypt_message(encrypted_data, iv)
            session_data = json.loads(decrypted_data.decode())
            
            # Store session information
            client_ip = session_data.get('client_ip')
            username = session_data.get('username')
            
            if client_ip and username:
                self.pending_auth[client_ip] = {
                    'timestamp': time.time(),
                    'symmetric_key': session_data.get('symmetric_key'),
                    'username': username
                }
                
                # Send ACK
                writer.write(b'ACK')
                await writer.drain()
            
        except Exception as e:
            print(f"Error handling TCP connection from {client_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_udp_packet(self):
        """Handle incoming UDP packets from SPA Client."""
        while True:
            try:
                data, addr = await asyncio.get_event_loop().sock_recvfrom(self.udp_socket, 4096)
                client_ip = addr[0]
                
                # Check if we're expecting authentication from this IP
                if client_ip not in self.pending_auth:
                    print(f"Unexpected UDP packet from {client_ip}")
                    continue
                
                auth_data = self.pending_auth[client_ip]
                current_time = time.time()
                
                # Check if authentication hasn't expired
                if current_time - auth_data['timestamp'] <= self.auth_timeout:
                    # Decrypt and decompress data
                    packet = json.loads(data.decode())
                    iv = base64.b64decode(packet['iv'])
                    encrypted_data = base64.b64decode(packet['data'])
                    
                    decrypted_data = self.decrypt_message(encrypted_data, iv)
                    fingerprint_data = self.decompress_data(decrypted_data)
                    
                    # Verify fingerprint with username
                    username = auth_data['username']
                    if self.verify_fingerprint(fingerprint_data, username):
                        # Authentication successful
                        self.authenticated_ips.add(client_ip)
                        self.update_firewall(client_ip, allow=True)
                        
                        # Send success response
                        response = {'status': 'success', 'message': 'Authentication successful'}
                        self.udp_socket.sendto(json.dumps(response).encode(), addr)
                    else:
                        # Authentication failed
                        self.update_firewall(client_ip, allow=False)
                        response = {'status': 'error', 'message': 'Authentication failed'}
                        self.udp_socket.sendto(json.dumps(response).encode(), addr)
                
                # Cleanup used authentication data
                self.pending_auth.pop(client_ip, None)
                
            except Exception as e:
                print(f"Error handling UDP packet: {e}")

    async def start(self):
        """Start the SPA server."""
        # Bind sockets
        self.tcp_socket.bind((self.host, self.tcp_port))
        self.tcp_socket.listen(5)
        self.udp_socket.bind((self.host, self.udp_port))
        
        # Start cleanup thread
        self.cleanup_thread.start()
        
        # Create TCP server
        server = await asyncio.start_server(
            self.handle_tcp_connection,
            self.host,
            self.tcp_port
        )
        
        print(f"SPA Server listening on TCP port {self.tcp_port} and UDP port {self.udp_port}")
        
        # Run TCP and UDP handlers
        async with server:
            await asyncio.gather(
                server.serve_forever(),
                self.handle_udp_packet()
            )

    async def shutdown(self):
        """Cleanup resources."""
        # Remove all firewall rules
        for ip in list(self.firewall_rules.keys()):
            self.update_firewall(ip, allow=False)
        
        self.tcp_socket.close()
        self.udp_socket.close()

if __name__ == "__main__":
    # Example usage
    TCP_PORT = 54321
    UDP_PORT = 54322
    
    server = SPAServer(TCP_PORT, UDP_PORT)
    
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nShutting down server...")
        asyncio.run(server.shutdown()) 