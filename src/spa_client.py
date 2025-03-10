import asyncio
import socket
import json
import time
from typing import Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os
from dotenv import load_dotenv
import zlib
from biometric.windows_hello import get_fingerprint

class SPAClient:
    def __init__(self, intermediate_server_host: str, intermediate_server_port: int):
        # Load environment variables
        load_dotenv()
        
        # Server configuration
        self.intermediate_server_host = intermediate_server_host
        self.intermediate_server_port = intermediate_server_port
        
        # Encryption configuration
        self.key = self.load_encryption_key()
        self.block_size = 16
        
        # Socket setup
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def load_encryption_key(self) -> bytes:
        """Load the Rijndael key from environment."""
        env_key = os.getenv('RIJNDAEL_KEY')
        if not env_key:
            raise ValueError("RIJNDAEL_KEY not found in environment variables")
        return base64.b64decode(env_key)

    def encrypt_message(self, message: bytes) -> Tuple[bytes, bytes]:
        """Encrypt message using Rijndael (AES) algorithm."""
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(message, self.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data, iv

    def compress_data(self, data: bytes) -> bytes:
        """Compress data to ensure it's under 700 bytes."""
        compressed = zlib.compress(data)
        if len(compressed) > 700:
            raise ValueError("Compressed data exceeds 700 bytes limit")
        return compressed

    async def send_tcp_auth_request(self, username: str) -> bool:
        """Send initial TCP authentication request."""
        try:
            # Prepare authentication data
            timestamp = time.time()
            auth_data = {
                'username': username,
                'timestamp': timestamp,
                'client_ip': self.get_local_ip()
            }
            
            # Encrypt data
            json_data = json.dumps(auth_data).encode()
            encrypted_data, iv = self.encrypt_message(json_data)
            
            # Prepare packet
            packet = {
                'iv': base64.b64encode(iv).decode(),
                'data': base64.b64encode(encrypted_data).decode()
            }
            
            # Send to intermediate server
            self.tcp_socket.connect((self.intermediate_server_host, self.intermediate_server_port))
            self.tcp_socket.settimeout(5)  # 5 seconds timeout
            self.tcp_socket.send(json.dumps(packet).encode())
            
            # Wait for ACK
            response = self.tcp_socket.recv(1024)
            return response == b'ACK'
            
        except Exception as e:
            print(f"TCP Authentication error: {e}")
            return False
        finally:
            self.tcp_socket.close()

    def get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            # Create a temporary socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    async def send_fingerprint(self) -> bool:
        """Scan and send fingerprint data."""
        try:
            # Get fingerprint using Windows Hello
            print("Please provide your fingerprint when prompted...")
            fingerprint_data = await get_fingerprint()
            
            if not fingerprint_data:
                print("Failed to get fingerprint")
                return False
            
            # Compress fingerprint data
            compressed_data = self.compress_data(fingerprint_data)
            
            # Encrypt compressed data
            encrypted_data, iv = self.encrypt_message(compressed_data)
            
            # Prepare packet
            packet = {
                'iv': base64.b64encode(iv).decode(),
                'data': base64.b64encode(encrypted_data).decode()
            }
            
            # Send UDP packet
            self.udp_socket.sendto(
                json.dumps(packet).encode(),
                (self.intermediate_server_host, self.intermediate_server_port + 1)  # UDP port is TCP port + 1
            )
            
            # Wait for response
            self.udp_socket.settimeout(15)  # 15 seconds timeout
            response_data, _ = self.udp_socket.recvfrom(1024)
            response = json.loads(response_data.decode())
            
            if response.get('status') == 'success':
                print("Authentication successful!")
                return True
            else:
                print(f"Authentication failed: {response.get('message', 'Unknown error')}")
                return False
            
        except Exception as e:
            print(f"Error sending fingerprint: {e}")
            return False
        finally:
            self.udp_socket.close()

    async def authenticate(self) -> bool:
        """Main authentication flow."""
        try:
            # Get username
            username = input("Enter username: ").strip()
            if not username:
                print("Username cannot be empty")
                return False
            
            # Send TCP authentication request
            print("Sending initial authentication request...")
            if not await self.send_tcp_auth_request(username):
                print("Initial authentication failed")
                return False
            
            # Send fingerprint
            print("Initial authentication successful. Proceeding with fingerprint verification...")
            return await self.send_fingerprint()
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return False

if __name__ == "__main__":
    # Example usage
    INTERMEDIATE_SERVER_HOST = "localhost"  # Replace with actual server address
    INTERMEDIATE_SERVER_PORT = 12345        # Replace with actual server port
    
    client = SPAClient(INTERMEDIATE_SERVER_HOST, INTERMEDIATE_SERVER_PORT)
    
    try:
        asyncio.run(client.authenticate())
    except KeyboardInterrupt:
        print("\nAuthentication cancelled by user") 