import asyncio
import socket
import json
import time
from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os
from dotenv import load_dotenv

class IntermediateServer:
    def __init__(self, listen_host: str, listen_port: int, spa_server_host: str, spa_server_port: int):
        # Load environment variables
        load_dotenv()
        
        # Server configuration
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.spa_server_host = spa_server_host
        self.spa_server_port = spa_server_port
        
        # Encryption configuration
        self.key = self.get_or_generate_key()
        self.block_size = 16
        
        # Socket setup
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.spa_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def get_or_generate_key(self) -> bytes:
        """Get existing key from environment or generate a new one."""
        env_key = os.getenv('RIJNDAEL_KEY')
        
        if env_key:
            try:
                return base64.b64decode(env_key)
            except Exception as e:
                print(f"Error decoding existing key: {e}")
                print("Generating new key...")
        
        # Generate new key
        new_key = get_random_bytes(32)  # 256-bit key for AES-256
        encoded_key = base64.b64encode(new_key).decode()
        
        # Update .env file with the new key
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
        env_template_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env.template')
        
        try:
            # If .env doesn't exist, create from template
            if not os.path.exists(env_path) and os.path.exists(env_template_path):
                with open(env_template_path, 'r') as template, open(env_path, 'w') as env_file:
                    for line in template:
                        if line.startswith('RIJNDAEL_KEY='):
                            env_file.write(f'RIJNDAEL_KEY={encoded_key}\n')
                        else:
                            env_file.write(line)
            else:
                # Update existing .env file
                if os.path.exists(env_path):
                    with open(env_path, 'r') as env_file:
                        lines = env_file.readlines()
                    
                    with open(env_path, 'w') as env_file:
                        key_updated = False
                        for line in lines:
                            if line.startswith('RIJNDAEL_KEY='):
                                env_file.write(f'RIJNDAEL_KEY={encoded_key}\n')
                                key_updated = True
                            else:
                                env_file.write(line)
                        if not key_updated:
                            env_file.write(f'\nRIJNDEAL_KEY={encoded_key}\n')
                else:
                    # Create new .env file with just the key
                    with open(env_path, 'w') as env_file:
                        env_file.write(f'RIJNDAEL_KEY={encoded_key}\n')
            
            print(f"Generated new Rijndael key and saved to {env_path}")
            return new_key
            
        except Exception as e:
            print(f"Error saving key to .env file: {e}")
            print("WARNING: Using temporary key - will be regenerated on next startup!")
            return new_key

    def encrypt_message(self, message: bytes) -> Tuple[bytes, bytes]:
        """Encrypt message using Rijndael (AES) algorithm."""
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(message, self.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data, iv

    def decrypt_message(self, encrypted_data: bytes, iv: bytes) -> bytes:
        """Decrypt message using Rijndael (AES) algorithm."""
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(encrypted_data)
        return unpad(padded_data, self.block_size)

    async def forward_to_spa_server(self, data: dict) -> bool:
        """Forward modified packet to SPA server and wait for ACK."""
        try:
            # Modify timestamp
            data['timestamp'] = data['timestamp'] + 15
            
            # Encrypt modified data
            json_data = json.dumps(data).encode()
            encrypted_data, iv = self.encrypt_message(json_data)
            
            # Prepare packet with IV
            packet = {
                'iv': base64.b64encode(iv).decode(),
                'data': base64.b64encode(encrypted_data).decode()
            }
            
            # Connect to SPA server
            self.spa_socket.connect((self.spa_server_host, self.spa_server_port))
            self.spa_socket.send(json.dumps(packet).encode())
            
            # Wait for ACK
            response = self.spa_socket.recv(1024)
            return response == b'ACK'
        except Exception as e:
            print(f"Error forwarding to SPA server: {e}")
            return False
        finally:
            self.spa_socket.close()

    async def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle incoming client connections."""
        try:
            # Receive encrypted data from client
            raw_data = client_socket.recv(4096)
            if not raw_data:
                return

            # Parse received packet
            packet = json.loads(raw_data.decode())
            iv = base64.b64decode(packet['iv'])
            encrypted_data = base64.b64decode(packet['data'])
            
            # Decrypt data
            decrypted_data = self.decrypt_message(encrypted_data, iv)
            data = json.loads(decrypted_data.decode())
            
            # Forward to SPA server
            success = await self.forward_to_spa_server(data)
            
            # Send ACK to client if successful
            if success:
                client_socket.send(b'ACK')
            else:
                client_socket.send(b'NACK')
                
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    async def start(self):
        """Start the intermediate server."""
        self.tcp_socket.bind((self.listen_host, self.listen_port))
        self.tcp_socket.listen(5)
        print(f"Intermediate server listening on {self.listen_host}:{self.listen_port}")
        
        while True:
            client_socket, address = await asyncio.get_event_loop().sock_accept(self.tcp_socket)
            print(f"Accepted connection from {address}")
            asyncio.create_task(self.handle_client(client_socket, address))

    async def shutdown(self):
        """Cleanup resources."""
        self.tcp_socket.close()
        self.spa_socket.close()

if __name__ == "__main__":
    # Example usage
    LISTEN_HOST = "0.0.0.0"
    LISTEN_PORT = 12345
    SPA_SERVER_HOST = "localhost"  # Replace with actual SPA server address
    SPA_SERVER_PORT = 54321        # Replace with actual SPA server port
    
    server = IntermediateServer(LISTEN_HOST, LISTEN_PORT, SPA_SERVER_HOST, SPA_SERVER_PORT)
    
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nShutting down server...")
        asyncio.run(server.shutdown()) 