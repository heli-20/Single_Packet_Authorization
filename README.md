# Secure Single Packet Authorization (SPA) System

A secure authentication system implementing Single Packet Authorization with biometric verification and Rijndael encryption.

## Project Structure
```
spa_system/
├── src/
│   ├── spa_client.py        # Client implementation
│   ├── intermediate_server.py # Intermediate server implementation
│   └── spa_server.py        # SPA server implementation (to be implemented)
├── .env                     # Configuration file (create from .env.template)
├── .env.template           # Template for configuration
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Features
- Single Packet Authorization (SPA) implementation
- Rijndael (AES) encryption for secure communication
- Biometric authentication using Windows Hello
- Timestamp-based replay attack prevention
- Intermediate server for additional security layer

## Security Features
1. **Pre-shared Key Encryption**: Rijndael (AES) encryption for all communications
2. **Timestamp Validation**: Prevents replay attacks
3. **Biometric Authentication**: Windows Hello integration
4. **Network Segmentation**: Three-tier architecture
5. **Packet Size Limitation**: Maximum 700 bytes for UDP packets

## Prerequisites
- Python 3.8 or later
- Windows 10 or later (for Windows Hello biometric support)
- Virtual environment (recommended)

## Installation

1. Clone the repository:
```bash
git clone <repository_url>
cd spa_system
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create configuration:
```bash
cp .env.template .env
```

5. Generate Rijndael key and update .env:
```bash
python -c "from Crypto.Random import get_random_bytes; import base64; print(base64.b64encode(get_random_bytes(32)).decode())"
```
Copy the output and set it as RIJNDAEL_KEY in .env

## Running the System

1. Start the SPA Server:
```bash
python src/spa_server.py
```

2. Start the Intermediate Server:
```bash
python src/intermediate_server.py
```

3. Run the SPA Client:
```bash
python src/spa_client.py
```

## Network Configuration

### SPA Client
- Connects to Intermediate Server
- Uses TCP for initial authentication
- Uses UDP for data transmission

### Intermediate Server
- Listens for client connections
- Forwards authenticated requests to SPA Server
- Modifies timestamps for security

### SPA Server
- Hidden from public network
- Processes authenticated requests
- Sends acknowledgments through Intermediate Server

## Security Considerations
1. Keep the Rijndael key secure and never share it
2. Use different networks for each component
3. Implement proper firewall rules
4. Monitor system logs for suspicious activity
5. Regularly update security configurations

## Contributing
Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the LICENSE file for more details.
