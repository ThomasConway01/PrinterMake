# 🔒 PrinterMake Server - Production Deployment

[![Security](https://img.shields.io/badge/Security-Quantum--Resistant-blue.svg)](#)
[![Server](https://img.shields.io/badge/Server-Production-green.svg)](#)
[![Domain](https://img.shields.io/badge/Domain-printermake.online-orange.svg)](#)

> **Production-ready server deployment for printermake.online with quantum-resistant encryption**

## 🚀 Overview

This folder contains the complete **PrinterMake server deployment** for your **printermake.online** domain. It includes quantum-resistant encryption, web interface, and complete server setup.

## 📁 Contents

### Core Components
- **`server.py`** - Main WebSocket server with quantum-resistant encryption
- **`quantum_crypto.py`** - Post-quantum cryptographic implementation
- **`encryption.py`** - Legacy encryption (fallback)
- **`requirements.txt`** - Python dependencies
- **`README.md`** - Server technical documentation

### Web Interface
- **`index.html`** - Modern web interface
- **`styles.css`** - Professional UI styling
- **`script.js`** - Interactive features
- **`demo.js`** - Chat demo functionality

### Installation
- **`LINUX_SERVER_INSTALLATION.md`** - Complete Linux server setup guide

## 🔐 Security Features

### Quantum-Resistant Encryption
- **X25519** - Quantum-resistant key exchange
- **AES-256-GCM** - Symmetric encryption with authentication
- **SHA-3** - Quantum-resistant hashing
- **Perfect Forward Secrecy** - Session-specific keys
- **Zero-Knowledge Architecture** - Server never sees content

### Security Protection
- **Rate Limiting** - DDoS protection (100 requests/minute)
- **IP Blocking** - Automatic and manual protection
- **Input Validation** - SQL injection and XSS prevention
- **Audit Logging** - Complete security event tracking

## 🌐 Domain: printermake.online

This server is configured for deployment to **printermake.online** with:

### Subdomain Strategy
- **printermake.online** - Main website
- **demo.printermake.online** - Interactive demo
- **ws.printermake.online** - WebSocket server
- **api.printermake.online** - REST API

### SSL & Security
- **Let's Encrypt** - Automatic SSL certificate
- **HTTPS Only** - All connections encrypted
- **Security Headers** - XSS, clickjacking, and injection protection
- **Nginx** - Web server and reverse proxy

## 🛠️ Quick Deployment

### For Linux Mint Server
See `LINUX_SERVER_INSTALLATION.md` for complete setup guide.

**Quick Start:**
```bash
# 1. Copy files to your server
scp -r . user@your-server:/home/user/printermake/

# 2. On your server
cd printermake
chmod +x install.sh
sudo ./install.sh

# 3. Access at: https://printermake.online
```

### Prerequisites
- **Linux Mint** (any recent version)
- **Python 3.11+**
- **Port 80, 443, 8765** available
- **Domain configured** for printermake.online

## 📋 Features

### Chat Server
- **WebSocket Communication** - Real-time messaging
- **Room-based Chat** - Organized discussions
- **Direct Messaging** - Private conversations
- **Message History** - Persistent chat logs
- **User Management** - Registration and authentication

### Web Interface
- **Interactive Demo** - Real-time chat simulation
- **Modern Design** - Professional dark theme
- **About Us Section** - Explains privacy philosophy
- **Download Links** - Direct access to clients
- **Responsive Layout** - Desktop and mobile

### Quantum Cryptography
- **Test Suite** - Built-in quantum encryption tests
- **Performance** - Optimized for speed and security
- **Fallbacks** - Works with or without cryptography library
- **Logging** - Complete security event tracking

## 🔍 Testing

### Test Quantum Cryptography
```bash
python quantum_crypto.py
```

**Expected Output:**
```
SUCCESS: All quantum cryptography tests passed!
ENCRYPTION: Message encrypted with: AES-256-GCM
QUANTUM: Quantum-resistant: True
```

### Test Web Interface
1. **Open** `index.html` in your browser
2. **Test** the interactive chat demo
3. **Try** the cyberpunk mode toggle
4. **Verify** all buttons and features work

### Test Server Components
```bash
# Test server startup
python server.py

# Check dependencies
pip install -r requirements.txt
```

## 🌐 Production Deployment

### Domain Configuration
See the main **DOMAIN_INSTALLATION_GUIDE.md** for complete domain setup.

### Server Requirements
- **OS**: Linux Mint or Ubuntu 20.04+
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 20GB+ free space
- **Network**: High-speed internet connection

### Service Management
- **Systemd** - Automatic startup and restart
- **Health Monitoring** - Automated service checks
- **Log Rotation** - Automatic log management
- **Backup System** - Daily database and config backups

## 🔧 Configuration

### Server Settings
Edit the server configuration:
- **Host**: 0.0.0.0 (all interfaces)
- **Port**: 8765 (WebSocket)
- **Database**: SQLite with encrypted storage
- **SSL**: Let's Encrypt certificates
- **Logging**: Complete audit trail

### Security Settings
- **Rate Limiting**: 100 requests/minute per IP
- **Max Connections**: 10 per IP
- **Session Timeout**: 3600 seconds
- **Registration**: Enabled
- **Guest Mode**: Enabled
- **Room Size**: 50 users maximum

## 📞 Support

### Documentation
- **`LINUX_SERVER_INSTALLATION.md`** - Complete server setup
- **`DOMAIN_INSTALLATION_GUIDE.md`** - Domain configuration
- **Server Code** - Inline documentation and comments

### Troubleshooting
1. **Check logs**: `sudo journalctl -u printermake-server -f`
2. **Test connectivity**: `curl -I https://printermake.online`
3. **Verify SSL**: `openssl s_client -connect printermake.online:443`
4. **Monitor services**: `systemctl status printermake-server`

### Common Issues
- **Port blocked**: Check firewall configuration
- **SSL errors**: Verify certificate installation
- **WebSocket issues**: Check nginx WebSocket proxy
- **Database issues**: Check SQLite permissions

## 🎯 Success Checklist

After deployment, verify:
- ✅ **Website accessible** at https://printermake.online
- ✅ **WebSocket working** at wss://ws.printermake.online
- ✅ **SSL certificate** valid and auto-renewing
- ✅ **Firewall configured** with proper rules
- ✅ **Services running** with systemctl
- ✅ **Logs monitoring** in journalctl
- ✅ **Backups scheduled** and working

## 🚀 Next Steps

1. **Deploy Server** - Follow installation guide
2. **Configure Domain** - Set up DNS records
3. **Test Everything** - Verify all components work
4. **Monitor Services** - Set up alerting
5. **Secure Backend** - Implement additional security

---

**Your printermake.online server is ready for production deployment! 🔒🌐**

*Built with quantum-resistant encryption for printermake.online*