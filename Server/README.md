# 🔒 PrinterMake Server - Open Source

[![Security](https://img.shields.io/badge/Security-Quantum--Resistant-blue.svg)](#)
[![Server](https://img.shields.io/badge/Server-Open--Source-green.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-orange.svg)](#)

> **Open-source self-hosted server for PrinterMake with quantum-resistant encryption**

## 🚀 Overview

This folder contains the **open-source PrinterMake server** that users can run on their own servers. It includes quantum-resistant encryption, complete setup guides, and self-hosting capabilities.

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

### Security Protection
- **Rate Limiting** - DDoS protection
- **IP Blocking** - Automatic and manual protection
- **Input Validation** - SQL injection and XSS prevention
- **Audit Logging** - Complete security event tracking

## 🌐 Self-Hosting Setup

This server can be deployed on any domain or subdomain you own:

### Recommended Domain Structure
- **your-domain.com** - Main website
- **chat.your-domain.com** - WebSocket server
- **api.your-domain.com** - REST API (future)

### SSL & Security
- **Let's Encrypt** - Automatic SSL certificate (recommended)
- **HTTPS/WSS** - All connections encrypted
- **Security Headers** - XSS, clickjacking, and injection protection
- **Nginx** - Web server and reverse proxy (recommended)

## 🛠️ Quick Deployment

### For Linux Mint Server
See `LINUX_SERVER_INSTALLATION.md` for complete setup guide.

**Quick Start:**
```bash
# 1. Download and extract files
git clone https://github.com/your-username/printermake.git
cd printermake/Server

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
python server.py

# 4. Connect clients to: ws://localhost:8765
```

### Prerequisites
- **Any OS** (Linux, Windows, macOS)
- **Python 3.8+**
- **Port 8765** available (or choose different port)
- **Optional**: Domain configured for your use

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

### Database & Storage
- **SQLite** - Lightweight, serverless database
- **Message History** - Persistent chat logs
- **User Management** - Registration and authentication
- **Secure Storage** - Encrypted data at rest

## 🔍 Testing

### Test Server Startup
```bash
# Test server startup
python server.py

# Check dependencies
pip install -r requirements.txt

# Test with custom port
python server.py --port 8080
```

## 🌐 Self-Hosting Deployment

### Server Requirements
- **OS**: Any modern OS (Linux, Windows, macOS)
- **RAM**: 1GB minimum, 2GB recommended
- **Storage**: 1GB+ free space
- **Network**: Internet connection for client access

### Service Management (Linux)
- **Systemd** - Automatic startup and restart (optional)
- **PM2** - Process management for Node.js style deployment (optional)
- **Log Rotation** - Automatic log management (optional)
- **Backup System** - Daily database backups (recommended)

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