# 🔒 PrinterMake - Quantum-Resistant Secure Chat Platform

[![Security](https://img.shields.io/badge/Security-Quantum--Resistant-blue.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)](#)

> **A quantum-resistant, encrypted CLI chat application for privacy-conscious users who refuse to compromise their security.**

**Built by people who are fed up with Discord and WhatsApp pretending to be secure while harvesting your data.**

## 🎯 What is PrinterMake?

PrinterMake is a **quantum-resistant**, encrypted CLI chat application designed for privacy-conscious users. Unlike mainstream chat platforms that claim security while storing your data and selling it to advertisers, PrinterMake implements true end-to-end encryption with post-quantum cryptographic algorithms.

### The Problem with Current Chat Apps
- **Discord**: Claims "end-to-end encryption" but stores your messages
- **WhatsApp**: Owned by Meta, uses your data for advertising  
- **Signal**: Collects metadata despite good encryption
- **Telegram**: Not actually E2E encrypted by default

### The PrinterMake Solution
- ✅ **True Quantum-Resistant Encryption** (X25519 + AES-256-GCM + SHA-3)
- ✅ **Zero Data Collection** - Server never sees your content
- ✅ **Self-Hosted Options** - Run your own server for complete control
- ✅ **Open Source & Transparent** - Auditable code
- ✅ **No Ads, No Tracking, No Bullshit** - Just secure communication

## 📁 Project Structure

This repository contains:

- **Web/** - Modern web interface and interactive demo
- **Client/** - CLI chat application
- **Server/** - Server components (Linux and Windows)

## 🚀 Installation Guide

### For End Users (Client Only)

#### Python Installation
```bash
# Install dependencies
pip install -r Client/requirements.txt

# Run in demo mode (no server required)
python Client/chat_client.py --demo

# Connect to a server
python Client/chat_client.py --host yourserver.com --port 8765
```

### For Server Deployment (Linux)

#### Prerequisites
- **Ubuntu 20.04+** or Debian 11+
- **Python 3.11+**
- **2GB RAM** minimum, 4GB recommended
- **20GB+** storage
- **Root/sudo** access

#### Installation Steps
```bash
# 1. Clone the repository
git clone https://github.com/your-username/printermake.git
cd printermake

# 2. Copy server files
cp -r Server/* /home/printermake/apps/
cd /home/printermake/apps

# 3. Install Python dependencies
python3.11 -m venv printermake_env
source printermake_env/bin/activate
pip install -r requirements.txt

# 4. Configure server
# Edit server configuration as needed
nano server.py

# 5. Start the server
python server.py

# For production, use systemd (see Server/LINUX_SERVER_INSTALLATION.md)
```

#### Complete Linux Server Guide
See `Server/LINUX_SERVER_INSTALLATION.md` for:
- **System preparation** and dependency installation
- **SSL certificate setup** with Let's Encrypt
- **Nginx configuration** for reverse proxy
- **Systemd service** creation and management
- **Security hardening** with firewall and fail2ban
- **Monitoring and maintenance** scripts

### For Server Deployment (Windows)

#### Prerequisites
- **Windows 10** or **Server 2019/2022**
- **Python 3.11+**
- **4GB RAM** minimum, 8GB recommended
- **PowerShell** (Administrator access)

#### Installation Steps
```powershell
# 1. Clone the repository
git clone https://github.com/your-username/printermake.git
cd printermake

# 2. Copy server files
Copy-Item -Recurse -Force "Server\*" -Destination "C:\PrinterMake\"

# 3. Install Python dependencies
cd "C:\PrinterMake"
pip install -r requirements.txt

# 4. Configure server
notepad server.py

# 5. Test server
python server.py

# For production, use Windows Service (see Windows guide)
```

#### Complete Windows Server Guide
See `Server/WINDOWS_SERVER_INSTALLATION.md` for:
- **PowerShell installation** scripts
- **Windows Service** creation and configuration
- **Windows Defender** exclusions
- **Firewall configuration**
- **Service monitoring** and health checks

## 💻 Features

### CLI Application
- **Discord-style Commands** - `/help`, `/rooms`, `msg user message`
- **Room-based Chat** - Create and join themed rooms
- **Direct Messaging** - Secure private conversations
- **Cyberpunk UI Mode** - Retro terminal aesthetic
- **Cross-platform** - Windows, Linux, macOS

### Web Interface
- **Interactive Demo** - Real-time chat simulation
- **Modern Design** - Professional dark theme
- **Responsive Layout** - Works on desktop and mobile
- **About Us Section** - Explains our privacy philosophy
- **Developer Portfolio** - Links to Thomas Conway's portfolio

### Security Features
- **Quantum-Resistant Encryption** - Future-proof security
- **End-to-End Communication** - No server-side decryption
- **Self-Hosted Options** - Complete infrastructure control
- **Zero Data Collection** - No usage analytics or profiling
- **Open Source** - Transparent, auditable code

## 🔐 Quantum-Resistant Security

Our encryption system is designed to resist attacks from both classical and quantum computers:

### Core Algorithms
- **X25519** - Quantum-resistant key exchange (ECDHE)
- **AES-256-GCM** - Symmetric encryption with authentication
- **SHA-3** - Quantum-resistant hashing
- **Perfect Forward Secrecy** - Session-specific keys

### Security Features
- **Zero-Knowledge Architecture** - Server never sees unencrypted content
- **Input Validation** - SQL injection and XSS prevention
- **Rate Limiting** - DDoS protection (100 requests/minute)
- **IP Blocking** - Automatic and manual protection
- **Audit Logging** - Complete security event tracking

## 🛠️ Usage

### CLI Client Commands
```bash
/help              # Show all commands
/rooms             # List available rooms
/join roomname     # Join a room
/leave             # Leave current room
/clear             # Clear chat history
/ui                # Toggle cyberpunk mode
msg username message  # Send direct message
```

### Web Interface
1. **Open** `Web/index.html` in your browser
2. **Test** the interactive chat demo
3. **Try** the cyberpunk mode toggle
4. **Explore** all features and functionality

## 🔍 Testing

### Quantum Cryptography Test
```bash
# Test the quantum-resistant encryption
cd Server
python quantum_crypto.py
```

**Expected Output:**
```
SUCCESS: All quantum cryptography tests passed!
ENCRYPTION: Message encrypted with: AES-256-GCM
QUANTUM: Quantum-resistant: True
```

### Application Test
```bash
# Test the complete application
python test_application.py
```

### Client Demo
```bash
# Test the CLI client in demo mode
python Client/chat_client.py --demo
```

## 🛡️ Security & Privacy

### What We Don't Do
- ❌ Store your messages on our servers
- ❌ Collect metadata or usage analytics
- ❌ Sell data to advertisers
- ❌ Use your information for profit
- ❌ Have backdoors or surveillance capabilities

### What We Do
- ✅ Encrypt everything end-to-end
- ✅ Use quantum-resistant algorithms
- ✅ Provide zero-knowledge architecture
- ✅ Offer self-hosted server options
- ✅ Maintain open source transparency

## 🤝 Contributing

PrinterMake is an open source project focused on privacy and security. We welcome contributions from developers, security researchers, and privacy advocates.

### How to Contribute
1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your improvements
4. **Test** thoroughly
5. **Submit** a pull request

### Areas for Contribution
- **Security** - Code audits, vulnerability research
- **Features** - New chat capabilities, UI improvements
- **Documentation** - Guides, tutorials, translations
- **Testing** - Automated tests, manual testing
- **Platform Support** - Mobile apps, web interface

## 📄 License

**MIT License** - Free to use, modify, and distribute.

You can:
- ✅ Use for any purpose (personal, commercial, educational)
- ✅ Modify and create derivative works
- ✅ Distribute and share
- ✅ Include in proprietary software

You just can't hold us liable if something goes wrong.

## 🚀 Production Deployment

### Domain Configuration
Ready for deployment to **printermake.online**:
- ✅ **DNS Configuration** - Complete GoDaddy setup guide
- ✅ **SSL Certificates** - Let's Encrypt automation
- ✅ **Nginx Configuration** - Web server and WebSocket proxy
- ✅ **Subdomain Strategy** - Separate domains for different services
- ✅ **Security Headers** - Complete HTTPS security

### Server Requirements
- **OS**: Ubuntu 20.04+ or Windows Server 2019/2022
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 20GB+ free space
- **Network**: High-speed internet connection

## 🌟 Why Choose PrinterMake?

### vs Discord
| Feature | Discord | PrinterMake |
|---------|---------|-------------|
| End-to-End Encryption | ❌ Claims but stores | ✅ True quantum-resistant |
| Data Collection | ✅ Everything | ❌ Zero |
| Self-Hosting | ❌ Impossible | ✅ Easy deployment |
| Open Source | ❌ Proprietary | ✅ MIT License |
| Privacy | ❌ Meta ownership | ✅ Privacy-first design |

### vs WhatsApp
| Feature | WhatsApp | PrinterMake |
|---------|----------|-------------|
| Encryption | ✅ Good | ✅ Quantum-resistant |
| Meta Ownership | ❌ Facebook | ✅ Independent |
| Self-Hosting | ❌ No | ✅ Yes |
| Open Source | ❌ Partial | ✅ Complete |
| Privacy | ❌ Metadata collection | ✅ Zero-knowledge |

## 📞 Support & Documentation

### Documentation Files
- **`Server/LINUX_SERVER_INSTALLATION.md`** - Complete Linux server setup
- **`Server/WINDOWS_SERVER_INSTALLATION.md`** - Complete Windows server setup
- **`Web/`** - Web interface and demo files
- **`Client/`** - CLI chat application

### Getting Help
- **GitHub Issues** - Bug reports and feature requests
- **Discussions** - Community support and ideas
- **Email** - security@printermake.online for security issues
- **Email** - support@printermake.online for general support

### Developer
**Created by Thomas Conway**
- **Portfolio**: [thomasconway01.github.io/Portfolio/](https://thomasconway01.github.io/Portfolio/)
- **GitHub**: [github.com/thomasconway01](https://github.com/thomasconway01)

## 🎉 Join the Revolution

PrinterMake represents a new era of secure communication. Join us in building a world where privacy is respected and data belongs to the user.

**Download, deploy, and start chatting securely today!**

---

**Built with ❤️ for people who believe privacy is a right, not a privilege.**

*No more printing your privacy away. Time to make secure communication standard.*