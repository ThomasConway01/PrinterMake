# 🔧 PrinterMake Linux Server - Production Deployment

[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-orange.svg)](https://ubuntu.com)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Security](https://img.shields.io/badge/Security-Quantum--Resistant-blue.svg)](#)

> **Production-ready Linux server deployment for PrinterMake secure chat platform**

## 🚀 Quick Start

### System Requirements
- **OS**: Ubuntu 20.04 LTS or newer
- **RAM**: 2GB minimum, 4GB recommended  
- **Storage**: 20GB+ SSD
- **Bandwidth**: High/unlimited
- **CPU**: 2+ cores recommended

### One-Command Installation
```bash
# Clone and run the automated installer
git clone https://github.com/printermake/server.git
cd server
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation

#### 1. Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### 2. Install Dependencies
```bash
sudo apt install -y python3.11 python3.11-pip python3.11-venv python3.11-dev
sudo apt install -y curl wget git nginx certbot python3-certbot-nginx
sudo apt install -y ufw htop sqlite3 build-essential libssl-dev libffi-dev
```

#### 3. Create Application User
```bash
sudo useradd -m -s /bin/bash printermake
sudo usermod -aG sudo printermake
sudo su - printermake
```

#### 4. Deploy Application
```bash
# Create directories
mkdir -p ~/apps/{logs,data,ssl,backup}
cd ~/apps

# Install Python dependencies
python3.11 -m venv printermake_env
source printermake_env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Set up database
sqlite3 ~/apps/data/printermake.db < /dev/null
```

#### 5. SSL Certificate (printermake.online)
```bash
# Get SSL certificate
sudo certbot --nginx -d printermake.online -d www.printermake.online

# Copy to application directory
sudo cp /etc/letsencrypt/live/printermake.online/fullchain.pem ~/apps/ssl/
sudo cp /etc/letsencrypt/live/printermake.online/privkey.pem ~/apps/ssl/
chown printermake:printermake ~/apps/ssl/*
```

#### 6. Nginx Configuration
```bash
# Create Nginx configuration
sudo nano /etc/nginx/sites-available/printermake.online
```

```nginx
# /etc/nginx/sites-available/printermake.online
server {
    listen 80;
    server_name printermake.online www.printermake.online demo.printermake.online;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name printermake.online www.printermake.online;
    
    # SSL Configuration
    ssl_certificate /home/printermake/apps/ssl/fullchain.pem;
    ssl_certificate_key /home/printermake/apps/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Document Root
    root /home/printermake/apps/web;
    index index.html;
    
    # WebSocket proxy for chat server
    location /ws/ {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
    
    # Main website
    location / {
        try_files $uri $uri/ =404;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}

# WebSocket subdomain
server {
    listen 443 ssl http2;
    server_name ws.printermake.online;
    
    ssl_certificate /home/printermake/apps/ssl/fullchain.pem;
    ssl_certificate_key /home/printermake/apps/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/printermake.online /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

#### 7. Systemd Services
```bash
# Create chat server service
sudo nano /etc/systemd/system/printermake-server.service
```

```ini
# /etc/systemd/system/printermake-server.service
[Unit]
Description=PrinterMake Secure Chat Server
After=network.target

[Service]
Type=simple
User=printermake
Group=printermake
WorkingDirectory=/home/printermake/apps
Environment=PATH=/home/printermake/apps/printermake_env/bin
ExecStart=/home/printermake/apps/printermake_env/bin/python server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=printermake-server

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable printermake-server
sudo systemctl start printermake-server
sudo systemctl status printermake-server
```

#### 8. Security Configuration
```bash
# Configure firewall
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 127.0.0.1 to any port 8765
sudo ufw status
```

## 🔧 Configuration

### Server Configuration File
```bash
nano /home/printermake/apps/config/server.conf
```

```ini
[server]
host = 0.0.0.0
port = 8765
database_path = /home/printermake/apps/data/printermake.db
log_path = /home/printermake/apps/logs/server.log
ssl_cert_path = /home/printermake/apps/ssl/fullchain.pem
ssl_key_path = /home/printermake/apps/ssl/privkey.pem

[security]
rate_limit_per_minute = 100
max_connections_per_ip = 10
session_timeout = 3600
enable_registration = true
enable_guest_mode = true
max_room_size = 50

[quantum_crypto]
enabled = true
algorithm = X25519
key_exchange = true
encryption = AES-256-GCM
hashing = SHA-3
```

### Environment Variables
```bash
# Create environment file
nano /home/printermaker/apps/.env
```

```bash
# Server Settings
SERVER_HOST=0.0.0.0
SERVER_PORT=8765
DATABASE_PATH=/home/printermake/apps/data/printermake.db
LOG_LEVEL=INFO

# Security Settings
JWT_SECRET=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -base64 32)
SESSION_TIMEOUT=3600
RATE_LIMIT=100

# Quantum Cryptography
QUANTUM_CRYPTO_ENABLED=true
X25519_ENABLED=true
AES_256_GCM_ENABLED=true
SHA3_ENABLED=true

# Domain Settings
DOMAIN=printermake.online
SSL_CERT_PATH=/home/printermake/apps/ssl/fullchain.pem
SSL_KEY_PATH=/home/printermake/apps/ssl/privkey.pem
```

## 🔐 Quantum Cryptography

The server includes advanced quantum-resistant encryption:

### Features
- **X25519 Key Exchange** - Quantum-resistant
- **AES-256-GCM Encryption** - Symmetric encryption
- **SHA-3 Hashing** - Quantum-resistant hash function
- **Perfect Forward Secrecy** - Session-specific keys
- **Zero-Knowledge Architecture** - Server never sees content

### Test Quantum Cryptography
```bash
# Test the quantum-resistant encryption
python quantum_crypto.py
```

Expected output:
```
✅ All quantum cryptography tests passed!
🔐 Message encrypted with: AES-256-GCM
🔑 Quantum-resistant: True
```

## 🛡️ Security

### Built-in Security Features
- **IP Blocking** - Automatic and manual blocking
- **Rate Limiting** - DDoS protection (100 req/min)
- **Input Sanitization** - SQL injection prevention
- **XSS Protection** - No raw HTML rendering
- **Session Management** - Secure authentication
- **Audit Logging** - Complete security tracking

### Security Monitoring
```bash
# Install security tools
sudo apt install -y fail2ban logwatch

# Configure fail2ban
sudo nano /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
```

```bash
# Start fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## 📊 Monitoring

### Health Checks
```bash
# Create health check script
nano /home/printermake/apps/health_check.sh
```

```bash
#!/bin/bash
# PrinterMake Health Check

LOG_FILE="/home/printermake/apps/logs/health.log"

# Check services
if ! systemctl is-active --quiet printermake-server; then
    echo "ERROR: printermake-server is not running" | tee -a "$LOG_FILE"
    systemctl restart printermake-server
fi

if ! systemctl is-active --quiet nginx; then
    echo "ERROR: nginx is not running" | tee -a "$LOG_FILE"
    systemctl restart nginx
fi

# Check disk space
DISK_USAGE=$(df /home/printermake/apps | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 85 ]; then
    echo "WARNING: Disk usage is ${DISK_USAGE}%" | tee -a "$LOG_FILE"
fi

echo "$(date): Health check completed" >> "$LOG_FILE"
```

```bash
chmod +x /home/printermake/apps/health_check.sh

# Add to crontab
crontab -e
# Add: */15 * * * * /home/printermake/apps/health_check.sh
```

### Log Management
```bash
# Create log rotation
sudo nano /etc/logrotate.d/printermake
```

```
/home/printermake/apps/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 printermake printermake
    postrotate
        systemctl reload printermake-server
    endscript
}
```

## 💾 Backup & Recovery

### Automated Backup
```bash
# Create backup script
nano /home/printermake/apps/backup.sh
```

```bash
#!/bin/bash
# PrinterMake Backup Script

BACKUP_DIR="/home/printermake/apps/backup"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup database
cp /home/printermake/apps/data/printermake.db "$BACKUP_DIR/printermake_db_$DATE.db"

# Backup SSL certificates
tar -czf "$BACKUP_DIR/ssl_$DATE.tar.gz" -C /home/printermake/apps ssl/

# Backup configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" -C /home/printermake/apps config/

# Remove old backups
find "$BACKUP_DIR" -name "*.db" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

```bash
chmod +x /home/printermake/apps/backup.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add: 0 2 * * * /home/printermake/apps/backup.sh
```

### Emergency Recovery
```bash
# Quick service restart
sudo systemctl restart nginx
sudo systemctl restart printermake-server

# Check status
sudo systemctl status printermake-server
sudo systemctl status nginx

# Test connectivity
curl -I https://printermake.online
curl -I wss://ws.printermake.online
```

## 🐛 Troubleshooting

### Common Issues

#### Server Won't Start
```bash
# Check logs
sudo journalctl -u printermake-server -f
tail -f /home/printermake/apps/logs/server.log

# Check permissions
ls -la /home/printermake/apps/
```

#### SSL Certificate Issues
```bash
# Check certificate
sudo certbot certificates

# Renew manually
sudo certbot renew --force-renewal
```

#### Database Issues
```bash
# Check database
sqlite3 /home/printermake/apps/data/printermake.db ".tables"
sqlite3 /home/printermake/apps/data/printermake.db "PRAGMA integrity_check;"

# Check permissions
chown printermake:printermake /home/printermake/apps/data/printermake.db
chmod 644 /home/printermake/apps/data/printermake.db
```

#### WebSocket Issues
```bash
# Check if port is listening
sudo netstat -tuln | grep 8765

# Test WebSocket connection
wscat -c wss://printermake.online/ws/ 2>/dev/null || echo "WebSocket test completed"
```

## 🔄 Updates

### Application Updates
```bash
# Update application
cd /home/printermake/apps
source printermake_env/bin/activate
git pull origin main
pip install -r requirements.txt
sudo systemctl restart printermake-server
```

### System Updates
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y
sudo reboot
```

## 📈 Performance

### Optimization
```bash
# Increase system limits
sudo nano /etc/security/limits.conf
```

```
# Add these lines
printermake soft nofile 65536
printermake hard nofile 65536
```

```bash
# Optimize Nginx
sudo nano /etc/nginx/nginx.conf
```

```nginx
# Add to http block
worker_rlimit_nofile 65536;
worker_connections 4096;

# Buffer settings
client_body_buffer_size 128k;
client_max_body_size 10m;
client_header_buffer_size 1k;
large_client_header_buffers 4 4k;
output_buffers 1 32k;
postpone_output 1460;
```

## 📞 Support

### Log Locations
- **Application logs**: `/home/printermake/apps/logs/`
- **System logs**: `/var/log/syslog`
- **Nginx logs**: `/var/log/nginx/`
- **Security logs**: `/var/log/auth.log`

### Health Commands
```bash
# Server status
sudo systemctl status printermake-server
sudo systemctl status nginx

# Check connections
sudo netstat -tuln | grep :8765
sudo ss -tuln | grep :443

# Test SSL
openssl s_client -connect printermake.online:443

# Monitor resources
htop
iotop
nethogs
```

---

**Your PrinterMake server is now running with quantum-resistant encryption! 🔒🚀**

*Built for printermake.online - Where secure communication meets cutting-edge design.*