// PrinterMake Interactive Demo
class ChatDemo {
    constructor() {
        this.currentUser = "Guest";
        this.connected = false;
        this.cyberpunkMode = false;
        this.users = ['Tom', 'Alice', 'Bob', 'Charlie', 'Diana'];
        this.currentRoom = 'general';
        this.messages = [
            {user: "System", content: "Welcome to PrinterMake! Type /help to see commands. Try: /ui, /rooms, msg Tom Hello!", time: "13:45:32", type: "system"},
            {user: "Tom", content: "Hey everyone! Anyone up for a secure chat?", time: "13:45:45", type: "message"},
            {user: "Alice", content: "Welcome to our demo! This is all simulated with real encryption simulation 🔐", time: "13:45:52", type: "message"},
            {user: "Bob", content: "Try the /ui command to see cyberpunk mode!", time: "13:46:01", type: "message"}
        ];
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.initializeTurnstile();
        this.simulateActivity();
    }
    
    setupEventListeners() {
        const input = document.getElementById('demo-input');
        const sendBtn = document.getElementById('send-btn');
        
        if (input && sendBtn) {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.sendMessage(input.value);
                    input.value = '';
                }
            });
            
            sendBtn.addEventListener('click', () => {
                this.sendMessage(input.value);
                input.value = '';
            });
        }
        
        // Suggestion buttons
        document.querySelectorAll('.suggestion').forEach(btn => {
            btn.addEventListener('click', () => {
                const cmd = btn.getAttribute('data-cmd');
                input.value = cmd;
                input.focus();
            });
        });
        
        // Download buttons
        document.getElementById('download-client')?.addEventListener('click', () => {
            this.simulateDownload('printermake-client-2.1.4.tar.gz');
        });
        
        document.getElementById('view-docs')?.addEventListener('click', () => {
            this.showMessage('System', 'Documentation will open in SETUP_GUIDE.md', 'system');
        });
        
        document.getElementById('view-github')?.addEventListener('click', () => {
            this.showMessage('System', 'Opening GitHub repository: https://github.com/printermake', 'system');
        });
    }
    
    initializeTurnstile() {
        // Initialize Cloudflare Turnstile
        if (window.turnstile) {
            window.turnstile.render('#cf-turnstile', {
                sitekey: '0x4AAAAAAB_8GZjvDcIeVygK',
                callback: function(token) {
                    console.log('Turnstile verified:', token);
                    document.getElementById('demo-chat').style.pointerEvents = 'auto';
                    document.getElementById('demo-input').disabled = false;
                },
                'error-callback': function() {
                    console.log('Turnstile error');
                },
                'expired-callback': function() {
                    console.log('Turnstile expired');
                }
            });
        }
    }
    
    sendMessage(content) {
        if (!content.trim()) return;
        
        // Add user message
        this.addMessage(this.currentUser, content, 'user');
        
        // Process commands or generate responses
        setTimeout(() => {
            this.processInput(content);
        }, 1000);
        
        // Simulate typing
        this.showTyping();
    }
    
    processInput(input) {
        const trimmed = input.trim();
        
        if (trimmed.startsWith('/')) {
            this.handleCommand(trimmed);
        } else if (trimmed.startsWith('msg ')) {
            this.handleDirectMessage(trimmed);
        } else if (trimmed.startsWith('join ')) {
            this.handleJoinRoom(trimmed);
        } else {
            this.handleChatMessage(trimmed);
        }
    }
    
    handleCommand(command) {
        const cmd = command.toLowerCase();
        
        switch (cmd) {
            case '/help':
                this.showMessage('System', 
                    'Available commands:\n' +
                    '  /help - Show this help\n' +
                    '  /ui - Toggle cyberpunk mode\n' +
                    '  /rooms - List rooms\n' +
                    '  /status - Show connection status\n' +
                    '  /clear - Clear chat\n' +
                    '  msg user message - Send direct message\n' +
                    '  join room - Join a room', 'system');
                break;
                
            case '/ui':
                this.toggleCyberpunkMode();
                break;
                
            case '/rooms':
                this.showMessage('System', 
                    'Available rooms:\n' +
                    '  general - General chat (5 users)\n' +
                    '  tech - Tech discussion (3 users)\n' +
                    '  gaming - Gaming chat (8 users)\n' +
                    '  random - Random topics (12 users)', 'system');
                break;
                
            case '/status':
                this.showMessage('System', 
                    'Connection Status:\n' +
                    '  Server: printermake.online:8765\n' +
                    '  Encryption: 🔐 Enabled (RSA-2048 + AES-256)\n' +
                    '  Users online: 47\n' +
                    '  Latency: 23ms\n' +
                    '  Uptime: 99.9%', 'system');
                break;
                
            case '/clear':
                this.clearChat();
                break;
                
            default:
                this.showMessage('System', `Unknown command: ${command}. Type /help for available commands.`, 'system');
        }
    }
    
    handleDirectMessage(input) {
        const parts = input.split(' ');
        if (parts.length >= 3) {
            const target = parts[1];
            const message = parts.slice(2).join(' ');
            this.showMessage(target, `DM from ${this.currentUser}: ${message}`, 'dm');
        } else {
            this.showMessage('System', 'Usage: msg <username> <message>', 'system');
        }
    }
    
    handleJoinRoom(input) {
        const room = input.split(' ')[1];
        if (room) {
            this.currentRoom = room;
            this.showMessage('System', `Joined room: ${room}`, 'system');
        } else {
            this.showMessage('System', 'Usage: join <room>', 'system');
        }
    }
    
    handleChatMessage(message) {
        // Generate realistic responses
        const responses = [
            {user: "Tom", content: "Great point! 🔥"},
            {user: "Alice", content: "That's really interesting. Tell me more!"},
            {user: "Bob", content: "I agree completely. The security here is impressive."},
            {user: "Charlie", content: "Nice! What do you think about the new features?"},
            {user: "Diana", content: "This chat is so much better than Discord honestly."}
        ];
        
        const randomResponse = responses[Math.floor(Math.random() * responses.length)];
        this.showMessage(randomResponse.user, randomResponse.content, 'message');
    }
    
    toggleCyberpunkMode() {
        this.cyberpunkMode = !this.cyberpunkMode;
        
        if (this.cyberpunkMode) {
            document.body.classList.add('cyberpunk');
            this.showMessage('System', '🔮 CYBERPUNK MODE ACTIVATED 🔮', 'system');
        } else {
            document.body.classList.remove('cyberpunk');
            this.showMessage('System', 'CYBERPUNK MODE DEACTIVATED', 'system');
        }
    }
    
    addMessage(user, content, type = 'message') {
        const chatWindow = document.getElementById('demo-chat');
        if (!chatWindow) return;
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        
        const now = new Date();
        const time = now.toLocaleTimeString('en-US', { hour12: false });
        
        messageDiv.innerHTML = `
            <span class="timestamp">${time}</span>
            <span class="username">${user}</span>
            <span class="content">${content}</span>
        `;
        
        chatWindow.appendChild(messageDiv);
        chatWindow.scrollTop = chatWindow.scrollHeight;
        
        // Add typing effect for new messages
        this.addTypingEffect(messageDiv);
    }
    
    addTypingEffect(element) {
        const content = element.querySelector('.content');
        if (!content) return;
        
        const text = content.textContent;
        content.textContent = '';
        
        let i = 0;
        const typeInterval = setInterval(() => {
            if (i < text.length) {
                content.textContent += text[i];
                i++;
            } else {
                clearInterval(typeInterval);
            }
        }, 50);
    }
    
    showTyping() {
        const chatWindow = document.getElementById('demo-chat');
        if (!chatWindow) return;
        
        const typingDiv = document.createElement('div');
        typingDiv.className = 'message typing';
        typingDiv.innerHTML = `
            <span class="timestamp">${new Date().toLocaleTimeString('en-US', { hour12: false })}</span>
            <span class="username">Someone</span>
            <span class="content"><span class="typing-indicator">typing...</span></span>
        `;
        
        chatWindow.appendChild(typingDiv);
        chatWindow.scrollTop = chatWindow.scrollHeight;
        
        // Remove typing indicator after 2 seconds
        setTimeout(() => {
            typingDiv.remove();
        }, 2000);
    }
    
    showMessage(user, content, type = 'message') {
        this.addMessage(user, content, type);
    }
    
    clearChat() {
        const chatWindow = document.getElementById('demo-chat');
        if (chatWindow) {
            chatWindow.innerHTML = '';
            this.addMessage('System', 'Chat cleared. Welcome back to PrinterMake!', 'system');
        }
    }
    
    simulateActivity() {
        // Simulate random user activity
        setInterval(() => {
            if (Math.random() < 0.3) { // 30% chance every 5 seconds
                const randomUsers = ['Tom', 'Alice', 'Bob', 'Charlie', 'Diana'];
                const randomMessages = [
                    'Anyone working on interesting projects?',
                    'The encryption here is solid 🔐',
                    'Just tried the /ui command - so cool!',
                    'Great community here',
                    'What do you all think about the new features?',
                    'This is way better than other platforms',
                    'The cyberpunk mode is awesome',
                    'How long has everyone been using PrinterMake?'
                ];
                
                const randomUser = randomUsers[Math.floor(Math.random() * randomUsers.length)];
                const randomMessage = randomMessages[Math.floor(Math.random() * randomMessages.length)];
                
                setTimeout(() => {
                    this.showMessage(randomUser, randomMessage, 'message');
                }, 1000);
            }
        }, 5000);
    }
    
    simulateDownload(filename) {
        this.showMessage('System', `Downloading ${filename}...`, 'system');
        setTimeout(() => {
            this.showMessage('System', '✅ Download complete! Check your Downloads folder.', 'system');
        }, 2000);
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    const demo = new ChatDemo();
    
    // Auto-focus input
    document.getElementById('demo-input')?.focus();
});

// Handle Enter key globally
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        // Could implement escape key functionality
    }
});