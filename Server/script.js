// PrinterMake Website - Modern Interactive Features
class PrinterMakeApp {
    constructor() {
        this.init();
    }
    
    init() {
        this.setupNavigation();
        this.setupThemeToggle();
        this.setupHeroActions();
        this.setupDemo();
        this.setupAnimations();
        this.setupDownloadButtons();
    }
    
    // Navigation functionality
    setupNavigation() {
        // Smooth scrolling for navigation links
        document.querySelectorAll('.nav-link, a[href^="#"]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = link.getAttribute('href');
                const targetSection = document.querySelector(targetId);
                
                if (targetSection) {
                    const offsetTop = targetSection.offsetTop - 80; // Account for fixed nav
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            });
        });
        
        // Update active nav link on scroll
        window.addEventListener('scroll', () => {
            const sections = document.querySelectorAll('section[id]');
            const navLinks = document.querySelectorAll('.nav-link');
            
            let current = '';
            sections.forEach(section => {
                const sectionTop = section.offsetTop - 100;
                if (window.pageYOffset >= sectionTop) {
                    current = section.getAttribute('id');
                }
            });
            
            navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === `#${current}`) {
                    link.classList.add('active');
                }
            });
        });
    }
    
    // Theme toggle functionality
    setupThemeToggle() {
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                document.body.classList.toggle('dark-theme');
                const isDark = document.body.classList.contains('dark-theme');
                themeToggle.textContent = isDark ? '☀️' : '🌙';
                
                // Store preference
                localStorage.setItem('printermake-theme', isDark ? 'dark' : 'light');
            });
            
            // Load saved theme
            const savedTheme = localStorage.getItem('printermake-theme');
            if (savedTheme === 'dark') {
                document.body.classList.add('dark-theme');
                themeToggle.textContent = '☀️';
            }
        }
    }
    
    // Hero section actions
    setupHeroActions() {
        const tryDemoBtn = document.getElementById('tryDemoBtn');
        const downloadBtn = document.getElementById('downloadBtn');
        
        if (tryDemoBtn) {
            tryDemoBtn.addEventListener('click', () => {
                const demoSection = document.querySelector('#demo');
                if (demoSection) {
                    demoSection.scrollIntoView({ behavior: 'smooth' });
                }
            });
        }
        
        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => {
                const downloadSection = document.querySelector('#download');
                if (downloadSection) {
                    downloadSection.scrollIntoView({ behavior: 'smooth' });
                }
            });
        }
    }
    
    // Demo chat functionality
    setupDemo() {
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
        
        this.initializeDemo();
        this.setupDemoEventListeners();
        this.initializeTurnstile();
        this.simulateActivity();
    }
    
    initializeDemo() {
        // Initialize Cloudflare Turnstile
        if (window.turnstile) {
            window.turnstile.render('#cf-turnstile', {
                sitekey: '0x4AAAAAAB_8GZjvDcIeVygK',
                callback: (token) => {
                    console.log('Turnstile verified:', token);
                    this.connected = true;
                    this.updateConnectionStatus(true);
                },
                'error-callback': () => {
                    console.log('Turnstile error');
                    this.updateConnectionStatus(false);
                },
                'expired-callback': () => {
                    console.log('Turnstile expired');
                    this.updateConnectionStatus(false);
                }
            });
        }
    }
    
    setupDemoEventListeners() {
        const input = document.getElementById('demo-input');
        const sendBtn = document.getElementById('send-btn');
        
        if (input && sendBtn) {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && this.connected) {
                    this.sendMessage(input.value);
                    input.value = '';
                }
            });
            
            sendBtn.addEventListener('click', () => {
                if (this.connected) {
                    this.sendMessage(input.value);
                    input.value = '';
                }
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
    }
    
    sendMessage(content) {
        if (!content.trim() || !this.connected) return;
        
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
                    '  Server: demo.printermake.online:8765\n' +
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
            document.body.classList.add('cyberpunk-mode');
            this.showMessage('System', '🔮 CYBERPUNK MODE ACTIVATED 🔮', 'system');
        } else {
            document.body.classList.remove('cyberpunk-mode');
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
    
    updateConnectionStatus(connected) {
        const statusIndicator = document.querySelector('.status-indicator');
        if (statusIndicator) {
            statusIndicator.className = connected ? 'status-indicator online' : 'status-indicator offline';
        }
        
        const input = document.getElementById('demo-input');
        if (input) {
            input.disabled = !connected;
            input.placeholder = connected 
                ? 'Type your message or commands (try: /help, msg Tom Hello, /ui)'
                : 'Please complete the security challenge above';
        }
    }
    
    simulateActivity() {
        // Simulate random user activity
        setInterval(() => {
            if (Math.random() < 0.3 && this.connected) { // 30% chance every 5 seconds
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
    
    // Download buttons
    setupDownloadButtons() {
        document.getElementById('download-client')?.addEventListener('click', () => {
            this.simulateDownload('printermake-client-2.1.4.tar.gz');
        });
        
        document.getElementById('view-docs')?.addEventListener('click', () => {
            this.showMessage('System', 'Documentation will open in README.md', 'system');
        });
        
        document.getElementById('view-github')?.addEventListener('click', () => {
            this.showMessage('System', 'Opening GitHub repository: https://github.com/printermake', 'system');
        });
    }
    
    simulateDownload(filename) {
        this.showMessage('System', `Downloading ${filename}...`, 'system');
        setTimeout(() => {
            this.showMessage('System', '✅ Download complete! Check your Downloads folder.', 'system');
        }, 2000);
    }
    
    // Scroll animations
    setupAnimations() {
        // Intersection Observer for fade-in animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                }
            });
        }, observerOptions);
        
        // Observe elements for animation
        document.querySelectorAll('.feature-card, .about-card, .download-card').forEach(el => {
            observer.observe(el);
        });
    }
}

// Utility functions
function createRipple(e) {
    const button = e.currentTarget;
    const circle = document.createElement('span');
    const diameter = Math.max(button.clientWidth, button.clientHeight);
    const radius = diameter / 2;
    
    circle.style.width = circle.style.height = `${diameter}px`;
    circle.style.left = `${e.clientX - button.offsetLeft - radius}px`;
    circle.style.top = `${e.clientY - button.offsetTop - radius}px`;
    circle.classList.add('ripple');
    
    const ripple = button.getElementsByClassName('ripple')[0];
    if (ripple) {
        ripple.remove();
    }
    
    button.appendChild(circle);
}

// Add ripple effect to buttons
document.addEventListener('DOMContentLoaded', () => {
    // Initialize the main app
    const app = new PrinterMakeApp();
    
    // Add ripple effect to buttons
    document.querySelectorAll('.btn-primary, .btn-secondary, .download-btn, .cta-button').forEach(button => {
        button.addEventListener('click', createRipple);
    });
    
    // Auto-focus demo input
    const demoInput = document.getElementById('demo-input');
    if (demoInput) {
        setTimeout(() => {
            demoInput.focus();
        }, 1000);
    }
    
    // Add loading animation
    document.body.classList.add('loaded');
});

// Handle cyberpunk mode styles
const cyberpunkStyles = `
    .cyberpunk-mode {
        filter: hue-rotate(180deg) invert(1) contrast(1.2);
        animation: glitch 0.3s infinite;
    }
    
    @keyframes glitch {
        0%, 90%, 100% { transform: translate(0); }
        20% { transform: translate(-2px, 2px); }
        40% { transform: translate(-2px, -2px); }
        60% { transform: translate(2px, 2px); }
        80% { transform: translate(2px, -2px); }
    }
    
    .ripple {
        position: absolute;
        border-radius: 50%;
        background-color: rgba(255, 255, 255, 0.6);
        transform: scale(0);
        animation: ripple-animation 0.6s linear;
        pointer-events: none;
    }
    
    @keyframes ripple-animation {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
    
    .animate-in {
        animation: slideInUp 0.6s ease-out forwards;
    }
    
    @keyframes slideInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .loaded {
        animation: fadeIn 0.3s ease-out;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
`;

// Inject cyberpunk styles
const styleSheet = document.createElement('style');
styleSheet.textContent = cyberpunkStyles;
document.head.appendChild(styleSheet);