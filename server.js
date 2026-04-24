const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-trading-secret-key';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// ==================== CREATE DATA DIRECTORY ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir, { recursive: true });

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(dataDir, 'pending_users.json');
const settingsFile = path.join(dataDir, 'bot_settings.json');

// ==================== CREATE DEFAULT FILES ====================
if (!fs.existsSync(usersFile)) {
    const hashedPassword = bcrypt.hashSync('Mujtabah@2598', 10);
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: hashedPassword,
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
    console.log('✅ Created users.json with owner account');
}

if (!fs.existsSync(pendingFile)) {
    fs.writeFileSync(pendingFile, JSON.stringify({}, null, 2));
    console.log('✅ Created pending_users.json');
}

if (!fs.existsSync(settingsFile)) {
    fs.writeFileSync(settingsFile, JSON.stringify({
        defaultProfitPercent: 0.5,
        maxConcurrentTrades: 1,
        tradeIntervalMinutes: 5
    }, null, 2));
    console.log('✅ Created bot_settings.json');
}

// ==================== HELPER FUNCTIONS ====================
function readUsers() { 
    try {
        return JSON.parse(fs.readFileSync(usersFile));
    } catch(e) {
        return {};
    }
}

function writeUsers(users) { 
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function readPending() { 
    try {
        return JSON.parse(fs.readFileSync(pendingFile));
    } catch(e) {
        return {};
    }
}

function writePending(pending) { 
    fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2));
}

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Log all requests for debugging
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Halal Trading Bot Running' });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', async (req, res) => {
    console.log('Register request received:', req.body);
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }
    
    const users = readUsers();
    if (users[email]) {
        return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    const pending = readPending();
    if (pending[email]) {
        return res.status(400).json({ success: false, message: 'Request already pending' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    pending[email] = { 
        email, 
        password: hashedPassword, 
        requestedAt: new Date().toISOString(), 
        status: 'pending' 
    };
    writePending(pending);
    
    res.json({ success: true, message: 'Registration request sent to owner.' });
});

app.post('/api/login', (req, res) => {
    console.log('Login request received:', req.body.email);
    const { email, password } = req.body;
    
    const users = readUsers();
    const user = users[email];
    
    if (!user) {
        const pending = readPending();
        if (pending[email]) {
            return res.status(401).json({ success: false, message: 'Pending approval' });
        }
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!user.isApproved && !user.isOwner) {
        return res.status(401).json({ success: false, message: 'Account not approved' });
    }
    
    if (user.isBlocked) {
        return res.status(401).json({ success: false, message: 'Your account has been blocked.' });
    }
    
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'No token' });
    }
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== SIMPLE BALANCE ENDPOINT (TEST) ====================
app.get('/api/test-balance', authenticate, async (req, res) => {
    res.json({ 
        success: true, 
        spotBalance: 1000, 
        fundingBalance: 500, 
        total: 1500,
        message: 'Test balance - API keys not connected yet'
    });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    res.json({ 
        success: true, 
        spotBalance: 1000, 
        fundingBalance: 500, 
        total: 1500,
        message: 'Demo balance - Connect real Binance API for actual balances'
    });
});

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    const { apiKey, secretKey, accountType } = req.body;
    
    if (!apiKey || !secretKey) {
        return res.status(400).json({ success: false, message: 'Both keys required' });
    }
    
    const users = readUsers();
    users[req.user.email].apiKey = encrypt(apiKey);
    users[req.user.email].secretKey = encrypt(secretKey);
    writeUsers(users);
    
    res.json({ 
        success: true, 
        message: 'API keys saved successfully!', 
        spotBalance: 1000,
        fundingBalance: 500,
        totalBalance: 1500
    });
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    res.json({ 
        success: true, 
        spotBalance: 1000, 
        fundingBalance: 500, 
        totalBalance: 1500,
        message: 'Connected successfully! (Demo mode - Add real Binance API for live trading)' 
    });
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) {
        return res.json({ success: false, message: 'No keys set' });
    }
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== TRADING ENDPOINTS (SIMPLIFIED) ====================
app.post('/api/start-halal-trading', authenticate, async (req, res) => {
    const { investmentAmount, profitPercent, timeLimit, accountType } = req.body;
    
    res.json({ 
        success: true, 
        sessionId: 'demo_session_' + Date.now(),
        message: `✅ Trading started! (Demo mode)\n\nInvestment: $${investmentAmount}\nProfit Target: ${profitPercent}%\nTime Limit: ${timeLimit} hours\n\nFull version with real Binance API coming soon.`
    });
});

app.post('/api/stop-halal-trading', authenticate, (req, res) => {
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/halal-session-status', authenticate, (req, res) => {
    res.json({ 
        success: true, 
        active: false,
        currentProfit: 0,
        totalTrades: 0,
        trades: []
    });
});

app.get('/api/trade-history', authenticate, (req, res) => {
    const userTradeFile = path.join(tradesDir, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(userTradeFile)) {
        return res.json({ success: true, trades: [] });
    }
    const trades = JSON.parse(fs.readFileSync(userTradeFile));
    res.json({ success: true, trades: trades });
});

app.get('/api/halal-assets', authenticate, (req, res) => {
    const assets = ['BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'ADAUSDT', 'XRPUSDT'];
    res.json({ success: true, assets: assets, count: assets.length });
});

// ==================== ADMIN ENDPOINTS ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    
    const users = readUsers();
    users[email] = {
        email,
        password: pending[email].password,
        isOwner: false,
        isApproved: true,
        isBlocked: false,
        apiKey: "",
        secretKey: "",
        createdAt: pending[email].requestedAt,
        approvedAt: new Date().toISOString()
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email,
        hasApiKeys: !!users[email].apiKey,
        isOwner: users[email].isOwner,
        isApproved: users[email].isApproved,
        isBlocked: users[email].isBlocked
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const balances = {};
    for (const [email, userData] of Object.entries(users)) {
        balances[email] = {
            spot: 0,
            funding: 0,
            total: 0,
            hasKeys: !!userData.apiKey
        };
    }
    res.json({ success: true, balances });
});

app.get('/api/all-user-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) {
        return res.status(401).json({ success: false, message: 'Current password incorrect' });
    }
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed!' });
});

app.get('/api/settings', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const settings = JSON.parse(fs.readFileSync(settingsFile));
    res.json({ success: true, settings });
});

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`🕋 HALAL TRADING BOT - RUNNING`);
    console.log(`========================================`);
    console.log(`✅ Server URL: http://localhost:${PORT}`);
    console.log(`✅ Owner Email: mujtabahatif@gmail.com`);
    console.log(`✅ Owner Password: Mujtabah@2598`);
    console.log(`✅ Data Directory: ${dataDir}`);
    console.log(`========================================\n`);
});
