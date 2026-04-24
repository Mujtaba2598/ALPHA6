const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-trading-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// ==================== HALAL ASSETS LIST ====================
// Only Sharia-compliant cryptocurrencies (no gambling coins, no interest-bearing tokens)
const HALAL_ASSETS = {
    'BTCUSDT': { name: 'Bitcoin', minQty: 0.00001, stepSize: 0.00001 },
    'ETHUSDT': { name: 'Ethereum', minQty: 0.0001, stepSize: 0.0001 },
    'BNBUSDT': { name: 'Binance Coin', minQty: 0.001, stepSize: 0.001 },
    'SOLUSDT': { name: 'Solana', minQty: 0.01, stepSize: 0.01 },
    'ADAUSDT': { name: 'Cardano', minQty: 1, stepSize: 1 },
    'XRPUSDT': { name: 'Ripple', minQty: 1, stepSize: 1 },
    'DOTUSDT': { name: 'Polkadot', minQty: 0.1, stepSize: 0.1 },
    'LINKUSDT': { name: 'Chainlink', minQty: 0.1, stepSize: 0.1 },
    'MATICUSDT': { name: 'Polygon', minQty: 1, stepSize: 1 },
    'AVAXUSDT': { name: 'Avalanche', minQty: 0.01, stepSize: 0.01 }
};

// ==================== DATA DIRECTORIES ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
const pendingDir = path.join(dataDir, 'pending');
const positionsDir = path.join(dataDir, 'positions');
const ordersDir = path.join(dataDir, 'orders');

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);
if (!fs.existsSync(pendingDir)) fs.mkdirSync(pendingDir);
if (!fs.existsSync(positionsDir)) fs.mkdirSync(positionsDir);
if (!fs.existsSync(ordersDir)) fs.mkdirSync(ordersDir);

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(pendingDir, 'pending_users.json');
const settingsFile = path.join(dataDir, 'bot_settings.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}

if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

if (!fs.existsSync(settingsFile)) {
    fs.writeFileSync(settingsFile, JSON.stringify({
        defaultProfitPercent: 0.5,
        maxConcurrentTrades: 1,
        tradeIntervalMinutes: 5
    }, null, 2));
}

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }
function readSettings() { return JSON.parse(fs.readFileSync(settingsFile)); }
function writeSettings(settings) { fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2)); }

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

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: '🤲 100% HALAL Trading Bot - No Riba, No Gharar, No Maysir, No Simulation',
        halalAssets: Object.keys(HALAL_ASSETS).length
    });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
    const hashedPassword = bcrypt.hashSync(password, 10);
    pending[email] = { email, password: hashedPassword, requestedAt: new Date().toISOString(), status: 'pending' };
    writePending(pending);
    res.json({ success: true, message: 'Registration request sent to owner for approval.' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    if (!user) {
        const pending = readPending();
        if (pending[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Your account has been blocked.' });
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
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
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected.` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}.` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email, 
        hasApiKeys: !!users[email].apiKey, 
        isOwner: users[email].isOwner, 
        isApproved: users[email].isApproved, 
        isBlocked: users[email].isBlocked,
        createdAt: users[email].createdAt
    }));
    res.json({ success: true, users: list });
});

// ==================== BINANCE API ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function getServerTime(useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    try {
        const response = await axios.get(`${baseUrl}/api/v3/time`, { timeout: 5000 });
        return response.data.serverTime;
    } catch (error) {
        console.log('Time sync error:', error.message);
        return Date.now();
    }
}

function generateSignature(queryString, secret) {
    return crypto.createHmac('sha256', secret).update(queryString).digest('hex');
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useDemo = false) {
    const timestamp = await getServerTime(useDemo);
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const sortedKeys = Object.keys(allParams).sort();
    const queryString = sortedKeys.map(k => `${k}=${allParams[k]}`).join('&');
    const signature = generateSignature(queryString, secretKey);
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
    const response = await axios({
        method,
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 10000
    });
    return response.data;
}

async function getSpotBalance(apiKey, secretKey, useDemo = false) {
    try {
        const accountData = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useDemo);
        const usdtBalance = accountData.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdtBalance?.free || 0);
    } catch (error) {
        console.error('Balance fetch error:', error.response?.data || error.message);
        return 0;
    }
}

async function getFundingBalance(apiKey, secretKey, useDemo = false) {
    try {
        const timestamp = await getServerTime(useDemo);
        const queryString = `timestamp=${timestamp}`;
        const signature = generateSignature(queryString, secretKey);
        const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
        const url = `${baseUrl}/sapi/v1/asset/get-funding-asset?${queryString}&signature=${signature}`;
        const response = await axios({
            method: 'POST',
            url,
            headers: { 'X-MBX-APIKEY': apiKey, 'Content-Type': 'application/json' },
            timeout: 10000
        });
        const usdtAsset = response.data.find(asset => asset.asset === 'USDT');
        return parseFloat(usdtAsset?.free || 0);
    } catch (error) {
        return 0;
    }
}

async function getCurrentPrice(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

async function getExchangeInfo(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/exchangeInfo?symbol=${symbol}`);
    return response.data;
}

async function getOrderBook(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/depth?symbol=${symbol}&limit=5`);
    return response.data;
}

// ==================== HALAL TRADING ENGINE ====================
// NO RANDOMNESS - Deterministic trading only

class HalalTradingEngine {
    
    constructor() {
        this.assetIndex = 0;
        this.activeTrades = new Map(); // sessionId -> trade data
    }
    
    // Deterministic asset selection - rotates through halal assets
    getNextAsset() {
        const assets = Object.keys(HALAL_ASSETS);
        const asset = assets[this.assetIndex];
        this.assetIndex = (this.assetIndex + 1) % assets.length;
        return asset;
    }
    
    // Get quantity with proper step size
    roundQuantity(quantity, symbol, useDemo = false) {
        const asset = HALAL_ASSETS[symbol];
        if (!asset) return quantity;
        const stepSize = asset.stepSize;
        return Math.floor(quantity / stepSize) * stepSize;
    }
    
    async placeLimitBuyOrder(apiKey, secretKey, symbol, quantity, limitPrice, useDemo = false) {
        const roundedQty = this.roundQuantity(quantity, symbol, useDemo);
        if (roundedQty <= 0) throw new Error('Quantity too small');
        
        const response = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
            symbol,
            side: 'BUY',
            type: 'LIMIT',
            timeInForce: 'GTC',
            quantity: roundedQty.toFixed(8),
            price: limitPrice.toFixed(2)
        }, 'POST', useDemo);
        return response;
    }
    
    async placeLimitSellOrder(apiKey, secretKey, symbol, quantity, limitPrice, useDemo = false) {
        const roundedQty = this.roundQuantity(quantity, symbol, useDemo);
        const response = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
            symbol,
            side: 'SELL',
            type: 'LIMIT',
            timeInForce: 'GTC',
            quantity: roundedQty.toFixed(8),
            price: limitPrice.toFixed(2)
        }, 'POST', useDemo);
        return response;
    }
    
    async checkOrderStatus(apiKey, secretKey, symbol, orderId, useDemo = false) {
        const response = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
            symbol,
            orderId
        }, 'GET', useDemo);
        return response;
    }
    
    async cancelOrder(apiKey, secretKey, symbol, orderId, useDemo = false) {
        const response = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
            symbol,
            orderId
        }, 'DELETE', useDemo);
        return response;
    }
    
    async getOpenOrders(apiKey, secretKey, symbol, useDemo = false) {
        const response = await binanceRequest(apiKey, secretKey, '/api/v3/openOrders', { symbol }, 'GET', useDemo);
        return response;
    }
    
    async executeTrade(sessionId, userEmail, apiKey, secretKey, config, useDemo = false) {
        const { investmentAmount, profitPercent, startedAt, timeLimit } = config;
        
        // Check time limit
        const elapsedHours = (Date.now() - startedAt) / (1000 * 60 * 60);
        if (elapsedHours >= timeLimit) {
            const session = activeSessions.get(sessionId);
            if (session) session.isActive = false;
            return { success: false, message: 'Time limit reached' };
        }
        
        let session = activeSessions.get(sessionId);
        if (!session) {
            session = {
                isActive: true,
                currentProfit: 0,
                trades: [],
                openPosition: null,
                investmentAmount,
                profitPercent,
                startedAt,
                userEmail
            };
            activeSessions.set(sessionId, session);
        }
        
        // Check if we have an open position
        const openPosition = session.openPosition;
        
        // If we have an open position, check if sell order is filled
        if (openPosition && openPosition.sellOrderId) {
            try {
                const orderStatus = await this.checkOrderStatus(
                    apiKey, secretKey, openPosition.symbol,
                    openPosition.sellOrderId, useDemo
                );
                
                if (orderStatus.status === 'FILLED') {
                    const fillPrice = parseFloat(orderStatus.price);
                    const profit = (fillPrice - openPosition.entryPrice) * openPosition.quantity;
                    const profitPercentReal = (profit / (openPosition.entryPrice * openPosition.quantity)) * 100;
                    
                    session.currentProfit += profit;
                    session.trades.push({
                        id: Date.now(),
                        symbol: openPosition.symbol,
                        type: 'SELL',
                        entryPrice: openPosition.entryPrice,
                        exitPrice: fillPrice,
                        quantity: openPosition.quantity,
                        profit: profit,
                        profitPercent: profitPercentReal,
                        timestamp: new Date().toISOString(),
                        status: 'COMPLETED'
                    });
                    
                    // Save to trade history
                    const userTradeFile = path.join(tradesDir, userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let allTrades = [];
                    if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
                    allTrades.unshift({
                        symbol: openPosition.symbol,
                        entryPrice: openPosition.entryPrice,
                        exitPrice: fillPrice,
                        quantity: openPosition.quantity,
                        profit: profit,
                        profitPercent: profitPercentReal,
                        timestamp: new Date().toISOString()
                    });
                    fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
                    
                    session.openPosition = null;
                    
                    return { 
                        success: true, 
                        trade: { 
                            symbol: openPosition.symbol, 
                            profit: profit, 
                            profitPercent: profitPercentReal,
                            message: `✅ Position closed! Profit: $${profit.toFixed(2)} (${profitPercentReal.toFixed(2)}%)`
                        } 
                    };
                }
                
                return { success: true, message: `Waiting for sell order to fill at $${openPosition.sellLimitPrice}` };
                
            } catch (error) {
                console.error('Order check error:', error.message);
                return { success: false, error: error.message };
            }
        }
        
        // If we have an open position with buy order placed
        if (openPosition && openPosition.buyOrderId && !openPosition.entryPrice) {
            try {
                const orderStatus = await this.checkOrderStatus(
                    apiKey, secretKey, openPosition.symbol,
                    openPosition.buyOrderId, useDemo
                );
                
                if (orderStatus.status === 'FILLED') {
                    const fillPrice = parseFloat(orderStatus.price);
                    const filledQuantity = parseFloat(orderStatus.executedQty);
                    
                    openPosition.entryPrice = fillPrice;
                    openPosition.quantity = filledQuantity;
                    openPosition.status = 'OWNED';
                    
                    // Now place sell order at profit target
                    const sellPrice = fillPrice * (1 + session.profitPercent / 100);
                    const sellOrder = await this.placeLimitSellOrder(
                        apiKey, secretKey, openPosition.symbol,
                        filledQuantity, sellPrice, useDemo
                    );
                    
                    openPosition.sellOrderId = sellOrder.orderId;
                    openPosition.sellLimitPrice = sellPrice;
                    
                    session.trades.push({
                        id: Date.now(),
                        symbol: openPosition.symbol,
                        type: 'BUY_FILLED',
                        entryPrice: fillPrice,
                        quantity: filledQuantity,
                        timestamp: new Date().toISOString(),
                        message: `Buy order filled at $${fillPrice}`
                    });
                    
                    return { 
                        success: true, 
                        message: `✅ Buy order filled! Own ${filledQuantity} ${openPosition.symbol} at $${fillPrice}. Sell order placed at $${sellPrice} (${session.profitPercent}% profit target)`
                    };
                    
                } else if (orderStatus.status === 'EXPIRED' || orderStatus.status === 'CANCELED') {
                    session.openPosition = null;
                    return { success: true, message: 'Buy order expired, will place new order' };
                }
                
                return { success: true, message: `Waiting for buy order to fill at $${openPosition.buyLimitPrice}` };
                
            } catch (error) {
                console.error('Buy order check error:', error.message);
                return { success: false, error: error.message };
            }
        }
        
        // No open position - place new limit buy order
        if (!openPosition) {
            // Check balance
            const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
            const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
            const totalBalance = spotBalance + fundingBalance;
            
            if (totalBalance < investmentAmount) {
                return { success: false, error: `Insufficient balance. Need ${investmentAmount} USDT, have ${totalBalance.toFixed(2)} USDT (Spot: ${spotBalance.toFixed(2)}, Funding: ${fundingBalance.toFixed(2)})` };
            }
            
            // Select asset deterministically
            const symbol = this.getNextAsset();
            const currentPrice = await getCurrentPrice(symbol, useDemo);
            const orderBook = await getOrderBook(symbol, useDemo);
            
            // Use best bid as buy limit (deterministic, not random)
            const bestBid = parseFloat(orderBook.bids[0]?.[0] || currentPrice);
            const buyLimitPrice = bestBid * 0.999; // 0.1% below best bid
            
            const quantity = investmentAmount / buyLimitPrice;
            const roundedQty = this.roundQuantity(quantity, symbol, useDemo);
            
            if (roundedQty <= 0) {
                return { success: false, error: `Quantity too small for ${symbol}. Minimum: ${HALAL_ASSETS[symbol]?.minQty}` };
            }
            
            try {
                const buyOrder = await this.placeLimitBuyOrder(
                    apiKey, secretKey, symbol, roundedQty, buyLimitPrice, useDemo
                );
                
                session.openPosition = {
                    symbol: symbol,
                    buyOrderId: buyOrder.orderId,
                    buyLimitPrice: buyLimitPrice,
                    quantity: roundedQty,
                    status: 'BUY_ORDER_PLACED',
                    createdAt: new Date().toISOString()
                };
                
                session.trades.push({
                    id: Date.now(),
                    symbol: symbol,
                    type: 'BUY_ORDER_PLACED',
                    limitPrice: buyLimitPrice,
                    quantity: roundedQty,
                    timestamp: new Date().toISOString(),
                    message: `Limit buy order placed for ${symbol} at $${buyLimitPrice}`
                });
                
                return { 
                    success: true, 
                    message: `📈 Buy order placed: ${roundedQty} ${symbol} @ $${buyLimitPrice} (Current: $${currentPrice})`
                };
                
            } catch (error) {
                console.error('Buy order error:', error.message);
                return { success: false, error: error.message };
            }
        }
        
        return { success: true, message: 'Monitoring orders...' };
    }
}

// Active sessions storage
const activeSessions = new Map();
const tradingEngine = new HalalTradingEngine();

// ==================== TRADING API ENDPOINTS ====================

app.post('/api/start-halal-trading', authenticate, async (req, res) => {
    const { 
        investmentAmount,
        profitPercent,
        timeLimit,
        accountType
    } = req.body;
    
    // Validation
    if (investmentAmount < 10) {
        return res.status(400).json({ success: false, message: 'Minimum investment is $10' });
    }
    
    if (profitPercent < 0.1 || profitPercent > 5) {
        return res.status(400).json({ success: false, message: 'Profit target must be between 0.1% and 5%' });
    }
    
    if (timeLimit < 0.5 || timeLimit > 168) {
        return res.status(400).json({ success: false, message: 'Time limit must be between 0.5 and 168 hours' });
    }
    
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) {
        return res.status(400).json({ success: false, message: 'Please add API keys first' });
    }
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = (accountType === 'testnet');
    
    // Verify balance
    try {
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        const totalBalance = spotBalance + fundingBalance;
        
        if (totalBalance < investmentAmount) {
            return res.status(400).json({ 
                success: false, 
                message: `Insufficient balance. You have ${totalBalance.toFixed(2)} USDT (Spot: ${spotBalance.toFixed(2)}, Funding: ${fundingBalance.toFixed(2)}), need ${investmentAmount}` 
            });
        }
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Failed to verify balance. Check API keys.' });
    }
    
    const sessionId = 'halal_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
    const settings = readSettings();
    const checkIntervalMs = settings.tradeIntervalMinutes * 60 * 1000;
    
    // Start trading loop
    const tradeInterval = setInterval(async () => {
        const session = activeSessions.get(sessionId);
        if (!session || !session.isActive) {
            clearInterval(tradeInterval);
            activeSessions.delete(sessionId);
            return;
        }
        
        const result = await tradingEngine.executeTrade(
            sessionId,
            req.user.email,
            apiKey,
            secretKey,
            {
                investmentAmount,
                profitPercent,
                startedAt: session.startedAt,
                timeLimit
            },
            useDemo
        );
        
        // Store result for client polling
        const sessionData = activeSessions.get(sessionId);
        if (sessionData) {
            sessionData.lastResult = result;
        }
        
    }, checkIntervalMs);
    
    activeSessions.set(sessionId, {
        isActive: true,
        currentProfit: 0,
        trades: [],
        openPosition: null,
        investmentAmount,
        profitPercent,
        timeLimit,
        startedAt: Date.now(),
        userEmail: req.user.email,
        interval: tradeInterval,
        lastResult: null
    });
    
    const mode = useDemo ? 'TESTNET (Practice)' : 'REAL BINANCE';
    res.json({ 
        success: true, 
        sessionId, 
        message: `🕋 HALAL TRADING STARTED (${mode})!\n\n✅ Trading ${Object.keys(HALAL_ASSETS).length} halal assets in rotation\n✅ Fixed ${profitPercent}% profit target per trade\n✅ Limit orders only - no gambling\n✅ No randomness - deterministic trading\n\nBot will place limit buy orders and wait for fills, then sell at your profit target.`
    });
});

app.post('/api/stop-halal-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const session = activeSessions.get(sessionId);
    if (session) {
        if (session.interval) {
            clearInterval(session.interval);
        }
        session.isActive = false;
        activeSessions.delete(sessionId);
    }
    res.json({ success: true, message: 'Halal trading stopped' });
});

app.post('/api/halal-session-status', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const session = activeSessions.get(sessionId);
    if (!session) {
        return res.json({ success: true, active: false });
    }
    
    const elapsedHours = (Date.now() - session.startedAt) / (1000 * 60 * 60);
    const timeRemaining = Math.max(0, session.timeLimit - elapsedHours);
    const progressPercent = session.targetProfit ? (session.currentProfit / session.targetProfit) * 100 : 0;
    
    res.json({
        success: true,
        active: session.isActive,
        currentProfit: session.currentProfit,
        openPosition: session.openPosition,
        trades: session.trades.slice(-20),
        timeRemaining: timeRemaining,
        totalTrades: session.trades.filter(t => t.type === 'SELL').length,
        lastResult: session.lastResult,
        profitPercent: session.profitPercent,
        investmentAmount: session.investmentAmount
    });
});

// ==================== API KEY MANAGEMENT ====================

app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey, accountType } = req.body;
    if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
    
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    const useDemo = (accountType === 'testnet');
    
    try {
        const spotBalance = await getSpotBalance(cleanApi, cleanSecret, useDemo);
        const fundingBalance = await getFundingBalance(cleanApi, cleanSecret, useDemo);
        
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        
        const mode = useDemo ? 'Testnet' : 'Real Binance';
        res.json({ 
            success: true, 
            message: `${mode} API keys saved!`, 
            spotBalance: spotBalance,
            fundingBalance: fundingBalance,
            totalBalance: spotBalance + fundingBalance
        });
    } catch (error) {
        console.error('API verification error:', error.response?.data || error.message);
        res.status(401).json({ success: false, message: 'Invalid API keys. Please ensure Spot & Margin trading permissions are enabled.' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = (accountType === 'testnet');
    
    try {
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        const mode = useDemo ? 'Testnet' : 'Real Binance';
        
        res.json({ 
            success: true, 
            spotBalance: spotBalance,
            fundingBalance: fundingBalance,
            totalBalance: spotBalance + fundingBalance,
            message: `Connected to ${mode}! Spot: ${spotBalance.toFixed(2)} USDT | Funding: ${fundingBalance.toFixed(2)} USDT` 
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Connection failed. Check your API keys and permissions.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No keys set' });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== BALANCE ENDPOINTS ====================

app.post('/api/get-balance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No API keys' });
    
    try {
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        
        res.json({ 
            success: true, 
            spotBalance: spotBalance, 
            fundingBalance: fundingBalance, 
            total: spotBalance + fundingBalance 
        });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ==================== TRADE HISTORY ENDPOINTS ====================

app.get('/api/trade-history', authenticate, (req, res) => {
    const userTradeFile = path.join(tradesDir, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(userTradeFile)) {
        return res.json({ success: true, trades: [] });
    }
    const trades = JSON.parse(fs.readFileSync(userTradeFile));
    res.json({ success: true, trades: trades });
});

app.get('/api/all-user-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    
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

// ==================== ADMIN BALANCE ENDPOINTS ====================

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    
    const users = readUsers();
    const balances = {};
    
    for (const [email, userData] of Object.entries(users)) {
        if (!userData.apiKey) {
            balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: false };
            continue;
        }
        
        try {
            const apiKey = decrypt(userData.apiKey);
            const secretKey = decrypt(userData.secretKey);
            const spotBalance = await getSpotBalance(apiKey, secretKey, false);
            const fundingBalance = await getFundingBalance(apiKey, secretKey, false);
            
            balances[email] = {
                spot: spotBalance,
                funding: fundingBalance,
                total: spotBalance + fundingBalance,
                hasKeys: true,
                lastUpdated: new Date().toISOString()
            };
        } catch (error) {
            balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: true, error: error.message };
        }
    }
    
    res.json({ success: true, balances });
});

// ==================== HALAL ASSETS ENDPOINT ====================

app.get('/api/halal-assets', authenticate, (req, res) => {
    res.json({ 
        success: true, 
        assets: HALAL_ASSETS,
        count: Object.keys(HALAL_ASSETS).length
    });
});

// ==================== SETTINGS ENDPOINTS ====================

app.get('/api/settings', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const settings = readSettings();
    res.json({ success: true, settings });
});

app.post('/api/settings', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { defaultProfitPercent, maxConcurrentTrades, tradeIntervalMinutes } = req.body;
    const settings = { defaultProfitPercent, maxConcurrentTrades, tradeIntervalMinutes };
    writeSettings(settings);
    res.json({ success: true, message: 'Settings updated' });
});

// ==================== PASSWORD CHANGE ====================

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

// ==================== CATCH-ALL ROUTE ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 100% HALAL TRADING BOT - NO SIMULATION, NO RANDOMNESS`);
    console.log(`========================================================`);
    console.log(`✅ ${Object.keys(HALAL_ASSETS).length} Halal Assets Available`);
    console.log(`✅ No Riba (Interest) - No leverage`);
    console.log(`✅ No Gharar (Uncertainty) - Limit orders only`);
    console.log(`✅ No Maysir (Gambling) - Deterministic trading, no randomness`);
    console.log(`✅ Actual asset ownership required before selling`);
    console.log(`✅ Spot + Funding wallet balances combined`);
    console.log(`✅ User trade history tracking`);
    console.log(`✅ Admin: Block/unblock users, view all balances`);
    console.log(`========================================================`);
    console.log(`Owner: mujtabahatif@gmail.com`);
    console.log(`Server running on port: ${PORT}`);
});
