const express = require('express');
const app = express();
const router = express.Router();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Authentication middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

// User routes
app.get('/api/users', authMiddleware, (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    res.json({
        users: [],
        page: parseInt(page),
        limit: parseInt(limit)
    });
});

app.get('/api/users/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    res.json({ id, name: 'John Doe', email: 'john@example.com' });
});

app.post('/api/users', authMiddleware, (req, res) => {
    const { name, email, age } = req.body;
    res.status(201).json({ id: 1, name, email, age });
});

app.put('/api/users/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    const { name, email } = req.body;
    res.json({ id, name, email, updated: true });
});

app.delete('/api/users/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    res.status(204).send();
});

// Product routes
router.get('/api/products', (req, res) => {
    const { category, min_price, max_price } = req.query;
    res.json({
        products: [],
        filters: { category, min_price, max_price }
    });
});

router.post('/api/products', (req, res) => {
    const { name, price, category } = req.body;
    res.status(201).json({ id: 1, name, price, category });
});

router.get('/api/products/:id', (req, res) => {
    const { id } = req.params;
    res.json({ id, name: 'Product', price: 99.99 });
});

// Authentication routes
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    res.json({
        token: 'jwt-token-here',
        user: { id: 1, username }
    });
});

app.post('/api/auth/logout', authMiddleware, (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

app.post('/api/auth/refresh', (req, res) => {
    const { refresh_token } = req.body;
    res.json({ token: 'new-jwt-token' });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Documentation
app.get('/docs', (req, res) => {
    res.json({
        title: 'API Documentation',
        version: '1.0.0',
        endpoints: [
            { path: '/api/users', method: 'GET' },
            { path: '/api/users/:id', method: 'GET' },
            { path: '/api/users', method: 'POST' }
        ]
    });
});

// Admin routes
app.get('/admin/users', authMiddleware, (req, res) => {
    const { page = 1, limit = 20 } = req.query;
    res.json({
        users: [],
        total: 100,
        page: parseInt(page),
        limit: parseInt(limit)
    });
});

app.get('/admin/stats', authMiddleware, (req, res) => {
    res.json({
        total_users: 1000,
        active_users: 750,
        total_products: 500
    });
});

// Search endpoint
app.get('/api/search', (req, res) => {
    const { q, type, limit = 10 } = req.query;
    res.json({
        query: q,
        type,
        results: [],
        total: 0
    });
});

// File upload
app.post('/api/upload', (req, res) => {
    const { file, description } = req.body;
    res.json({
        id: 'file-123',
        filename: file,
        description,
        uploaded_at: new Date().toISOString()
    });
});

// Webhook endpoint
app.post('/api/webhooks/github', (req, res) => {
    const { event, payload } = req.body;
    res.json({ received: true, event });
});

// Use router
app.use(router);

module.exports = app; 