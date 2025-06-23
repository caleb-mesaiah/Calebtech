const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const cloudinary = require('cloudinary').v2; // Use v2 API
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const path = require('path');

const app = express();

// Cloudinary configuration
try {
    cloudinary.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET
    });
    console.log('Cloudinary configured successfully');
} catch (error) {
    console.error('Cloudinary configuration error:', {
        message: error.message,
        stack: error.stack
    });
    process.exit(1); // Exit if Cloudinary fails
}

// Multer storage for Cloudinary
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'calebtech-products',
        allowed_formats: ['jpg', 'png', 'jpeg']
    }
});
const upload = multer({ storage: storage });

// Middleware
app.use(cors({
    origin: 'https://calebtech.onrender.com',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    methods: ['GET', 'POST', 'PUT', 'DELETE']
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// CSRF Middleware
const csrfProtection = csrf({
    cookie: {
        key: '_csrf',
        secure: process.env.NODE_ENV === 'production', // false for local
        sameSite: 'strict',
        maxAge: 3600
    },
    value: (req) => {
        const token = req.headers['x-csrf-token'] || req.body._csrf || req.query._csrf;
        console.log('CSRF token validation', {
            token,
            cookie: req.cookies._csrf,
            headers: req.headers['x-csrf-token'],
            body: req.body._csrf,
            query: req.query._csrf,
            url: req.url,
            method: req.method
        });
        return token;
    }
});

// Apply CSRF protection selectively
app.use((req, res, next) => {
    if (req.method === 'GET' || req.path === '/api/auth/login' || req.path === '/api/csrf-token') {
        return next();
    }
    csrfProtection(req, res, next);
});

// Schemas
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: String,
    role: { type: String, default: 'user' },
    resetToken: String,
    resetTokenExpiration: Date
});

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    price: { type: Number, required: true },
    brand: String,
    stock: { type: Number, default: 0 },
    image: String,
    createdAt: { type: Date, default: Date.now },
    deleted: { type: Boolean, default: false } // Soft deletion
});

const OrderSchema = new mongoose.Schema({
    orderId: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{
        name: String,
        price: Number,
        quantity: Number,
        image: String
    }],
    total: { type: Number, required: true },
    shippingAddress: String,
    status: { type: String, default: 'Pending' },
    createdAt: { type: Date, default: Date.now }
});

const RepairSchema = new mongoose.Schema({
    repairId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    deviceType: String,
    deviceModel: String,
    issue: String,
    contactMethod: String,
    preferredDate: Date,
    status: { type: String, default: 'Pending' },
    image: String
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);
const Repair = mongoose.model('Repair', RepairSchema);

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Auth Middleware
const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id);
        if (!req.user) return res.status(401).json({ message: 'User not found' });
        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Admin Middleware
const adminMiddleware = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Routes
// CSRF Token
app.get('/api/csrf-token', (req, res, next) => {
    try {
        const token = req.csrfToken();
        console.log('CSRF token generated', { token, cookies: req.cookies });
        res.json({ csrfToken: token });
    } catch (error) {
        console.error('CSRF token generation error:', {
            message: error.message,
            stack: error.stack
        });
        res.status(500).json({ message: 'Failed to generate CSRF token' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        console.log('User logged in:', { email: user.email });
        res.json({ token, role: user.role });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Profile
app.get('/api/auth/profile', authMiddleware, (req, res) => {
    res.json({
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role,
        phone: req.user.phone
    });
});

// Register
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, phone } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ message: 'User already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        user = new User({ name, email, password: hashedPassword, phone });
        await user.save();
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        console.log('User registered:', { email });
        res.json({ token, role: user.role });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Forgot Password
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'User not found' });
        const resetToken = Math.random().toString(36).slice(-8);
        user.resetToken = resetToken;
        user.resetTokenExpiration = Date.now() + 3600000; // 1 hour
        await user.save();
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset',
            text: `Your reset code is: ${resetToken}`
        };
        await transporter.sendMail(mailOptions);
        res.json({ message: 'Reset code sent to email' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reset Password
app.post('/api/auth/reset-password', async (req, res) => {
    const { email, resetToken, newPassword } = req.body;
    try {
        const user = await User.findOne({
            email,
            resetToken,
            resetTokenExpiration: { $gt: Date.now() }
        });
        if (!user) return res.status(400).json({ message: 'Invalid or expired reset token' });
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();
        res.json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Products
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find({ deleted: { $ne: true } });
        res.json({ products });
        console.log('Products fetched', { count: products.length });
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add Product
app.post('/api/products', authMiddleware, adminMiddleware, upload.single('image'), async (req, res) => {
    try {
        console.log('CSRF token validated for product addition', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        const { name, description, price, brand, stock } = req.body;
        const image = req.file ? req.file.path : undefined;
        const product = new Product({
            name,
            description,
            price: parseFloat(price),
            brand,
            stock: parseInt(stock),
            image
        });
        await product.save();
        console.log('Product added:', { name });
        res.status(201).json(product);
    } catch (error) {
        console.error('Add product error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update Product
app.put('/api/products/:id', authMiddleware, adminMiddleware, upload.single('image'), async (req, res) => {
    try {
        console.log('CSRF token validated for product update', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        const { name, description, price, brand, stock } = req.body;
        const updateData = {
            name,
            description,
            price: parseFloat(price),
            brand,
            stock: parseInt(stock)
        };
        if (req.file) updateData.image = req.file.path;
        const product = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
        if (!product) return res.status(404).json({ message: 'Product not found' });
        console.log('Product updated:', { name });
        res.json(product);
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete Product (Soft Delete)
app.delete('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for product deletion', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Soft delete product attempt', { id: req.params.id });
        const product = await Product.findByIdAndUpdate(req.params.id, { deleted: true }, { new: true });
        if (!product) {
            console.log('Product not found', { id: req.params.id });
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json({ message: 'Product flagged for deletion' });
        console.log('Product flagged for deletion', { name: product.name });
    } catch (error) {
        console.error('Soft delete product error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Orders
app.get('/api/admin/orders', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const orders = await Order.find().populate('userId');
        res.json(orders);
        console.log('Orders fetched', { count: orders.length });
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update Order Status
app.put('/api/admin/orders/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for order update', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        const { status } = req.body;
        const order = await Order.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!order) return res.status(404).json({ message: 'Order not found' });
        console.log('Order status updated:', { orderId: order.orderId, status });
        res.json(order);
    } catch (error) {
        console.error('Update order error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete Order
app.delete('/api/admin/orders/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for order deletion', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        const order = await Order.findByIdAndDelete(req.params.id);
        if (!order) return res.status(404).json({ message: 'Order not found' });
        console.log('Order deleted:', { orderId: order.orderId });
        res.json({ message: 'Order deleted' });
    } catch (error) {
        console.error('Delete order error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Repairs
app.get('/api/admin/repairs', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const repairs = await Repair.find();
        res.json(repairs);
        console.log('Repairs fetched', { count: repairs.length });
    } catch (error) {
        console.error('Get repairs error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update Repair Status
app.put('/api/admin/repairs/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for repair update', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        const { status } = req.body;
        const repair = await Repair.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!repair) return res.status(404).json({ message: 'Repair not found' });
        console.log('Repair status updated:', { repairId: repair.repairId, status });
        res.json(repair);
    } catch (error) {
        console.error('Update repair error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete Repair
app.delete('/api/admin/repairs/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for repair deletion', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        const repair = await Repair.findByIdAndDelete(req.params.id);
        if (!repair) return res.status(404).json({ message: 'Repair not found' });
        console.log('Repair deleted:', { repairId: repair.repairId });
        res.json({ message: 'Repair deleted' });
    } catch (error) {
        console.error('Delete repair error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
        console.log('Users fetched', { count: users.length });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update User
app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for user update', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        const { name, email, phone, role } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { name, email, phone, role }, { new: true });
        if (!user) return res.status(404).json({ message: 'User not found' });
        console.log('User updated:', { email });
        res.json(user);
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete User
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for user deletion', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        console.log('User deleted:', { email: user.email });
        res.json({ message: 'User deleted' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Analytics
app.get('/api/admin/analytics', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const totalRevenue = await Order.aggregate([
            { $match: { status: 'Delivered' } },
            { $group: { _id: null, total: { $sum: '$total' } } }
        ]);
        const totalOrders = await Order.countDocuments();
        res.json({
            totalRevenue: totalRevenue[0]?.total || 0,
            totalOrders
        });
        console.log('Analytics fetched');
    } catch (error) {
        console.error('Analytics error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// CSRF Error Handler
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        console.error('CSRF Validation Error:', {
            message: err.message,
            tokenReceived: req.headers['x-csrf-token'],
            cookie: req.headers.cookie,
            bodyToken: req.body._csrf,
            url: req.url,
            method: req.method
        });
        return res.status(400).json({ message: 'Invalid CSRF token' });
    }
    console.error('Unexpected Error:', {
        message: err.message,
        stack: err.stack
    });
    res.status(500).json({ message: 'Server error' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 
