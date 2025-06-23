const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;

const app = express();

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

// CSP Header
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", 
        "default-src 'self'; " +
        "script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net 'unsafe-eval'; " +
        "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: https://res.cloudinary.com; " +
        "connect-src 'self' https://calebtech.onrender.com");
    next();
});

// Request Logging
app.use((req, res, next) => {
    console.log('Request:', {
        method: req.method,
        url: req.url,
        headers: {
            'X-CSRF-Token': req.headers['x-csrf-token'],
            Cookie: req.headers.cookie,
            Authorization: req.headers.authorization ? 'Bearer <redacted>' : undefined
        }
    });
    next();
});

// CSRF Middleware
const csrfProtection = csurf({
    cookie: {
        key: '_csrf',
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 3600
    },
    value: (req) => req.headers['x-csrf-token'] || req.body._csrf
});

// Log Environment Variables
console.log('Environment variables:', {
    MONGODB_URI: process.env.MONGODB_URI ? 'Set' : 'Missing',
    JWT_SECRET: process.env.JWT_SECRET ? 'Set' : 'Missing',
    EMAIL_USER: process.env.EMAIL_USER ? 'Set' : 'Missing',
    EMAIL_PASS: process.env.EMAIL_PASS ? 'Set' : 'Missing',
    CLOUDINARY_CLOUD_NAME: process.env.CLOUDINARY_CLOUD_NAME ? 'Set' : 'Missing',
    CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY ? 'Set' : 'Missing',
    CLOUDINARY_API_SECRET: process.env.CLOUDINARY_API_SECRET ? 'Set' : 'Missing'
});

// Configure Cloudinary
try {
    cloudinary.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET
    });
    console.log('Cloudinary configured successfully');
} catch (error) {
    console.error('Cloudinary config error:', error);
}

// Configure Multer with Cloudinary Storage
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'calebtech/products',
        allowed_formats: ['jpg', 'png', 'webp'],
        transformation: [{ width: 500, height: 500, crop: 'limit' }]
    }
});
const upload = multer({ storage });

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected', { database: mongoose.connection.db.databaseName }))
    .catch(err => console.error('MongoDB connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    phone: String,
    address: String,
    likedProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    price: { type: Number, required: true },
    brand: String,
    stock: { type: Number, default: 0 },
    image: String,
    createdAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
    orderId: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{
        productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        name: String,
        quantity: Number,
        price: Number,
        image: String
    }],
    total: { type: Number, required: true },
    shippingAddress: String,
    status: { type: String, default: 'Pending' },
    createdAt: { type: Date, default: Date.now }
});

const RepairSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    repairId: { type: String, required: true, unique: true },
    name: String,
    email: String,
    phone: String,
    deviceType: String,
    deviceModel: String,
    issue: String,
    contactMethod: String,
    preferredDate: Date,
    image: String,
    status: { type: String, default: 'Pending' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);
const Repair = mongoose.model('Repair', RepairSchema);

// Nodemailer Setup
let transporter;
try {
    transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });
    console.log('Nodemailer configured successfully');
} catch (error) {
    console.error('Nodemailer config error:', error);
}

// Middleware
const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        console.log('Auth middleware: No token provided');
        return res.status(401).json({ message: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Auth middleware: Token decoded', { userId: decoded.id });
        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            console.log('Auth middleware: User not found', { userId: decoded.id });
            return res.status(401).json({ message: 'User not found' });
        }
        req.user = user;
        next();
    } catch (error) {
        console.error('JWT verification error:', error);
        res.status(401).json({ message: 'Invalid token' });
    }
};

const adminMiddleware = (req, res, next) => {
    console.log('Admin middleware: Checking role', { role: req.user.role });
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Routes
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    const token = req.csrfToken();
    console.log('CSRF token generated', { token, cookies: req.cookies });
    res.cookie('_csrf', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 3600 });
    res.json({ csrfToken: token });
});

app.post('/api/auth/register', csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for register');
        const { name, email, password, phone } = req.body;
        console.log('Register attempt', { email });
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log('User already exists', { email });
            return res.status(400).json({ message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword, phone });
        await user.save();
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(201).json({ token, user: { name, email, role: user.role, phone } });
        console.log('User registered', { email });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/login', csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for login', { 
            tokenReceived: req.headers['x-csrf-token'],
            cookie: req.cookies._csrf
        });
        const { email, password } = req.body;
        console.log('Login attempt', { email });
        const user = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
        if (!user) {
            console.log('Login failed: User not found', { email });
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Login failed: Password mismatch', { email });
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: { name: user.name, email, role: user.role, phone: user.phone } });
        console.log('User logged in', { email });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/auth/profile', authMiddleware, async (req, res) => {
    try {
        console.log('Profile request', { email: req.user.email });
        res.json(req.user);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/forgot-password', csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for forgot-password');
        const { email } = req.body;
        console.log('Forgot password request', { email });
        const user = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
        if (!user) {
            console.log('Forgot password: User not found', { email });
            return res.status(404).json({ message: 'User not found' });
        }
        const token = Math.random().toString(36).substring(2);
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset',
            text: `Click here to reset your password: https://calebtech.onrender.com/reset-password.html?token=${token}`
        };
        await transporter.sendMail(mailOptions);
        res.json({ message: 'Password reset email sent' });
        console.log('Password reset email sent', { email });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/reset-password', csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for reset-password');
        const { token, newPassword } = req.body;
        console.log('Reset password attempt', { token });
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });
        if (!user) {
            console.log('Reset password: Invalid or expired token');
            return res.status(400).json({ message: 'Invalid or expired token' });
        }
        user.password = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        res.json({ message: 'Password reset successful' });
        console.log('Password reset successful', { email: user.email });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json({ products });
        console.log('Products fetched', { count: products.length });
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            console.log('Product not found', { id: req.params.id });
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json(product);
        console.log('Product fetched', { name: product.name });
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/products', authMiddleware, adminMiddleware, csrfProtection, upload.single('image'), async (req, res) => {
    try {
        console.log('CSRF token validated for product addition');
        const { name, description, price, brand, stock } = req.body;
        console.log('Add product attempt', { name, price, stock, description, brand, hasImage: !!req.file });
        if (!name || !price || !stock) {
            console.log('Validation failed: Missing required fields', { name, price, stock });
            return res.status(400).json({ message: 'Name, price, and stock are required' });
        }
        if (isNaN(parseFloat(price)) || isNaN(parseInt(stock))) {
            console.log('Validation failed: Invalid price or stock', { price, stock });
            return res.status(400).json({ message: 'Price and stock must be valid numbers' });
        }
        const image = req.file ? req.file.path : null;
        const newProduct = new Product({
            name,
            description,
            price: parseFloat(price),
            brand,
            stock: parseInt(stock),
            image
        });
        await newProduct.save();
        res.status(201).json(newProduct);
        console.log('Product added', { name });
    } catch (error) {
        console.error('Add product error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, csrfProtection, upload.single('image'), async (req, res) => {
    try {
        console.log('CSRF token validated for product update');
        const { name, description, price, brand, stock } = req.body;
        console.log('Update product attempt', { id: req.params.id, name, price, stock, description, brand, hasImage: !!req.file });
        if (!name || !price || !stock) {
            console.log('Validation failed: Missing required fields', { name, price, stock });
            return res.status(400).json({ message: 'Name, price, and stock are required' });
        }
        if (isNaN(parseFloat(price)) || isNaN(parseInt(stock))) {
            console.log('Validation failed: Invalid price or stock', { price, stock });
            return res.status(400).json({ message: 'Price and stock must be valid numbers' });
        }
        const updateData = {
            name,
            description,
            price: parseFloat(price),
            brand,
            stock: parseInt(stock)
        };
        if (req.file) {
            updateData.image = req.file.path;
            console.log('Product image updated', { path: req.file.path });
        }
        const product = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
        if (!product) {
            console.log('Product not found', { id: req.params.id });
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json(product);
        console.log('Product updated', { name });
    } catch (error) {
        console.error('Update product error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/products/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for product deletion');
        console.log('Delete product attempt', { id: req.params.id });
        const product = await Product.findByIdAndDelete(req.params.id);
        if (!product) {
            console.log('Product not found', { id: req.params.id });
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json({ message: 'Product deleted' });
        console.log('Product deleted', { name: product.name });
    } catch (error) {
        console.error('Delete product error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/orders', authMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for order creation');
        const { items, total, shippingAddress } = req.body;
        console.log('Create order attempt', { email: req.user.email });
        const orderId = `ORD${Date.now()}`;
        const order = new Order({
            orderId,
            userId: req.user._id,
            items,
            total: parseFloat(total),
            shippingAddress
        });
        await order.save();
        const user = await User.findById(req.user._id);
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Order Confirmation',
            text: `Your order #${orderId} has been placed successfully. Total: ₦${total}`
        };
        await transporter.sendMail(mailOptions);
        res.status(201).json(order);
        console.log('Order created', { orderId });
    } catch (error) {
        console.error('Create order error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        console.log('Get orders', { email: req.user.email });
        const orders = await Order.find({ userId: req.user._id }).populate('userId', 'name email');
        res.json(orders);
        console.log('Orders fetched', { count: orders.length });
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/repairs', csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for repair creation');
        const { userId, name, email, phone, deviceType, deviceModel, issue, contactMethod, preferredDate, image } = req.body;
        console.log('Create repair request', { email });
        const repairId = `REP${Date.now()}`;
        const repair = new Repair({
            userId,
            repairId,
            name,
            email,
            phone,
            deviceType,
            deviceModel,
            issue,
            contactMethod,
            preferredDate,
            image
        });
        await repair.save();
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Repair Request Confirmation',
            text: `Your repair request #${repairId} has been received. We'll contact you soon.`
        };
        await transporter.sendMail(mailOptions);
        res.status(201).json(repair);
        console.log('Repair request created', { repairId });
    } catch (error) {
        console.error('Create repair error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/orders', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('Get admin orders', { email: req.user.email });
        const orders = await Order.find().populate('userId', 'name email');
        res.json(orders);
        console.log('Admin orders fetched', { count: orders.length });
    } catch (error) {
        console.error('Get admin orders error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/orders/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for order update');
        const { status } = req.body;
        console.log('Update order', { id: req.params.id });
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'email');
        if (!order) {
            console.log('Order not found', { id: req.params.id });
            return res.status(404).json({ message: 'Order not found' });
        }
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: order.userId.email,
            subject: 'Order Status Update',
            text: `Your order #${order.orderId} is now ${status}.`
        };
        await transporter.sendMail(mailOptions);
        res.json(order);
        console.log('Order updated', { orderId: order.orderId });
    } catch (error) {
        console.error('Update order error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/orders/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for order deletion');
        console.log('Delete order', { id: req.params.id });
        const order = await Order.findByIdAndDelete(req.params.id);
        if (!order) {
            console.log('Order not found', { id: req.params.id });
            return res.status(404).json({ message: 'Order not found' });
        }
        res.json({ message: 'Order deleted' });
        console.log('Order deleted', { orderId: order.orderId });
    } catch (error) {
        console.error('Delete order error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/repairs', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('Get admin repairs', { email: req.user.email });
        const repairs = await Repair.find().populate('userId', 'email');
        res.json(repairs);
        console.log('Admin repairs fetched', { count: repairs.length });
    } catch (error) {
        console.error('Get repairs error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/repairs/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for repair update');
        const { status } = req.body;
        console.log('Update repair', { id: req.params.id });
        const repair = await Repair.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'email');
        if (!repair) {
            console.log('Repair not found', { id: req.params.id });
            return res.status(404).json({ message: 'Repair not found' });
        }
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: repair.email,
            subject: 'Repair Status Update',
            text: `Your repair request #${repair.repairId} is now ${status}.`
        };
        await transporter.sendMail(mailOptions);
        res.json(repair);
        console.log('Repair updated', { repairId: repair.repairId });
    } catch (error) {
        console.error('Update repair error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/repairs/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for repair deletion');
        console.log('Delete repair', { id: req.params.id });
        const repair = await Repair.findByIdAndDelete(req.params.id);
        if (!repair) {
            console.log('Repair not found', { id: req.params.id });
            return res.status(404).json({ message: 'Repair not found' });
        }
        res.json({ message: 'Repair deleted' });
        console.log('Repair deleted', { repairId: repair.repairId });
    } catch (error) {
        console.error('Delete repair error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('Get admin users', { email: req.user.email });
        const users = await User.find().select('-password');
        res.json(users);
        console.log('Admin users fetched', { count: users.length });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for user update');
        const { name, email, phone, role } = req.body;
        console.log('Update user', { id: req.params.id });
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { name, email, phone, role },
            { new: true }
        ).select('-password');
        if (!user) {
            console.log('User not found', { id: req.params.id });
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
        console.log('User updated', { email: user.email });
    } catch (error) {
        console.error('Update user error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('CSRF token validated for user deletion');
        console.log('Delete user', { id: req.params.id });
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            console.log('User not found', { id: req.params.id });
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User deleted' });
        console.log('User deleted', { email: user.email });
    } catch (error) {
        console.error('Delete user error:', { error: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/analytics', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('Get analytics', { email: req.user.email });
        const totalRevenue = await Order.aggregate([
            { $match: { status: 'Delivered' } },
            { $group: { _id: null, total: { $sum: '$total' } } }
        ]);
        const totalOrders = await Order.countDocuments();
        res.json({
            totalRevenue: totalRevenue[0]?.total || 0,
            totalOrders
        });
        console.log('Analytics fetched', { totalRevenue: totalRevenue[0]?.total || 0, totalOrders });
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
        return res.status(403).json({ message: 'Invalid CSRF token' });
    }
    console.error('Unexpected Error:', {
        message: err.message,
        stack: err.stack
    });
    res.status(500).json({ message: 'Server error' });
});

// Serve Static Files
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
