const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const csrf = require('csurf');
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const { cloudinary } = require('cloudinary').v2;
const path = require('path');

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

// Cloudinary configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer configuration for file uploads
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'calebtech_products',
        allowed_formats: ['jpg', 'png', 'jpeg']
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Error: Images only (jpg, png, jpeg)!'));
    }
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

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// Schemas
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: String,
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
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
    orderId: { type: String, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    items: [{
        name: String,
        quantity: Number,
        price: Number,
        image: String
    }],
    total: Number,
    status: { type: String, enum: ['Pending', 'Processing', 'Shipped', 'Delivered'], default: 'Pending' },
    shippingAddress: String,
    createdAt: { type: Date, default: Date.now }
});

const RepairSchema = new mongoose.Schema({
    repairId: { type: String, unique: true },
    name: String,
    email: String,
    deviceType: String,
    deviceModel: String,
    issue: String,
    contactMethod: String,
    preferredDate: Date,
    status: { type: String, enum: ['Pending', 'In Progress', 'Completed'], default: 'Pending' },
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

// Authentication middleware
const authMiddleware = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('Auth middleware: No token provided');
        return res.status(401).json({ message: 'No token provided' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        console.log('Auth middleware: Token verified', { userId: decoded.id });
        next();
    } catch (error) {
        console.error('Auth middleware error:', { message: error.message });
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Admin middleware
const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user || user.role !== 'admin') {
            console.log('Admin middleware: Access denied', { userId: req.user.id });
            return res.status(403).json({ message: 'Admin access required' });
        }
        console.log('Admin middleware: Access granted', { userId: req.user.id });
        next();
    } catch (error) {
        console.error('Admin middleware error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
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

// User registration
app.post('/api/auth/register', async (req, res) => {
    try {
        console.log('Register attempt', { email: req.body.email });
        const { name, email, password, phone } = req.body;
        if (!name || !email || !password) {
            console.log('Register: Missing fields', { body: req.body });
            return res.status(400).json({ message: 'All fields are required' });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log('Register: User already exists', { email });
            return res.status(400).json({ message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword, phone });
        await user.save();
        console.log('User registered', { email });
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Register error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
});

// User login
app.post('/api/auth/login', async (req, res) => {
    try {
        console.log('Login attempt', { email: req.body.email });
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            console.log('Login: User not found', { email });
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Login: Invalid password', { email });
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('User logged in', { email, token });
        res.json({ token });
    } catch (error) {
        console.error('Login error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
});

// User profile
app.get('/api/auth/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            console.log('Profile: User not found', { userId: req.user.id });
            return res.status(404).json({ message: 'User not found' });
        }
        console.log('Profile fetched', { email: user.email });
        res.json(user);
    } catch (error) {
        console.error('Profile error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
});

// Products
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find({ deleted: { $ne: true } });
        res.json({ products });
        console.log('Products fetched', { count: products.length });
    } catch (error) {
        console.error('Get products error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/products', authMiddleware, adminMiddleware, upload.single('image'), async (req, res) => {
    try {
        console.log('CSRF token validated for product addition', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Add product attempt', { body: req.body });
        const { name, description, price, stock, brand } = req.body;
        if (!name || !price || !stock) {
            console.log('Add product: Missing fields', { body: req.body });
            return res.status(400).json({ message: 'Name, price, and stock are required' });
        }
        const product = new Product({
            name,
            description,
            price: parseFloat(price),
            stock: parseInt(stock),
            brand,
            image: req.file ? req.file.path : null
        });
        await product.save();
        console.log('Product added', { name });
        res.status(201).json(product);
    } catch (error) {
        console.error('Add product error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, upload.single('image'), async (req, res) => {
    try {
        console.log('CSRF token validated for product update', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Update product attempt', { id: req.params.id, body: req.body });
        const { name, description, price, stock, brand } = req.body;
        const updateData = {
            name,
            description,
            price: parseFloat(price),
            stock: parseInt(stock),
            brand
        };
        if (req.file) {
            updateData.image = req.file.path;
        }
        const product = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
        if (!product) {
            console.log('Product not found', { id: req.params.id });
            return res.status(404).json({ message: 'Product not found' });
        }
        console.log('Product updated', { name });
        res.json(product);
    } catch (error) {
        console.error('Update product error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

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
        console.error('Soft delete product error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

// Orders
app.post('/api/orders', authMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for order creation', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Create order attempt', { userId: req.user.id });
        const { items, total, shippingAddress } = req.body;
        if (!items || !total || !shippingAddress) {
            console.log('Create order: Missing fields', { body: req.body });
            return res.status(400).json({ message: 'All fields are required' });
        }
        const orderCount = await Order.countDocuments();
        const order = new Order({
            orderId: `ORD${1000 + orderCount}`,
            userId: req.user.id,
            items,
            total: parseFloat(total),
            shippingAddress
        });
        await order.save();
        console.log('Order created', { orderId: order.orderId });

        // Send confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: 'Order Confirmation - CalebTech',
            text: `Your order ${order.orderId} has been placed successfully! Total: ₦${total.toLocaleString()}`
        };
        await transporter.sendMail(mailOptions);
        console.log('Order confirmation email sent', { email: req.body.email });

        res.status(201).json(order);
    } catch (error) {
        console.error('Create order error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/orders', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const orders = await Order.find().populate('userId', 'name email');
        console.log('Orders fetched', { count: orders.length });
        res.json(orders);
    } catch (error) {
        console.error('Get orders error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/orders/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for order update', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Update order attempt', { id: req.params.id, status: req.body.status });
        const { status } = req.body;
        const order = await Order.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!order) {
            console.log('Order not found', { id: req.params.id });
            return res.status(404).json({ message: 'Order not found' });
        }
        console.log('Order updated', { orderId: order.orderId, status });
        res.json(order);
    } catch (error) {
        console.error('Update order error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/orders/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for order deletion', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Delete order attempt', { id: req.params.id });
        const order = await Order.findByIdAndDelete(req.params.id);
        if (!order) {
            console.log('Order not found', { id: req.params.id });
            return res.status(404).json({ message: 'Order not found' });
        }
        console.log('Order deleted', { orderId: order.orderId });
        res.json({ message: 'Order deleted' });
    } catch (error) {
        console.error('Delete order error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

// Repairs
app.post('/api/repairs', upload.single('image'), async (req, res) => {
    try {
        console.log('CSRF token validated for repair creation', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Create repair attempt', { body: req.body });
        const { name, email, deviceType, deviceModel, issue, contactMethod, preferredDate } = req.body;
        if (!name || !email || !deviceType || !issue || !contactMethod || !preferredDate) {
            console.log('Create repair: Missing fields', { body: req.body });
            return res.status(400).json({ message: 'All fields are required' });
        }
        const repairCount = await Repair.countDocuments();
        const repair = new Repair({
            repairId: `REP${1000 + repairCount}`,
            name,
            email,
            deviceType,
            deviceModel,
            issue,
            contactMethod,
            preferredDate,
            image: req.file ? req.file.path : null
        });
        await repair.save();
        console.log('Repair created', { repairId: repair.repairId });

        // Send confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Repair Request Confirmation - CalebTech',
            text: `Your repair request ${repair.repairId} has been received!`
        };
        await transporter.sendMail(mailOptions);
        console.log('Repair confirmation email sent', { email });

        res.status(201).json(repair);
    } catch (error) {
        console.error('Create repair error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/repairs', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const repairs = await Repair.find();
        console.log('Repairs fetched', { count: repairs.length });
        res.json(repairs);
    } catch (error) {
        console.error('Get repairs error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/repairs/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for repair update', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Update repair attempt', { id: req.params.id, status: req.body.status });
        const { status } = req.body;
        const repair = await Repair.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!repair) {
            console.log('Repair not found', { id: req.params.id });
            return res.status(404).json({ message: 'Repair not found' });
        }
        console.log('Repair updated', { repairId: repair.repairId, status });
        res.json(repair);
    } catch (error) {
        console.error('Update repair error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/repairs/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for repair deletion', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Delete repair attempt', { id: req.params.id });
        const repair = await Repair.findByIdAndDelete(req.params.id);
        if (!repair) {
            console.log('Repair not found', { id: req.params.id });
            return res.status(404).json({ message: 'Repair not found' });
        }
        console.log('Repair deleted', { repairId: repair.repairId });
        res.json({ message: 'Repair deleted' });
    } catch (error) {
        console.error('Delete repair error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin analytics
app.get('/api/admin/analytics', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const totalRevenue = await Order.aggregate([
            { $match: { status: 'Delivered' } },
            { $group: { _id: null, total: { $sum: '$total' } } }
        ]);
        const totalOrders = await Order.countDocuments();
        console.log('Analytics fetched', { totalRevenue: totalRevenue[0]?.total || 0, totalOrders });
        res.json({
            totalRevenue: totalRevenue[0]?.total || 0,
            totalOrders
        });
    } catch (error) {
        console.error('Analytics error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        console.log('Users fetched', { count: users.length });
        res.json(users);
    } catch (error) {
        console.error('Get users error:', { message: error.message });
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for user update', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Update user attempt', { id: req.params.id, body: req.body });
        const { name, email, phone, role } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { name, email, phone, role }, { new: true });
        if (!user) {
            console.log('User not found', { id: req.params.id });
            return res.status(404).json({ message: 'User not found' });
        }
        console.log('User updated', { email });
        res.json(user);
    } catch (error) {
        console.error('Update user error:', { message: error.message, stack: error.stack });
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('CSRF token validated for user deletion', {
            token: req.headers['x-csrf-token'] || req.body._csrf,
            cookie: req.cookies._csrf
        });
        console.log('Delete user attempt', { id: req.params.id });
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            console.log('User not found', { id: req.params.id });
            return res.status(404).json({ message: 'User not found' });
        }
        console.log('User deleted', { email: user.email });
        res.json({ message: 'User deleted' });
    } catch (error) {
        console.error('Delete user error:', { message: error.message, stack: error.stack });
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
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
