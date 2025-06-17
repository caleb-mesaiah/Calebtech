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
app.use(cors({ origin: 'https://calebtech.onrender.com', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
const csrfProtection = csurf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production' } });

// Log environment variables (mask sensitive values)
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

// Configure Multer with Cloudinary storage
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'calebtech/products',
        allowed_formats: ['jpg', 'png', 'webp'],
        transformation: [{ width: 500, height: 500, crop: 'limit' }]
    }
});
const upload = multer({ storage });

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    phone: String,
    resetPasswordToken: String,
    resetPasswordExpires: Date
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

// Nodemailer setup
try {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });
    console.log('Nodemailer configured successfully');
    module.exports.transporter = transporter;
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
        console.log('Auth middleware: Token decoded', decoded);
        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            console.log('Auth middleware: User not found', decoded.id);
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
    console.log('Admin middleware: User role', req.user.role);
    if (!req.user.role) {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Routes
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    const token = req.csrfToken();
    console.log('CSRF token generated:', token);
    res.json({ csrfToken: token });
});

app.post('/api/auth/register', csrfProtection, async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        console.log('Register attempt:', email);
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log('User already exists:', email);
            return res.status(400).json({ message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword, phone });
        await user.save();
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(201).json({ token, user: { name, email, role: user.role, phone } });
        console.log('User registered:', email);
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/login', csrfProtection, async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt:', email);
        const user = await User.findOne({ email });
        if (!user) {
            console.log('Login failed: User not found', email);
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Login failed: Password mismatch', email);
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: { name: user.name, email, role: user.role, phone: user.phone } });
        console.log('User logged in:', email);
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/auth/profile', authMiddleware, async (req, res) => {
    try {
        console.log('Profile request for user:', req.user.email);
        res.json(req.user);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/forgot-password', csrfProtection, async (req, res) => {
    try {
        const { email } = req.body;
        console.log('Forgot password request:', email);
        const user = await User.findOne({ email });
        if (!user) {
            console.log('Forgot password: User not found', email);
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
        await module.exports.transporter.sendMail(mailOptions);
        res.json({ message: 'Password reset email sent' });
        console.log('Password reset email sent to:', email);
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/reset-password', csrfProtection, async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        console.log('Reset password attempt with token:', token);
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
        console.log('Password reset successful for:', user.email);
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json({ products });
        console.log('Products fetched:', products.length);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            console.log('Product not found:', req.params.id);
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json(product);
        console.log('Product fetched:', product.name);
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/products', authMiddleware, adminMiddleware, csrfProtection, upload.single('image'), async (req, res) => {
    try {
        const { name, description, price, brand, stock } = req.body;
        console.log('Add product attempt:', name);
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
        console.log('Product added:', name);
    } catch (error) {
        console.error('Add product error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, csrfProtection, upload.single('image'), async (req, res) => {
    try {
        const { name, description, price, brand, stock } = req.body;
        console.log('Update product attempt:', req.params.id);
        const updateData = {
            name,
            description,
            price: parseFloat(price),
            brand,
            stock: parseInt(stock)
        };
        if (req.file) {
            updateData.image = req.file.path;
            console.log('Product image updated:', req.file.path);
        }
        const product = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
        if (!product) {
            console.log('Product not found:', req.params.id);
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json(product);
        console.log('Product updated:', name);
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/products/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('Delete product attempt:', req.params.id);
        const product = await Product.findByIdAndDelete(req.params.id);
        if (!product) {
            console.log('Product not found:', req.params.id);
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json({ message: 'Product deleted' });
        console.log('Product deleted:', product.name);
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/orders', authMiddleware, csrfProtection, async (req, res) => {
    try {
        const { items, total, shippingAddress } = req.body;
        console.log('Create order attempt:', req.user.email);
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
        await module.exports.transporter.sendMail(mailOptions);
        res.status(201).json(order);
        console.log('Order created:', orderId);
    } catch (error) {
        console.error('Create order error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        console.log('Get orders for user:', req.user.email);
        const orders = await Order.find({ userId: req.user._id }).populate('userId', 'name email');
        res.json(orders);
        console.log('Orders fetched:', orders.length);
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/repairs', csrfProtection, async (req, res) => {
    try {
        const { userId, name, email, phone, deviceType, deviceModel, issue, contactMethod, preferredDate, image } = req.body;
        console.log('Create repair request:', email);
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
        await module.exports.transporter.sendMail(mailOptions);
        res.status(201).json(repair);
        console.log('Repair request created:', repairId);
    } catch (error) {
        console.error('Create repair error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/orders', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('Get admin orders by:', req.user.email);
        const orders = await Order.find().populate('userId', 'name email');
        res.json(orders);
        console.log('Admin orders fetched:', orders.length);
    } catch (error) {
        console.error('Get admin orders error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/orders/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        const { status } = req.body;
        console.log('Update order:', req.params.id);
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'email');
        if (!order) {
            console.log('Order not found:', req.params.id);
            return res.status(404).json({ message: 'Order not found' });
        }
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: order.userId.email,
            subject: 'Order Status Update',
            text: `Your order #${order.orderId} is now ${status}.`
        };
        await module.exports.transporter.sendMail(mailOptions);
        res.json(order);
        console.log('Order updated:', order.orderId);
    } catch (error) {
        console.error('Update order error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/orders/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('Delete order:', req.params.id);
        const order = await Order.findByIdAndDelete(req.params.id);
        if (!order) {
            console.log('Order not found:', req.params.id);
            return res.status(404).json({ message: 'Order not found' });
        }
        res.json({ message: 'Order deleted' });
        console.log('Order deleted:', order.orderId);
    } catch (error) {
        console.error('Delete order error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/repairs', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('Get admin repairs by:', req.user.email);
        const repairs = await Repair.find().populate('userId', 'email');
        res.json(repairs);
        console.log('Admin repairs fetched:', repairs.length);
    } catch (error) {
        console.error('Get repairs error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/repairs/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        const { status } = req.body;
        console.log('Update repair:', req.params.id);
        const repair = await Repair.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'email');
        if (!repair) {
            console.log('Repair not found:', req.params.id);
            return res.status(404).json({ message: 'Repair not found' });
        }
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: repair.email,
            subject: 'Repair Status Update',
            text: `Your repair request #${repair.repairId} is now ${status}.`
        };
        await module.exports.transporter.sendMail(mailOptions);
        res.json(repair);
        console.log('Repair updated:', repair.repairId);
    } catch (error) {
        console.error('Update repair error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/repairs/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('Delete repair:', req.params.id);
        const repair = await Repair.findByIdAndDelete(req.params.id);
        if (!repair) {
            console.log('Repair not found:', req.params.id);
            return res.status(404).json({ message: 'Repair not found' });
        }
        res.json({ message: 'Repair deleted' });
        console.log('Repair deleted:', repair.repairId);
    } catch (error) {
        console.error('Delete repair error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('Get admin users by:', req.user.email);
        const users = await User.find().select('-password');
        res.json(users);
        console.log('Admin users fetched:', users.length);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        const { name, email, phone, role } = req.body;
        console.log('Update user:', req.params.id);
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { name, email, phone, role },
            { new: true }
        ).select('-password');
        if (!user) {
            console.log('User not found:', req.params.id);
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
        console.log('User updated:', user.email);
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, csrfProtection, async (req, res) => {
    try {
        console.log('Delete user:', req.params.id);
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            console.log('User not found:', req.params.id);
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User deleted' });
        console.log('User deleted:', user.email);
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/analytics', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        console.log('Get analytics by:', req.user.email);
        const totalRevenue = await Order.aggregate([
            { $match: { status: 'Delivered' } },
            { $group: { _id: null, total: { $sum: '$total' } } }
        ]);
        const totalOrders = await Order.countDocuments();
        res.json({
            totalRevenue: totalRevenue[0]?.total || 0,
            totalOrders
        });
        console.log('Analytics fetched:', { totalRevenue: totalRevenue[0]?.total || 0, totalOrders });
    } catch (error) {
        console.error('Analytics error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Serve static files
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
