 const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Models
const User = require('./models/User');
const Order = require('./models/Order');
const Repair = require('./models/Repair');
const Product = require('./models/Product');

// Multer for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Auth Middleware
const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token provided' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
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
// User Authentication
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone, address } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword, phone, address, role: 'user' });
        await user.save();

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token, user: { id: user._id, name, email, role: user.role } });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user._id, name: user.name, email, role: user.role } });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/auth/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
    try {
        const { name, phone, address } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { name, phone, address },
            { new: true, runValidators: true }
        ).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const resetLink = `http://localhost:3000/reset-password.html?token=${token}`;

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request',
            html: `<p>Click <a href="${resetLink}">here</a> to reset your password. Link expires in 1 hour.</p>`
        });

        res.json({ message: 'Password reset email sent' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        res.status(400).json({ message: 'Invalid or expired token' });
    }
});

// Products
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/products', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { name, description, price, image } = req.body;
        const product = new Product({ name, description, price, image });
        await product.save();
        res.status(201).json(product);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { name, description, price, image } = req.body;
        const product = await Product.findByIdAndUpdate(
            req.params.id,
            { name, description, price, image },
            { new: true }
        );
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json(product);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const product = await Product.findByIdAndDelete(req.params.id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json({ message: 'Product deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Orders
app.post('/api/orders', authMiddleware, async (req, res) => {
    try {
        const { items, total, shippingAddress } = req.body;
        const orderId = `ORD${Date.now()}`;
        const order = new Order({
            userId: req.user.id,
            orderId,
            items,
            total,
            shippingAddress,
            status: 'Processing'
        });
        await order.save();

        // Send order confirmation email
        const user = await User.findById(req.user.id);
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Order Confirmation',
            html: `<p>Thank you for your order #${orderId}. Total: ₦${total.toLocaleString()}. Status: ${order.status}</p>`
        });

        res.status(201).json(order);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(orders);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/orders', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const orders = await Order.find().sort({ createdAt: -1 }).populate('userId', 'name email');
        res.json(orders);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/orders/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'email');
        if (!order) {
            return res.status(404).json({ message: 'Order not found' });
        }

        // Send status update email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: order.userId.email,
            subject: 'Order Status Update',
            html: `<p>Your order #${order.orderId} is now ${status}.</p>`
        });

        res.json(order);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Repairs
app.post('/api/repairs', upload.single('image'), authMiddleware, async (req, res) => {
    try {
        const { name, email, phone, deviceType, deviceModel, issue, contactMethod, preferredDate } = req.body;
        const repairId = `REP${Date.now()}`;
        const image = req.file ? req.file.filename : null;

        const repair = new Repair({
            userId: req.user.id,
            repairId,
            name,
            email,
            phone,
            deviceType,
            deviceModel,
            issue,
            contactMethod,
            preferredDate,
            image,
            status: 'Pending'
        });
        await repair.save();

        // Send repair confirmation email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Repair Request Confirmation',
            html: `<p>Your repair request #${repairId} for ${deviceType} (${deviceModel}) has been received. Status: ${repair.status}</p>`
        });

        res.status(201).json(repair);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/repairs/user', authMiddleware, async (req, res) => {
    try {
        const repairs = await Repair.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json(repairs);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/repairs', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const repairs = await Repair.find().sort({ createdAt: -1 }).populate('userId', 'name email');
        res.json(repairs);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/repairs/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const repair = await Repair.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'email');
        if (!repair) {
            return res.status(404).json({ message: 'Repair not found' });
        }

        // Send status update email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: repair.userId.email,
            subject: 'Repair Status Update',
            html: `<p>Your repair request #${repairId} is now ${status}.</p>`
        });

        res.json(repair);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/repairs/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const repair = await Repair.findByIdAndDelete(req.params.id);
        if (!repair) {
            return res.status(404).json({ message: 'Repair not found' });
        }
        res.json({ message: 'Repair deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Users (Admin)
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Analytics (Admin)
app.get('/api/admin/analytics', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalOrders = await Order.countDocuments();
        const totalRepairs = await Repair.countDocuments();
        const totalRevenue = await Order.aggregate([
            { $match: { status: 'Delivered' } },
            { $group: { _id: null, total: { $sum: '$total' } } }
        ]);

        res.json({
            totalUsers,
            totalOrders,
            totalRepairs,
            totalRevenue: totalRevenue[0]?.total || 0
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Serve frontend routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
