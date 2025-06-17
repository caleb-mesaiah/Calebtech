const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const axios = require('axios');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, process.env.UPLOAD_DIR || 'public')));

// CSRF protection
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' // Added for better cookie handling
  }
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.error('CSRF token error:', err);
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  next(err);
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Models
const User = require('./models/User');
const Order = require('./models/Order');
const Repair = require('./models/Repair');
const Product = require('./models/Product');

// Multer for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, process.env.UPLOAD_DIR || 'public', 'Uploads/')),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
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

// Input Validation Middleware
const validateProductInput = (req, res, next) => {
  const { name, description, price, brand, stock, image } = req.body;
  if (!name || !description || !price || !brand || !stock || !image) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  if (typeof price !== 'number' || price < 0) {
    return res.status(400).json({ message: 'Invalid price' });
  }
  if (typeof stock !== 'number' || stock < 0) {
    return res.status(400).json({ message: 'Invalid stock' });
  }
  next();
};

// CSRF Token Route
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  try {
    const token = req.csrfToken();
    console.log('CSRF token generated:', token);
    res.json({ csrfToken: token });
  } catch (error) {
    console.error('CSRF token generation error:', error);
    res.status(500).json({ message: 'Failed to generate CSRF token' });
  }
});
// Routes
// User Authentication
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone, address } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const normalizedEmail = email.toLowerCase();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email: normalizedEmail,
      password: hashedPassword,
      phone,
      address,
      role: 'user',
      likedProducts: []
    });
    await user.save();
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, name, email: normalizedEmail, role: user.role } });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', csrfProtection, async (req, res) => {
  try {
    const { email, password, _csrf } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials: User not found' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials: Incorrect password' });
    }
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    console.error('Profile error:', error);
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
    console.error('Profile update error:', error);
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
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const resetLink = `${process.env.APP_URL || 'https://calebtech.onrender.com'}/reset-password.html?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password. Link expires in 1 hour.</p>`
    });
    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/reset-password', csrfProtection, async (req, res) => {
  try {
    const { token, password, _csrf } = req.body;
    console.log('Reset password request:', { token, password: '***', _csrf });
    if (!token || !password) {
      console.warn('Missing token or password');
      return res.status(400).json({ message: 'Token and password are required' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      console.warn('User not found for reset password:', decoded.userId);
      return res.status(400).json({ message: 'Invalid or expired token' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();
    console.log('Password reset successful for:', user.email);
    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', {
      message: error.message,
      stack: error.stack,
      token: req.body.token,
      csrf: req.body._csrf
    });
    res.status(500).json({ message: 'Server error' });
  }
});

// Products
app.get('/api/products', async (req, res) => {
  try {
    const { search, brand, priceMin, priceMax } = req.query;
    let query = {};
    if (search) query.name = { $regex: search, $options: 'i' };
    if (brand) query.brand = brand;
    if (priceMin || priceMax) {
      query.price = {};
      if (priceMin) query.price.$gte = Number(priceMin);
      if (priceMax) query.price.$lte = Number(priceMax);
    }
    const products = await Product.find(query);
    res.json({ products });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });
    res.json(product);
  } catch (error) {
    console.error('Get product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/products', authMiddleware, adminMiddleware, validateProductInput, async (req, res) => {
  try {
    const { name, description, price, brand, stock, image } = req.body;
    const product = new Product({ name, description, price, brand, stock, image });
    await product.save();
    res.status(201).json(product);
  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, validateProductInput, async (req, res) => {
  try {
    const { name, description, price, brand, stock, image } = req.body;
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { name, description, price, brand, stock, image },
      { new: true }
    );
    if (!product) return res.status(404).json({ message: 'Product not found' });
    res.json(product);
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });
    res.json({ message: 'Product deleted' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Likes
app.post('/api/likes/:id', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });
    const user = await User.findById(req.user.id);
    if (user.likedProducts.includes(product._id)) {
      return res.status(400).json({ message: 'Product already liked' });
    }
    user.likedProducts.push(product._id);
    await user.save();
    res.json({ message: 'Product liked' });
  } catch (error) {
    console.error('Like product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/likes/:id', authMiddleware, csrfProtection, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });
    const user = await User.findById(req.user.id);
    const index = user.likedProducts.indexOf(product._id);
    if (index === -1) return res.status(400).json({ message: 'Product not liked' });
    user.likedProducts.splice(index, 1);
    await user.save();
    res.json({ message: 'Product unliked' });
  } catch (error) {
    console.error('Unlike product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Orders
app.post('/api/orders', authMiddleware, async (req, res) => {
  try {
    const { items, total, shippingAddress } = req.body;
    if (!items?.length || !total || !shippingAddress) {
      return res.status(400).json({ message: 'All fields are required' });
    }
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
    const user = await User.findById(req.user.id);
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Order Confirmation',
      html: `<p>Thank you for your order #${orderId}. Total: ₦${total.toLocaleString()}. Status: ${order.status}</p>`
    });
    res.status(201).json(order);
  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/orders/initialize', authMiddleware, async (req, res) => {
  try {
    const { email, amount, items, shippingAddress } = req.body;
    if (!email || !amount || !items?.length || !shippingAddress) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email,
        amount: amount * 100,
        callback_url: process.env.APP_URL ? `${process.env.APP_URL}/checkout.html` : 'https://calebtech.onrender.com/checkout.html'
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );
    const { authorization_url, reference } = response.data.data;
    res.json({ authorization_url, reference });
  } catch (error) {
    console.error('Initialize payment error:', error);
    res.status(500).json({ message: 'Error initializing payment' });
  }
});

app.post('/api/paystack/webhook', async (req, res) => {
  try {
    const { event, data } = req.body;
    if (event === 'charge.success') {
      const { reference, amount, customer, metadata } = data;
      const orderId = `ORD${Date.now()}`;
      const order = new Order({
        userId: customer.metadata?.userId || null,
        orderId,
        items: metadata?.items || [],
        total: amount / 100,
        shippingAddress: metadata?.shippingAddress || {},
        status: 'Processing',
        paymentReference: reference
      });
      await order.save();
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: customer.email,
        subject: 'Order Confirmation',
        html: `<p>Thank you for your order #${orderId}. Total: ₦${(amount / 100).toLocaleString()}. Status: Processing</p>`
      });
    }
    res.status(200).send('Webhook received');
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/orders', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 }).populate('userId', 'name email');
    res.json(orders);
  } catch (error) {
    console.error('Get admin orders error:', error);
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
    if (!order) return res.status(404).json({ message: 'Order not found' });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: order.userId.email,
      subject: 'Order Status Update',
      html: `<p>Your order #${order.orderId} is now ${status}.</p>`
    });
    res.json(order);
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Repairs
app.post('/api/repairs', upload.single('image'), authMiddleware, async (req, res) => {
  try {
    const { name, email, phone, deviceType, deviceModel, issue, contactMethod, preferredDate } = req.body;
    if (!name || !email || !phone || !deviceType || !deviceModel || !issue || !contactMethod || !preferredDate) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const repairId = `REP${Date.now()}`;
    const image = req.file ? `/${process.env.UPLOAD_DIR || 'public'}/Uploads/${req.file.filename}` : null;
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
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Repair Request Confirmation',
      html: `<p>Your repair request #${repairId} for ${deviceType} (${deviceModel}) has been received. Status: ${repair.status}</p>`
    });
    res.status(201).json(repair);
  } catch (error) {
    console.error('Create repair error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/repairs/user', authMiddleware, async (req, res) => {
  try {
    const repairs = await Repair.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(repairs);
  } catch (error) {
    console.error('Get user repairs error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/repairs', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const repairs = await Repair.find().sort({ createdAt: -1 }).populate('userId', 'name email');
    res.json(repairs);
  } catch (error) {
    console.error('Get admin repairs error:', error);
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
    if (!repair) return res.status(404).json({ message: 'Repair not found' });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: repair.userId.email,
      subject: 'Repair Status Update',
      html: `<p>Your repair request #${repair.repairId} is now ${status}.</p>`
    });
    res.json(repair);
  } catch (error) {
    console.error('Update repair error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/admin/repairs/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const repair = await Repair.findByIdAndDelete(req.params.id);
    if (!repair) return res.status(404).json({ message: 'Repair not found' });
    res.json({ message: 'Repair deleted' });
  } catch (error) {
    console.error('Delete repair error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Users (Admin)
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Delete user error:', error);
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
    console.error('Analytics error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Serve frontend routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, process.env.UPLOAD_DIR || 'public', 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`)); 
