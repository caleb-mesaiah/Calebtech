const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Models
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  address: String,
  password: String,
  role: { type: String, default: 'user' },
  resetToken: String,
  resetTokenExpiry: Date,
});
const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
  stock: Number,
  image: String,
  description: String,
  createdAt: { type: Date, default: Date.now },
});
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  email: String,
  name: String,
  phone: String,
  shippingAddress: String,
  billingAddress: String,
  deliveryOption: String,
  paymentMethod: String,
  items: [{ name: String, price: Number, quantity: Number, image: String }],
  subtotal: Number,
  deliveryFee: Number,
  total: Number,
  status: { type: String, default: 'Pending' },
  orderId: String,
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);

// Middleware to verify JWT
const authMiddleware = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token provided.' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    req.user = await User.findById(decoded.userId);
    if (!req.user) throw new Error();
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token.' });
  }
};

// Middleware to verify admin role
const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin privileges required.' });
  }
  next();
};

// Initialize default admin user
app.post('/api/auth/init-admin', async (req, res) => {
  try {
    const existingAdmin = await User.findOne({ email: 'admin@calebtech.com' });
    if (existingAdmin) {
      return res.status(400).json({ message: 'Admin user already exists.' });
    }
    const hashedPassword = await bcrypt.hash('Admin123', 10);
    const adminUser = new User({
      name: 'Admin User',
      email: 'admin@calebtech.com',
      phone: '1234567890',
      address: 'Caleb Tech HQ',
      password: hashedPassword,
      role: 'admin',
    });
    await adminUser.save();
    res.json({ message: 'Admin user created: admin@calebtech.com / Admin123' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating admin user.' });
  }
});

// Auth Endpoints
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, phone, password: hashedPassword });
    await user.save();
    res.json({ message: 'Registration successful.' });
  } catch (error) {
    res.status(400).json({ message: 'Error registering user.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1d' });
    res.json({ token });
  } catch (error) {
    res.status(400).json({ message: 'Error logging in.' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Email not found.' });
    }
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000;
    await user.save();
    console.log(`Reset link: /reset-password.html?token=${resetToken}`);
    res.json({ message: 'Password reset link sent.' });
  } catch (error) {
    res.status(400).json({ message: 'Error processing request.' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token.' });
    }
    user.password = await bcrypt.hash(password, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();
    res.json({ message: 'Password reset successfully.' });
  } catch (error) {
    res.status(400).json({ message: 'Error resetting password.' });
  }
});

// Profile Endpoints
app.get('/api/auth/profile', authMiddleware, (req, res) => {
  res.json({
    name: req.user.name,
    email: req.user.email,
    phone: req.user.phone,
    address: req.user.address,
    role: req.user.role,
  });
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { name, phone, address } = req.body;
    req.user.name = name;
    req.user.phone = phone;
    req.user.address = address;
    await req.user.save();
    res.json({ message: 'Profile updated.' });
  } catch (error) {
    res.status(400).json({ message: 'Error updating profile.' });
  }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const isMatch = await bcrypt.compare(currentPassword, req.user.password);
    if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect.' });
    req.user.password = await bcrypt.hash(newPassword, 10);
    await req.user.save();
    res.json({ message: 'Password changed.' });
  } catch (error) {
    res.status(400).json({ message: 'Error changing password.' });
  }
});

// User Order Endpoints
app.get('/api/orders', authMiddleware, async (req, res) => {
  const orders = await Order.find({ userId: req.user._id }).sort({ createdAt: -1 });
  res.json(orders);
});

app.post('/api/orders', async (req, res) => {
  try {
    const orderData = req.body;
    const token = req.header('Authorization')?.replace('Bearer ', '');
    let userId = null;
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
      userId = decoded.userId;
    }
    const orderId = `ORD${Date.now()}`;
    const order = new Order({ ...orderData, userId, orderId });
    for (const item of orderData.items) {
      const product = await Product.findOne({ name: item.name });
      if (product && product.stock < item.quantity) {
        return res.status(400).json({ message: `Insufficient stock for ${item.name}.` });
      }
      if (product) {
        product.stock -= item.quantity;
        await product.save();
      }
    }
    await order.save();
    res.json({ orderId });
  } catch (error) {
    res.status(400).json({ message: 'Error creating order.' });
  }
});

// Admin Endpoints
app.get('/api/admin/orders', [authMiddleware, adminMiddleware], async (req, res) => {
  const orders = await Order.find().sort({ createdAt: -1 });
  res.json(orders);
});

app.put('/api/admin/orders/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ message: 'Order not found.' });
    order.status = status;
    await order.save();
    res.json({ message: 'Order status updated.' });
  } catch (error) {
    res.status(400).json({ message: 'Error updating order.' });
  }
});

app.delete('/api/admin/orders/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(req.params.id);
    if (!order) return res.status(404).json({ message: 'Order not found.' });
    res.json({ message: 'Order deleted.' });
  } catch (error) {
    res.status(400).json({ message: 'Error deleting order.' });
  }
});

app.get('/api/admin/products', [authMiddleware, adminMiddleware], async (req, res) => {
  const products = await Product.find().sort({ createdAt: -1 });
  res.json(products);
});

app.post('/api/admin/products', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.json({ message: 'Product added.' });
  } catch (error) {
    res.status(400).json({ message: 'Error adding product.' });
  }
});

app.put('/api/admin/products/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found.' });
    Object.assign(product, req.body);
    await product.save();
    res.json({ message: 'Product updated.' });
  } catch (error) {
    res.status(400).json({ message: 'Error updating product.' });
  }
});

app.delete('/api/admin/products/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found.' });
    res.json({ message: 'Product deleted.' });
  } catch (error) {
    res.status(400).json({ message: 'Error deleting product.' });
  }
});

app.get('/api/admin/users', [authMiddleware, adminMiddleware], async (req, res) => {
  const users = await User.find().select('-password').sort({ createdAt: -1 });
  res.json(users);
});

app.put('/api/admin/users/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    const { name, email, phone, role } = req.body;
    user.name = name;
    user.email = email;
    user.phone = phone;
    user.role = role;
    await user.save();
    res.json({ message: 'User updated.' });
  } catch (error) {
    res.status(400).json({ message: 'Error updating user.' });
  }
});

app.delete('/api/admin/users/:id', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'User deleted.' });
  } catch (error) {
    res.status(400).json({ message: 'Error deleting user.' });
  }
});

app.get('/api/admin/analytics', [authMiddleware, adminMiddleware], async (req, res) => {
  try {
    const orders = await Order.find();
    const totalSales = orders.reduce((sum, order) => sum + order.total, 0);
    const totalOrders = orders.length;
    const pendingOrders = orders.filter(order => order.status === 'Pending').length;
    const productSales = {};
    orders.forEach(order => {
      order.items.forEach(item => {
        if (!productSales[item.name]) {
          productSales[item.name] = { totalSold: 0, totalRevenue: 0 };
        }
        productSales[item.name].totalSold += item.quantity;
        productSales[item.name].totalRevenue += item.price * item.quantity;
      });
    });
    const topProducts = Object.entries(productSales)
      .map(([name, data]) => ({ name, ...data }))
      .sort((a, b) => b.totalSold - a.totalSold)
      .slice(0, 5);
    res.json({ totalSales, totalOrders, pendingOrders, topProducts });
  } catch (error) {
    res.status(400).json({ message: 'Error fetching analytics.' });
  }
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`Server running on port ${port}`));
  })
  .catch(err => console.error('MongoDB connection error:', err));