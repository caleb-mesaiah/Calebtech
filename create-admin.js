 const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const User = require('./models/User');

mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log('MongoDB connected');
    const email = process.env.ADMIN_EMAIL.toLowerCase();
    const password = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
    await User.deleteOne({ email });
    const user = new User({
      name: process.env.ADMIN_NAME || 'Admin User',
      email,
      password,
      phone: process.env.ADMIN_PHONE || '1234567890',
      address: process.env.ADMIN_ADDRESS || 'Caleb Tech HQ',
      role: 'admin'
    });
    await user.save();
    console.log('Admin user created');
    process.exit(0);
  })
  .catch(err => {
    console.error('Error:', err);
    process.exit(1);
  });
