const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
// NEW: Use dotenv for environment variables
require('dotenv').config();
// NEW: Import existing User model
const User = require('./models/User');

async function createAdminUser() {
  try {
    // MODIFIED: Use MONGODB_URI from .env
    await mongoose.connect(process.env.MONGODB_URI, {
      // REMOVED: Deprecated options (useNewUrlParser, useUnifiedTopology)
    });
    console.log('Connected to MongoDB');

    // NEW: Use configurable admin email and password from .env
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@calebtech.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123';
    const adminName = process.env.ADMIN_NAME || 'Admin User';
    const adminPhone = process.env.ADMIN_PHONE || '1234567890';
    const adminAddress = process.env.ADMIN_ADDRESS || 'Caleb Tech HQ';

    // Check if admin user exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      console.log(`Admin user already exists: ${adminEmail}`);
      return;
    }

    // Create default admin user
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    const adminUser = new User({
      name: adminName,
      email: adminEmail,
      phone: adminPhone,
      address: adminAddress,
      password: hashedPassword,
      role: 'admin',
      likedProducts: [], // NEW: Initialize likedProducts
    });

    await adminUser.save();
    console.log(`Admin user created: ${adminEmail} / Password: ${adminPassword}`);

  } catch (error) {
    // MODIFIED: Enhanced error logging
    console.error('Error creating admin user:', {
      message: error.message,
      stack: error.stack,
    });
    throw error; // NEW: Rethrow for external handling
  } finally {
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  }
}

// NEW: Execute with error handling
createAdminUser()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
