const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  orderId: { type: String, required: true },
  items: [{
    id: Number,
    name: String,
    price: Number,
    quantity: Number
  }],
  total: { type: Number, required: true },
  shippingAddress: { type: Object, required: true },
  status: { type: String, default: 'Processing' },
  paymentReference: { type: String }
}, { timestamps: true });

module.exports = mongoose.model('Order', orderSchema);
