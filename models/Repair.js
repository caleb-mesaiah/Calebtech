const mongoose = require('mongoose');

const repairSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  repairId: { type: String, required: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  deviceType: { type: String, required: true },
  deviceModel: { type: String, required: true },
  issue: { type: String, required: true },
  contactMethod: { type: String, required: true },
  preferredDate: { type: String, required: true },
  image: String,
  status: { type: String, default: 'Pending' }
}, { timestamps: true });

module.exports = mongoose.model('Repair', repairSchema);
