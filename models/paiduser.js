const mongoose = require('mongoose');

const formEntrySchema = new mongoose.Schema({
  email: { type: String, required: true },
  uuid: { type: String, required: true },
  planType: { type: String, enum: ['basic', 'pro', 'enterprise'], required: true },
  paymentDate: { type: Date, required: true },
  expiredDate: { type: Date, required: true },
  planStatus: { type: String, enum: ['active', 'expired'], required: true },
  productType: { type: String, enum: ['creation', 'renewal'], required: true },
  nextDueDate: { type: Date, required: true },
}, {
  timestamps: true
});

module.exports = mongoose.model('paidusers', formEntrySchema);
