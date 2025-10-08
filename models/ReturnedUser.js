const mongoose = require("mongoose");

const CountSchema = new mongoose.Schema({
  weblink: { type: Number, default: 0 },
  pdf: { type: Number, default: 0 },
  video: { type: Number, default: 0 },
  docx: { type: Number, default: 0 },
  powerpoint: { type: Number, default: 0 },
});

const ReturnedUserSchema = new mongoose.Schema({
  documentId: { type: String, required: true }, // ADD THIS FIELD
  userId: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  count: { type: CountSchema, default: {} },
  lastRequestTime: { type: Date }, // ADD THIS FIELD
  __v: { type: Number, select: false },
});

// Create compound index for better performance
ReturnedUserSchema.index({ documentId: 1, userId: 1 });

module.exports = mongoose.model("ReturnedUser", ReturnedUserSchema);
