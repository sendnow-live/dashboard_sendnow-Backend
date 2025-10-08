const mongoose = require('mongoose');

const fcmTokenSchema = new mongoose.Schema({
  uuid: {
    type: String,
    required: true,
    index: true
  },
  fcmToken: {
    type: String,
    required: true,
    unique: true
  },
  deviceInfo: {
    userAgent: String,
    platform: String,
    deviceType: String, // 'web', 'android', 'ios'
    browserName: String,
    browserVersion: String,
    osName: String,
    osVersion: String,
    deviceModel: String,
    ipAddress: String
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastUsed: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for efficient queries
fcmTokenSchema.index({ uuid: 1, fcmToken: 1 });
fcmTokenSchema.index({ uuid: 1, isActive: 1 });

// Pre-save middleware to update timestamps
fcmTokenSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Method to deactivate token
fcmTokenSchema.methods.deactivate = function() {
  this.isActive = false;
  this.updatedAt = Date.now();
  return this.save();
};

// Static method to find active tokens for a user
fcmTokenSchema.statics.findActiveTokensByUuid = function(uuid) {
  return this.find({ uuid, isActive: true });
};

// Static method to update or create FCM token
fcmTokenSchema.statics.upsertFCMToken = async function(uuid, fcmToken, deviceInfo = {}) {
  try {
    // Check if token already exists
    const existingToken = await this.findOne({ fcmToken });
    
    if (existingToken) {
      // Update existing token
      existingToken.uuid = uuid;
      existingToken.deviceInfo = { ...existingToken.deviceInfo, ...deviceInfo };
      existingToken.isActive = true;
      existingToken.lastUsed = Date.now();
      return await existingToken.save();
    } else {
      // Create new token
      return await this.create({
        uuid,
        fcmToken,
        deviceInfo,
        isActive: true,
        lastUsed: Date.now()
      });
    }
  } catch (error) {
    throw new Error(`FCM Token upsert failed: ${error.message}`);
  }
};

module.exports = mongoose.model('FCMToken', fcmTokenSchema);