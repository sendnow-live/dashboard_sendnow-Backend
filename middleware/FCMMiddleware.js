const admin = require('firebase-admin');
const Users = require('../models/User');
const FCMToken = require('../models/FCMtoken'); // Import the FCM Token model
const serviceAccount = require('../config/firebase-service-account.json');

// Initialize Firebase Admin with service account only once
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

// Helper function to extract device info from request
const extractDeviceInfo = (req) => {
  const userAgent = req.headers['user-agent'] || '';
  const ipAddress = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 
                   (req.connection.socket ? req.connection.socket.remoteAddress : null);
  
  return {
    userAgent,
    ipAddress,
    platform: req.headers['x-platform'] || 'web',
    deviceType: req.headers['x-device-type'] || 'web',
    browserName: req.headers['x-browser-name'] || '',
    browserVersion: req.headers['x-browser-version'] || '',
    osName: req.headers['x-os-name'] || '',
    osVersion: req.headers['x-os-version'] || '',
    deviceModel: req.headers['x-device-model'] || ''
  };
};

const fcmVerificationMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(400).json({ error: 'Authorization header missing or malformed' });
    }

    const token = authHeader.split(' ')[1];

    // ✅ Verify token using Firebase Admin SDK
    const decodedToken = await admin.auth().verifyIdToken(token);

    const uid = decodedToken.user_id;
    const email = decodedToken.email;

    console.log('✅ Firebase Verified Token:', { uid, email });

    // 🔍 Check user in DB by uid and email
    const user = await Users.findOne({ uid, email });

    if (!user) {
      console.warn('❌ User not found for given uid and email');
      return res.status(401).json({ error: 'Unauthorized: user not found' });
    }

    // 🔥 FCM Token verification and storage
    const { fcmToken } = req.body;
    
    if (fcmToken) {
      try {
        // Extract device information from request
        const deviceInfo = extractDeviceInfo(req);
        
        // Verify FCM token is valid (optional - validates token format)
        if (fcmToken.length < 100) {
          console.warn('⚠️ FCM Token seems invalid (too short)');
          return res.status(400).json({ error: 'Invalid FCM token format' });
        }

        // Check if FCM token is already associated with this user
        const existingTokenRecord = await FCMToken.findOne({ 
          uuid: uid, 
          fcmToken: fcmToken,
          isActive: true 
        });

        if (existingTokenRecord) {
          // Update last used timestamp
          existingTokenRecord.lastUsed = Date.now();
          existingTokenRecord.deviceInfo = { ...existingTokenRecord.deviceInfo, ...deviceInfo };
          await existingTokenRecord.save();
          console.log('✅ FCM Token updated for existing user');
        } else {
          // Store or update FCM token in database
          await FCMToken.upsertFCMToken(uid, fcmToken, deviceInfo);
          console.log('✅ FCM Token stored/updated successfully');
        }

        // Optionally validate FCM token with Firebase (uncomment if needed)
        
        try {
          await admin.messaging().send({
            token: fcmToken,
            data: { test: 'validation' }
          }, true); // dry run
          console.log('✅ FCM Token is valid');
        } catch (fcmError) {
          console.warn('⚠️ FCM Token validation failed:', fcmError.message);
          // Deactivate invalid token
          await FCMToken.findOneAndUpdate(
            { fcmToken }, 
            { isActive: false }
          );
        }
        

      } catch (fcmError) {
        console.error('❌ FCM Token processing error:', fcmError.message);
        // Don't block the request, just log the error
      }
    }

    // ✅ Attach verified data to request
    req.user = { uid, email };
    req.body.uuid = uid;
    
    console.log('✅ Middleware completed successfully');
    next();

  } catch (error) {
    console.error('❌ Middleware error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

module.exports = fcmVerificationMiddleware;