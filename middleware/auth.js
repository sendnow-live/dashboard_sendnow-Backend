const admin = require('firebase-admin');
const Users = require('../models/User');
const serviceAccount = require('../config/firebase-service-account.json');

// Initialize Firebase Admin with service account only once
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const authenticationMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(400).json({ error: 'Authorization header missing or malformed' });
    }

    const token = authHeader.split(' ')[1];

    try {
      // ✅ Verify token using Firebase Admin SDK
      const decodedToken = await admin.auth().verifyIdToken(token);
      const uid = decodedToken.user_id || decodedToken.uid;
      const email = decodedToken.email;

      console.log('✅ Firebase Verified Token:', { uid, email });

      // 🔍 Check user in DB by uid and email
      const user = await Users.findOne({ uid, email });

      if (!user) {
        console.warn('❌ User not found for given uid and email');
        return res.status(401).json({ error: 'Unauthorized: user not found in DB' });
      }

      // ✅ Attach verified data to request
      req.user = { uid, email };
      req.body.uuid = uid; // 🔥 Add this line as you requested
      console.log(req.body, "bdoyyyyy");

      next();

    } catch (tokenError) {
      console.error('❌ Token verification failed:', tokenError.message);
      
      // Simple session expired message for any token error
      return res.status(401).json({ 
        error: 'Your session has expired. Please refresh the application and try again.',
        expired: true
      });
    }

  } catch (error) {
    console.error('❌ Middleware error:', error.message);
    return res.status(401).json({ 
      error: 'Your session has expired. Please refresh the application and try again.',
      expired: true
    });
  }
};

module.exports = authenticationMiddleware;
