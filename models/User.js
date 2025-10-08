const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  uid: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  displayName: String,
  photoURL: String,
  emailVerified: Boolean,
  metadata: {
    creationTime: String,
    lastSignInTime: String,
  },
  providerData: [
    {
      providerId: String,
      uid: String,
      displayName: String,
      email: String,
      phoneNumber: String,
      photoURL: String,
    }
  ]
});

module.exports = mongoose.model("User", UserSchema);
