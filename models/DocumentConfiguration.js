const mongoose = require("mongoose");

const documentConfigSchema = new mongoose.Schema(
  {
    passwordProtect: { type: Boolean, default: false },
    password: { type: String, default: null }, // Hashed password
    plainPassword: { type: String, default: null }, // 🔓 Plain password
    downloadEnabled: { type: Boolean, default: false },
    leadCapture: { type: Boolean, default: false },
     aiAgentEnabled : {type : Boolean, default: false},
    requiredEmailToView: { type: Boolean, default: true }, 
    expiryDate: { type: Date, default: null },

    documentId: { type: String, required: true },
    uuid: { type: String, required: true },
    email: { type: String, required: true },
    plantype: {
      type: String,
      enum: ["basic", "pro", "enterprise"],
      required: true,
    },

    // New pro plan features
    customDomainEnabled: { type: Boolean, default: false },
    deactivateLink: { type: Boolean, default: false },
    customLogoEnabled: { type: Boolean, default: false },
    logoRedirectUrl: { type: String, default: null }, // ✅ NEW: Logo redirect URL
    customLogoUrl: { type: String, default: null }, // S3 public URL
    emailApprovalEnabled: { type: Boolean, default: false },
    approvedEmails: { type: [String], default: [] },
  },
  { timestamps: true }
);

module.exports = mongoose.model("DocumentConfiguration", documentConfigSchema);

