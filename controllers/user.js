
const User = require("../models/User");
require("dotenv").config();
const jwt = require('jsonwebtoken');
const Pdfanalytics = require("../models/Pdfanalytics");
const Docxanalytics = require('../models/Docxanalytics')
const newUser = require("../models/newUser");
const ReturnedUser = require("../models/ReturnedUser");
const ShortenedUrl = require("../models/test"); // Updated model name
const UserVisit = require("../models/UserVisit"); // UserVisit model
const VideoAnalytics = require('../models/Videoanalytics')
const path = require('path');
const axios = require('axios');
const { v4: uuidv4 } = require("uuid");  // Import the UUID generator
const moment = require("moment");
const DocxAnalytics = require("../models/Docxanalytics");
const PowerPointAnalytics = require("../models/PowerPointAnalytics");
const Webanalytics = require('../models/Webanalytics');
// const { bucket } = require("../config/firebaseconfig"); 
const AWS = require("aws-sdk");
const UserBase = require("../models/User");
const PaidUser = require("../models/paiduser");
const DocumentConfiguration = require("../models/DocumentConfiguration");
const bcrypt = require("bcryptjs");
const { TOP_SITES_BLACKLIST } = require("../controllers/constants/blacklist");
const { body, validationResult } = require('express-validator');
const LeadCaptureForm = require('../models/LeadCaptureForm');
const DocumentDownloads = require("../models/DocumentDownloads");




const createOrUpdateUser = async (req, res) => {
  try {
    const {
      uid,
      email,
      displayName,
      photoURL,
      emailVerified,
      metadata,
      providerData,
    } = req.body;

    if (!uid || !email) {
      return res.status(400).json({ error: "Missing uid or email" });
    }

    const existingUser = await User.findOne({ uid });

    if (existingUser) {
      existingUser.email = email;
      existingUser.displayName = displayName;
      existingUser.photoURL = photoURL;
      existingUser.emailVerified = emailVerified;
      existingUser.metadata = metadata;
      existingUser.providerData = providerData;

      const updatedUser = await existingUser.save();
      return res.status(200).json({ message: "User updated", user: updatedUser });
    }

    const newUser = new User({
      uid,
      email,
      displayName,
      photoURL,
      emailVerified,
      metadata,
      providerData,
    });

    const savedUser = await newUser.save();
    return res.status(201).json({ message: "User created", user: savedUser });

  } catch (err) {
    console.error("❌ Error storing user:", err);
    return res.status(500).json({ error: "Failed to store user", details: err.message });
  }
};

// Controller 1: Check Custom ID Availability (Global Check)
const checkCustomIdAvailability = async (req, res) => {
  try {
    const { customId, currentId } = req.body;

    // Validate input
    if (!customId) {
      return res.status(400).json({
        allow: false,
        documentId: "",
        newId: "",
        oldId: currentId || "",
        message: "Custom ID is required"
      });
    }

    // Validate custom ID format (alphanumeric, max 12 characters)
    const customIdRegex = /^[a-zA-Z0-9]{1,12}$/;
    if (!customIdRegex.test(customId)) {
      return res.status(400).json({
        allow: false,
        documentId: "",
        newId: customId,
        oldId: currentId || "",
        message: "Custom ID must be alphanumeric only and max 12 characters"
      });
    }

    // Check if custom ID already exists globally across all users
    const existingUrl = await ShortenedUrl.findOne({ shortId: customId });

    if (existingUrl) {
      // ID is taken by any user (could be same user or different user)
      return res.status(409).json({
        allow: false,
        documentId: "",
        newId: customId,
        oldId: currentId || "",
        message: "ID already exists, taken by another user"
      });
    }

    // Custom ID is available globally
    return res.status(200).json({
      allow: true,
      documentId: "",
      newId: customId,
      oldId: currentId || "",
      message: "Custom ID is available"
    });

  } catch (error) {
    console.error('Error checking custom ID availability:', error);
    return res.status(500).json({
      allow: false,
      documentId: "",
      newId: "",
      oldId: currentId || "",
      message: "Internal server error while checking availability"
    });
  }
};
// Controller 2: Save Custom ID using Document ID
const saveCustomId = async (req, res) => {
  try {
    const { documentId, customId } = req.body;
    
    const userUuid = req.body.uuid; // From middleware
    console.log("📥 Incoming request to save custom ID:", { documentId, customId, userUuid });

    // Validate input
    if (!documentId || !customId) {
      return res.status(400).json({
        allow: false,
        documentId: documentId || "",
        newId: customId || "",
        oldId: "",
        message: "Document ID and Custom ID are required"
      });
    }

    // Validate custom ID format
    const customIdRegex = /^[a-zA-Z0-9]{1,12}$/;
    if (!customIdRegex.test(customId)) {
      return res.status(400).json({
        allow: false,
        documentId: documentId,
        newId: customId,
        oldId: "",
        message: "Custom ID must be alphanumeric only and max 12 characters"
      });
    }

    // Find the document by shortId (not _id) and verify ownership
    const document = await ShortenedUrl.findOne({ 
      shortId: documentId,
      userUuid: userUuid 
    });
    
    if (!document) {
      return res.status(404).json({
        allow: false,
        documentId: documentId,
        newId: customId,
        oldId: "",
        message: "Document not found or unauthorized access"
      });
    }

    const oldId = document.shortId;

    // If the new ID is the same as current, no changes needed
    if (oldId === customId) {
      return res.status(200).json({
        allow: true,
        documentId: documentId,
        newId: customId,
        oldId: oldId,
        message: "No changes made, ID is already set"
      });
    }

    // Check if the new custom ID is already taken by anyone
    const existingUrl = await ShortenedUrl.findOne({ 
      shortId: customId
    });

    if (existingUrl) {
      return res.status(409).json({
        allow: false,
        documentId: documentId,
        newId: customId,
        oldId: oldId,
        message: "ID already exists, taken by another user"
      });
    }

    // Update the document with new custom ID using the MongoDB _id
    await ShortenedUrl.findByIdAndUpdate(
      document._id,
      { shortId: customId },
      { new: true }
    );

    return res.status(200).json({
      allow: true,
      documentId: customId, // Return the new ID as documentId
      newId: customId,
      oldId: oldId,
      message: "Custom ID saved successfully"
    });

  } catch (error) {
    console.error('Error saving custom ID:', error);
    
    // Handle MongoDB duplicate key error
    if (error.code === 11000) {
      return res.status(409).json({
        allow: false,
        documentId: req.body.documentId || "",
        newId: req.body.customId || "",
        oldId: "",
        message: "ID already exists, taken by another user"
      });
    }

    return res.status(500).json({
      allow: false,
      documentId: req.body.documentId || "",
      newId: req.body.customId || "",
      oldId: "",
      message: "Internal server error while saving custom ID"
    });
  }
};


const saveDocumentSettings = async (req, res) => {
  try {
    console.log("📥 Incoming request to save document settings:", req.body);

    const {
      documentId,
      uuid,
      passwordProtect,
      password,
      downloadEnabled,
      leadCapture,
      aiAgentEnabled,
      expiryDate,
      customDomainEnabled,
      customDomain,
      deactivateLink,
      customLogoEnabled,
      customLogoUrl: frontendLogoUrl,
      logoRedirectUrl, // ✅ Extract logo redirect URL
      emailApprovalEnabled,
      approvedEmails,
      requiredEmailToView
    } = req.body;

    console.log("🔍 Extracted logoRedirectUrl:", logoRedirectUrl); // ✅ DEBUG LOG

    const bool = (val) => val !== undefined && val !== null && String(val).toLowerCase() === "true";
    const parsedApprovedEmails = approvedEmails ? JSON.parse(approvedEmails) : [];

    if (!documentId || !uuid) {
      return res.status(400).json({ message: "documentId and uuid are required" });
    }

    // --- 1. Validate paid user plan FIRST ---
    const paidUser = await PaidUser.findOne({ uuid });
    if (!paidUser) {
      return res.status(403).json({ message: "Only paid users can configure documents." });
    }

    const now = new Date();
    const isExpired = paidUser.expiredDate && new Date(paidUser.expiredDate) < now;
    if (paidUser.planStatus !== "active" || isExpired) {
      return res.status(403).json({ message: "Your plan is not active or has expired." });
    }

    const plan = paidUser.planType.toLowerCase();

    // --- 2. Fetch existing shortened URL record ---
    const existingUrl = await ShortenedUrl.findOne({ userUuid: uuid, shortId: documentId });
    if (!existingUrl) {
      return res.status(404).json({ message: "Shortened URL not found." });
    }

    const dbExpiryDate = existingUrl.expirationDate ? new Date(existingUrl.expirationDate) : null;
    console.log("📦 Existing URL record:", { existingExpiry: dbExpiryDate });

    // --- 3. Parse and validate expiryDate from request ---
    let parsedExpiryDate = null;
    if (expiryDate) {
      parsedExpiryDate = new Date(expiryDate);
      if (isNaN(parsedExpiryDate.getTime())) {
        return res.status(400).json({ message: "Invalid expiryDate format." });
      }

      console.log("🕒 Parsed Request Expiry:", parsedExpiryDate.toISOString());
      
      // Updated logic: Only allow if new expiry is EARLIER than existing expiry
      if (dbExpiryDate) {
        console.log("🕒 DB Expiry:", dbExpiryDate.toISOString());
        console.log("🕒 Request Expiry:", parsedExpiryDate.toISOString());

        // Allow only if the new expiry date is EARLIER than the existing one
        if (parsedExpiryDate > dbExpiryDate) {
          return res.status(400).json({
            message: "❌ Expiry date must be earlier than the current one.",
          });
        }
        
        console.log("✅ New expiry date is earlier than existing expiry. Update allowed.");
      }
    }

    // --- 4. Get existing document configuration to preserve existing data ---
    const existingConfig = await DocumentConfiguration.findOne({ documentId, uuid });
    console.log("📦 Existing configuration:", existingConfig);

    // Initialize with existing config data or defaults
    let configData = {
      documentId,
      uuid,
      email: paidUser.email, // ✅ Set user info early
      plantype: paidUser.planType,
      passwordProtect: existingConfig?.passwordProtect || false,
      password: existingConfig?.password || null,
      plainPassword: existingConfig?.plainPassword || null,
      downloadEnabled: existingConfig?.downloadEnabled || false,
      leadCapture: existingConfig?.leadCapture || false,
      aiAgentEnabled: existingConfig?.aiAgentEnabled || false,
      requiredEmailToView: existingConfig?.requiredEmailToView !== undefined ? existingConfig.requiredEmailToView : true,
      expiryDate: existingConfig?.expiryDate || null,
      customDomainEnabled: existingConfig?.customDomainEnabled || false,
      customDomain: existingConfig?.customDomain || null,
      deactivateLink: existingConfig?.deactivateLink || false,
      customLogoEnabled: existingConfig?.customLogoEnabled || false,
      customLogoUrl: existingConfig?.customLogoUrl || null,
      logoRedirectUrl: existingConfig?.logoRedirectUrl || null, // ✅ Initialize logo redirect URL
      emailApprovalEnabled: existingConfig?.emailApprovalEnabled || false,
      approvedEmails: existingConfig?.approvedEmails || [],
    };

    // --- 5. Handle custom logo upload ---
    if (req.files?.customLogo?.[0]) {
      const logoFile = req.files.customLogo[0];
      const s3Params = {
        Bucket: process.env.AWS_S3_BUCKET,
        Key: `logos/${Date.now()}_${logoFile.originalname}`,
        Body: logoFile.buffer,
        ContentType: logoFile.mimetype,
        ACL: "public-read",
      };
      const uploadResult = await s3.upload(s3Params).promise();
      configData.customLogoUrl = uploadResult.Location;
      console.log("📸 New logo uploaded:", configData.customLogoUrl);
    } else if (frontendLogoUrl && frontendLogoUrl !== 'undefined' && frontendLogoUrl !== '') {
      // Preserve existing logo URL if provided from frontend
      configData.customLogoUrl = frontendLogoUrl;
      console.log("📸 Preserving existing logo URL:", configData.customLogoUrl);
    }

    // --- 6. Update only the fields that are provided in the request ---
    
    // Handle password protection
    if (passwordProtect !== undefined) {
      configData.passwordProtect = bool(passwordProtect);
      if (bool(passwordProtect) && password) {
        configData.password = await bcrypt.hash(password, 10);
        configData.plainPassword = password;
      } else if (!bool(passwordProtect)) {
        configData.password = null;
        configData.plainPassword = null;
      }
    }

    // Handle other boolean fields - only update if explicitly provided
    if (downloadEnabled !== undefined) {
      configData.downloadEnabled = bool(downloadEnabled);
    }

    if (aiAgentEnabled !== undefined) {
      configData.aiAgentEnabled = bool(aiAgentEnabled);
    }

    if (requiredEmailToView !== undefined) {
      configData.requiredEmailToView = bool(requiredEmailToView);
      console.log("🔍 Processing requiredEmailToView:", bool(requiredEmailToView));
    }

    if (customDomainEnabled !== undefined) {
      if (plan === "basic" && bool(customDomainEnabled)) {
        return res.status(403).json({
          message: "Basic plan users cannot enable custom domain.",
        });
      }
      configData.customDomainEnabled = bool(customDomainEnabled);
      if (bool(customDomainEnabled) && customDomain) {
        configData.customDomain = customDomain;
      } else if (!bool(customDomainEnabled)) {
        configData.customDomain = null;
      }
    }

    if (deactivateLink !== undefined) {
      configData.deactivateLink = bool(deactivateLink);
    }

    if (customLogoEnabled !== undefined) {
      if (plan === "basic" && bool(customLogoEnabled)) {
        return res.status(403).json({
          message: "Basic plan users cannot enable custom logo.",
        });
      }
      configData.customLogoEnabled = bool(customLogoEnabled);
      if (!bool(customLogoEnabled)) {
        configData.customLogoUrl = null;
        configData.logoRedirectUrl = null; // ✅ Clear redirect URL when logo is disabled
      }
    }

    // ✅ FIXED: Handle logo redirect URL - Always process this field
    console.log("🔍 Processing logoRedirectUrl:", logoRedirectUrl);
    if (logoRedirectUrl !== undefined) {
      configData.logoRedirectUrl = logoRedirectUrl && logoRedirectUrl.trim() !== "" ? logoRedirectUrl.trim() : null;
      console.log("✅ Set logoRedirectUrl in configData:", configData.logoRedirectUrl);
    }

    // Handle expiry date
    if (parsedExpiryDate) {
      configData.expiryDate = parsedExpiryDate;
    }

    // --- 7. Handle lead capture ---
    if (leadCapture !== undefined) {
      if (plan === "basic" && bool(leadCapture)) {
        return res.status(403).json({
          message: "Basic plan users cannot enable lead capture.",
        });
      }
      
      configData.leadCapture = bool(leadCapture);
    }

    // --- 8. Handle email approval ---
    if (emailApprovalEnabled !== undefined) {
      if (plan === "basic" && bool(emailApprovalEnabled)) {
        return res.status(403).json({
          message: "Basic plan users cannot enable email approvals.",
        });
      }
      
      configData.emailApprovalEnabled = bool(emailApprovalEnabled);
      
      if (bool(emailApprovalEnabled)) {
        configData.approvedEmails = parsedApprovedEmails;
      } else {
        configData.approvedEmails = [];
      }
    }

    console.log("🔄 Final config data to be saved:", configData);
    console.log("🔍 Final logoRedirectUrl value:", configData.logoRedirectUrl); // ✅ DEBUG LOG

    // --- 9. Update or create document configuration ---
    const config = await DocumentConfiguration.findOneAndUpdate(
      { documentId, uuid },
      { $set: configData }, // ✅ FIXED: Use $set operator explicitly
      { upsert: true, new: true, runValidators: true } // ✅ Added runValidators
    );

    console.log("💾 Saved config result:", config); // ✅ DEBUG LOG
    console.log("💾 Saved logoRedirectUrl:", config.logoRedirectUrl); // ✅ DEBUG LOG

    // --- 10. Update ShortenedUrl with active/deactivate status and expiry date ---
    const urlUpdate = {};
    
    if (deactivateLink !== undefined) {
      urlUpdate.active = bool(deactivateLink) ? "D" : "Y";
    }

    // Always update expiry date in ShortenedUrl if new expiry date is provided and validation passed
    if (parsedExpiryDate) {
      urlUpdate.expirationDate = parsedExpiryDate;
      console.log("🛠 Updating expirationDate in ShortenedUrl from:", dbExpiryDate?.toISOString(), "to:", parsedExpiryDate.toISOString());
    }

    // Only update if there are changes to make
    if (Object.keys(urlUpdate).length > 0) {
      const updateResult = await ShortenedUrl.updateMany(
        { userUuid: uuid, shortId: documentId },
        urlUpdate
      );
      console.log(`✅ Updated ${updateResult.modifiedCount} shortened URL(s) with new settings.`);
    }

    console.log("✅ Document settings saved successfully with preserved data.");

    return res.status(201).json({
      message: "Document settings saved successfully.",
      config,
    });
  } catch (error) {
    console.error("❌ Error in saveDocumentSettings:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const getDocumentConfiguration = async (req, res) => {
  try {
    const { documentId } = req.params;
    const { uuid } = req.body;

    // Validate input
    if (!documentId || !uuid) {
      return res.status(400).json({ message: "documentId and uuid are required" });
    }

    // Validate paid user
    const paidUser = await PaidUser.findOne({ uuid });
    if (!paidUser) {
      return res.status(403).json({ message: "Access denied: Not a paid user." });
    }

    const now = new Date();
    const isExpired = new Date(paidUser.expiredDate) < now; // Fix: Ensure proper date comparison

    console.log("🔍 Debug Info:");
    console.log("Plan Type:", paidUser.planType);
    console.log("Plan Status:", paidUser.planStatus);
    console.log("Expired Date:", paidUser.expiredDate);
    console.log("Current Date:", now);
    console.log("Is Expired:", isExpired);

    // Fixed validation logic
    if (
      !["basic", "pro"].includes(paidUser.planType) ||  // Allow both basic and pro
      isExpired  // Only check if expired, ignore planStatus for now
    ) {
      return res.status(403).json({
        message: `Access denied: Plan type is '${paidUser.planType}' and expiry status is ${isExpired ? 'expired' : 'active'}.`,
      });
    }

    // Alternative: If you want to check planStatus too, use this instead:
    
    if (
      !["basic", "pro"].includes(paidUser.planType) ||
      !["active", "expired"].includes(paidUser.planStatus) ||  // Allow both active and expired status
      isExpired
    ) {
      return res.status(403).json({
        message: `Access denied: Plan type is '${paidUser.planType}', status is '${paidUser.planStatus}', and expiry status is ${isExpired ? 'expired' : 'active'}.`,
      });
    }
    

    // Fetch configuration
    const config = await DocumentConfiguration.findOne({ documentId, uuid });
    if (!config) {
      return res.status(404).json({ message: "No configuration found for this document." });
    }

    // Construct response from schema
    const responsePayload = {
      passwordProtect: config.passwordProtect === true,
      password: config.plainPassword || "",
      downloadEnabled: config.downloadEnabled === true,
      leadCapture: config.leadCapture === true,
      expiryDate: config.expiryDate || null,
      requiredEmailToView: config.requiredEmailToView !== undefined ? config.requiredEmailToView : true,
      documentId: config.documentId,
      uuid: config.uuid,
      email: config.email,
      plantype: config.plantype || "basic",

      customDomainEnabled: config.customDomainEnabled === true,
      deactivateLink: config.deactivateLink === true,
      customLogoEnabled: config.customLogoEnabled === true,
      customLogoUrl: config.customLogoUrl || null,
      logoRedirectUrl: config.logoRedirectUrl || null, // ✅ NEW: Include logo redirect URL in response
      aiAgentEnabled: config.aiAgentEnabled === true || false, // Fix: This was wrong syntax
      emailApprovalEnabled: config.emailApprovalEnabled === true,
      approvedEmails: Array.isArray(config.approvedEmails) ? config.approvedEmails : [],
    };

    return res.status(200).json(responsePayload);

  } catch (error) {
    console.error("❌ Error fetching document configuration:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};





// controllers/authCheckController.js
const getUserPlanDetails = async (req, res) => {
  try {
    const { uuid } = req.body;

    console.log("📩 Incoming request for getUserPlanDetails with UUID:", uuid);

    if (!uuid) {
      console.warn("⚠️ UUID missing in request body");
      return res.status(400).json({ error: "UUID is required." });
    }

    // 1. Get email from UserBase
    const user = await UserBase.findOne({ uid: uuid });
    if (!user) {
      console.warn("❌ User not found for UUID:", uuid);
      return res.status(404).json({ error: "User not found." });
    }

    const email = user.email;
    console.log("✅ Found user email:", email);

    // 2. Get paid plan from PaidUser
    const paidInfo = await PaidUser.findOne({ uuid, email }).sort({ createdAt: -1 });

    console.log("💳 PaidUser info:", paidInfo);

    const planType = paidInfo?.planType || "free";
    const planStatus = paidInfo?.planStatus || "expired";
    const renewalDate = paidInfo?.nextDueDate || null;

    // Plan limits
    const planLimits = {
      free: { maxLinks: 3, maxStorage: 50 },
      basic: { maxLinks: 15, maxStorage: 500 },
      pro: { maxLinks: 100, maxStorage: 1024 }, // MB
    };

    const currentPlan = planLimits[planType] || planLimits.free;
    console.log("📊 Current Plan:", currentPlan);

    // 3. Get user's shortened URLs
    const urls = await ShortenedUrl.find({ userUuid: uuid });
    console.log("🔗 Total shortened URLs found:", urls.length);

    let usedStorage = 0;
    let pdfCount = 0;
    let docxCount = 0;
    let videoCount = 0;
    let weburlCount = 0;

    urls.forEach(url => {
      usedStorage += url.fileSizeMB || 0;

      if (url.mimeType.includes("pdf")) pdfCount++;
      else if (url.mimeType.includes("officedocument.wordprocessingml.document")) docxCount++;
      else if (url.mimeType.includes("video")) videoCount++;
      else if (url.mimeType === "weblink") weburlCount++;
    });

    const totalLinksUsed = urls.length;
    const availableLimit = currentPlan.maxLinks - totalLinksUsed;
    const totalLimit = currentPlan.maxLinks;
    const totalStorage = currentPlan.maxStorage;

    let expiryDays = null;
    if (paidInfo && paidInfo.expiredDate) {
      const diffTime = new Date(paidInfo.expiredDate).getTime() - new Date().getTime();
      expiryDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    }

    console.log("📦 Storage Used (MB):", usedStorage);
    console.log("🧮 PDF:", pdfCount, " DOCX:", docxCount, " VIDEO:", videoCount, " WEBLINK:", weburlCount);
    console.log("📈 Limits → Available:", availableLimit, " / Total:", totalLimit);
    console.log("⏳ Expiry in days:", expiryDays);
    console.log("📅 Renewal Date:", renewalDate);

    // 4. Return JSON response
    return res.json({
      planType: planType.charAt(0).toUpperCase() + planType.slice(1),
      planStatus: planStatus.charAt(0).toUpperCase() + planStatus.slice(1),
      renewalDate,
      expiryDays,
      availableLimit,
      totalLimit,
      usedStorage,
      totalStorage,
      pdfCount,
      docxCount,
      videoCount,
      weburlCount,
    });

  } catch (error) {
    console.error("❗ Error in getUserPlanDetails:", error);
    res.status(500).json({ error: "Server error." });
  }
};








const validateShortenedUrl = async (uuid, url) => {
  const shortId = url.split('/').pop(); // Extract the short ID from URL
  const existingShortUrl = await ShortenedUrl.findOne({ userUuid: uuid, shortId });

  if (!existingShortUrl) {
    throw new Error("ID is mismatched");
  }
  return true;
};



// ------------------------
// LOGIN
// ------------------------
const login = async (req, res) => {
  const { email, password } = req.body;
  console.log(email, password);

  if (!email || !password) {
    return res.status(400).json({
      msg: "Bad request. Please add email and password in the request body",
    });
  }

  let foundUser = await User.findOne({ email: req.body.email });
  console.log(foundUser, "founduser")
  if (foundUser) {
    const isMatch = await foundUser.comparePassword(password);
    if (isMatch) {
      // Generate a JWT token for the user
      const token = jwt.sign(
        { id: foundUser._id, name: foundUser.name },
        process.env.JWT_SECRET,
        { expiresIn: "30d" }
      );
      // Retrieve the UUID stored in the user document
      const userUuid = foundUser.uuid;

      console.log(userUuid, "uuid")

      return res.status(200).json({
        msg: "user logged in",
        token,
        uuid: userUuid,
      });
    } else {
      return res.status(400).json({ msg: "Bad password" });
    }
  } else {
    return res.status(400).json({ msg: "Bad credentials" });
  }
};

// ------------------------
// REGISTER
// ------------------------
const register = async (req, res) => {
  let foundUser = await User.findOne({ email: req.body.email });
  if (!foundUser) {
    let { username, email, password } = req.body;
    if (username.length && email.length && password.length) {
      // Generate a unique UUID for the new user
      const userUuid = uuidv4();
      const person = new User({
        name: username,
        email: email,
        password: password,
        uuid: userUuid  // Store the UUID in the user document
      });
      await person.save();
      return res.status(201).json({ person, uuid: userUuid });
    } else {
      return res.status(400).json({ msg: "Please add all values in the request body" });
    }
  } else {
    return res.status(400).json({ msg: "Email already in use" });
  }
};

// ------------------------
// UPLOAD FILE ENDPOINT
// ------------------------



// Upload file handler
const authenticateUser = async (uuid) => {
  try {
    // 1) find the user document by its uid
    const user = await UserBase.findOne({ uid: uuid }).select('_id');
    if (!user) {
      return { message: 'User not found' };
    }


    const { data } = await axios.post(
      'https://submission-sendnow-live.onrender.com/api/forms/checkactivestatus',
      { userId: user._id.toString() }
    );


    return data;

  } catch (err) {
    console.error('Error in authenticateUser:', err);
    // you can throw or wrap this error as you see fit
    throw err;
  }
};


// Configure AWS S3 client
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_KEY,
  region: process.env.AWS_REGION
});


const fileSizeLimitsInactive = {
  "application/pdf": 50,
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": 50,
  "application/msword": 50,
  "video/mp4": 50,
  "video/webm": 50,
  "video/ogg": 50,
  "image/jpeg": 50,
  "image/png": 50,
  "image/gif": 50,
};

// Basic-plan users: 350 MB
const fileSizeLimitsBasic = {
  "application/pdf": 350,
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": 350,
  "application/msword": 350,
  "video/mp4": 350,
  "video/webm": 350,
  "video/ogg": 350,
  "image/jpeg": 350,
  "image/png": 350,
  "image/gif": 350,
};

// Pro-plan users: 1024 MB (1 GB)
const fileSizeLimitsPro = {
  "application/pdf": 1024,
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": 1024,
  "application/msword": 1024,
  "video/mp4": 1024,
  "video/webm": 1024,
  "video/ogg": 1024,
  "image/jpeg": 1024,
  "image/png": 1024,
  "image/gif": 1024,
};

const pageCountCache = new Map();

// Function to count PDF pages on backend
async function getTotalPages(pdfUrl) {
  try {
    if (pageCountCache.has(pdfUrl)) {
      console.log(`📄 Using cached page count for: ${pdfUrl}`);
      return pageCountCache.get(pdfUrl);
    }

    console.log(`📄 Counting pages for PDF: ${pdfUrl}`);

    const response = await axios.get(pdfUrl, { 
      responseType: "arraybuffer",
      timeout: 60000,
      maxContentLength: 50 * 1024 * 1024 
    });
    
    const pdfData = new Uint8Array(response.data);

    // Import PDF.js
    const pdfjsLib = await import('pdfjs-dist/legacy/build/pdf.js');

    // Disable worker in Node.js
    pdfjsLib.GlobalWorkerOptions.workerSrc = false;

    const pdfDocument = await pdfjsLib.getDocument({
      data: pdfData,
      verbosity: 0
    }).promise;

    const pageCount = pdfDocument.numPages;
    pageCountCache.set(pdfUrl, pageCount);

    console.log(`✅ PDF has ${pageCount} pages`);
    return pageCount;

  } catch (error) {
    console.error("❌ Error counting PDF pages:", error.message);
    // fallback regex method...
    try {
      const fallbackCount = await countPagesUsingRegex(pdfUrl);
      if (fallbackCount > 0) {
        pageCountCache.set(pdfUrl, fallbackCount);
        return fallbackCount;
      }
    } catch {}
    return 1;
  }
}

// Fallback method: Parse PDF using regex patterns
async function countPagesUsingRegex(pdfUrl) {
  try {
    const response = await axios.get(pdfUrl, { 
      responseType: "text",
      timeout: 30000
    });
    
    const pdfText = response.data;
    
    // Look for /Count entries which indicate page count
    const countMatches = pdfText.match(/\/Count\s+(\d+)/g);
    if (countMatches && countMatches.length > 0) {
      const counts = countMatches.map(match => {
        const num = match.match(/\d+/);
        return num ? parseInt(num[0]) : 0;
      });
      
      // Return the highest count found (usually the total page count)
      const maxCount = Math.max(...counts);
      if (maxCount > 0) {
        console.log(`📄 Fallback method found ${maxCount} pages`);
        return maxCount;
      }
    }
    
    // Alternative: Look for /Type /Page entries
    const pageMatches = pdfText.match(/\/Type\s*\/Page[^s]/g);
    if (pageMatches && pageMatches.length > 0) {
      console.log(`📄 Fallback method found ${pageMatches.length} page objects`);
      return pageMatches.length;
    }
    
    return 0;
  } catch (error) {
    console.error("❌ Regex fallback failed:", error.message);
    return 0;
  }
}

// Helper function to determine if file should have page count
function shouldCountPages(mimeType, fileName) {
  // ALWAYS count pages for these document types since URL is always PDF
  const documentTypes = [
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", // DOCX
    "application/msword", // DOC
    "application/vnd.openxmlformats-officedocument.presentationml.presentation", // PPTX
    "application/vnd.ms-powerpoint" // PPT
  ];
  
  if (documentTypes.includes(mimeType)) {
    console.log(`📄 File type ${mimeType} qualifies for page counting`);
    return true;
  }
  
  // Also check filename for PDF extension (additional safety)
  if (fileName && (fileName.toLowerCase().includes('.pdf') || fileName.toLowerCase().includes('_converted.pdf'))) {
    console.log(`📄 Filename ${fileName} indicates PDF - counting pages`);
    return true;
  }
  
  console.log(`📄 File type ${mimeType} with filename ${fileName} - NOT counting pages`);
  return false;
}

// Updated uploadFile function with backend page counting
const uploadFile = async (req, res) => {
  try {
    // Extract all data from the payload
    const { 
      shortId, 
      url, 
      fileName, 
      mimeType, 
      fileSizeMB, 
      totalPages, // This will be ignored, we'll count on backend
      uuid
    } = req.body;

    console.log(`🔍 Processing file: ${fileName}`);
    console.log(`📋 MIME type: ${mimeType}`);
    console.log(`🔗 URL: ${url}`);

    // Validate all required fields
    if (!shortId) return res.status(400).json({ message: "Short ID is required" });
    if (!uuid) return res.status(400).json({ message: "UUID is required" });
    if (!url) return res.status(400).json({ message: "File URL is required" });
    if (!fileName) return res.status(400).json({ message: "File name is required" });
    if (!mimeType) return res.status(400).json({ message: "MIME type is required" });
    if (fileSizeMB === undefined || fileSizeMB === null) {
      return res.status(400).json({ message: "File size is required" });
    }

    // 1) Authenticate user & get plan
    let auth;
    try {
      auth = await authenticateUser(uuid);
    } catch (err) {
      console.error('Authentication helper error:', err);
      return res.status(500).json({ message: 'Internal authentication error' });
    }

    // 2) Determine plan-based limits
    let countLimit, expireDays;
    if (auth?.active === true) {
      if (auth.planType === 'basic') {
        countLimit = 15;
        expireDays = 60;
      } else if (auth.planType === 'pro') {
        countLimit = 100;
        expireDays = 180;
      } else {
        countLimit = 3;
        expireDays = 7;
      }
    } else {
      countLimit = 3;
      expireDays = 7;
    }

    // 3) Enforce upload count limit
    const existingCount = await ShortenedUrl.countDocuments({ userUuid: uuid });
    if (existingCount >= countLimit) {
      return res.status(400).json({
        message: `Upload limit reached (${existingCount}/${countLimit}).`
      });
    }

    // 4) Enforce storage cap
    let storageCap;
    if (auth.active) {
      if (auth.planType === 'basic') {
        storageCap = 500; // MB
      } else if (auth.planType === 'pro') {
        storageCap = 1024; // MB
      } else {
        storageCap = 50; // MB
      }
    } else {
      storageCap = 50; // MB
    }

    // Check current storage usage
    const storageAgg = await ShortenedUrl.aggregate([
      { $match: { userUuid: uuid } },
      { $group: { _id: null, totalUsed: { $sum: "$fileSizeMB" } } }
    ]);

    const currentUsageMB = storageAgg.length ? storageAgg[0].totalUsed : 0;

    if (currentUsageMB + fileSizeMB > storageCap) {
      return res.status(400).json({
        message: `Storage cap exceeded. Used ${currentUsageMB.toFixed(2)} MB of ${storageCap} MB. This file would add ${fileSizeMB.toFixed(2)} MB.`
      });
    }

    // 5) Prepare expiration dates
    const effectiveDate = new Date();
    const expirationDate = new Date(effectiveDate.getTime() + expireDays * 24 * 60 * 60 * 1000);

    // 6) Count PDF pages on backend - ALWAYS for document types
    let backendPageCount = null;
    
    // Check if this file type should have pages counted
    const needsPageCount = shouldCountPages(mimeType, fileName);
    
    if (needsPageCount) {
      try {
        console.log(`🔍 COUNTING PAGES for ${fileName} (MIME: ${mimeType})`);
        console.log(`📄 Attempting to count pages from URL: ${url}`);
        
        backendPageCount = await getTotalPages(url);
        console.log(`📊 ✅ SUCCESS: Backend counted ${backendPageCount} pages for ${fileName}`);
      } catch (pageCountError) {
        console.error(`⚠️ FAILED to count pages for ${fileName}:`, pageCountError.message);
        backendPageCount = 1; // Default fallback
        console.log(`📊 Using fallback page count: ${backendPageCount}`);
      }
    } else {
      console.log(`ℹ️ SKIPPING page count for ${fileName} (MIME: ${mimeType}) - not a document type`);
    }

    // 7) Prepare the database document
    const documentData = {
      shortId,
      fileName,
      mimeType, // Keep original MIME type for database
      originalUrl: url, // The S3 PDF URL from frontend
      effectiveDate,
      expirationDate,
      userUuid: uuid,
      fileSizeMB: parseFloat(fileSizeMB) // Ensure it's a number
    };

    // Add backend-counted totalPages if applicable
    if (backendPageCount !== null) {
      documentData.totalPages = backendPageCount;
      console.log(`📊 Storing ${backendPageCount} pages in database for ${fileName}`);
    }

    // 8) Create the database record
    const createdRecord = await ShortenedUrl.create(documentData);

    // 9) Prepare success response
    let successMessage = "File processed successfully";
    
    // Customize message based on file type
    if (mimeType.startsWith('video/')) {
      successMessage = "Video uploaded successfully";
    } else if (mimeType === "application/pdf") {
      successMessage = `PDF uploaded successfully${backendPageCount ? ` (${backendPageCount} pages)` : ''}`;
    } else if (mimeType.includes('word') || mimeType.includes('presentation')) {
      // For converted files, mention the original format
      let originalFormat = 'Document';
      if (mimeType.includes('word')) {
        originalFormat = 'Word document';
      } else if (mimeType.includes('presentation')) {
        originalFormat = 'PowerPoint presentation';
      }
      successMessage = `${originalFormat} converted to PDF and uploaded successfully${backendPageCount ? ` (${backendPageCount} pages)` : ''}`;
    }

    // 10) Return comprehensive success response
    const responseData = {
      message: successMessage,
      shortId,
      file: {
        url,
        mimeType,
        fileName,
        fileSizeMB,
        ...(backendPageCount !== null && { totalPages: backendPageCount })
      },
      effectiveDate,
      expirationDate,
      originalUrl: url,
      recordId: createdRecord._id,
      storageUsed: {
        current: (currentUsageMB + fileSizeMB).toFixed(2),
        total: storageCap,
        percentage: (((currentUsageMB + fileSizeMB) / storageCap) * 100).toFixed(1)
      },
      ...(backendPageCount !== null && { pageCountMethod: 'backend' })
    };

    console.log(`✅ File processed successfully: ${fileName} (${fileSizeMB.toFixed(2)} MB) for user ${uuid}${backendPageCount ? ` - ${backendPageCount} pages counted and stored` : ''}`);
    
    return res.status(200).json(responseData);

  } catch (error) {
    console.error("❌ Error during file processing:", error);
    
    // Handle specific error types
    if (error.name === 'ValidationError') {
      return res.status(400).json({
        message: "Validation error",
        error: error.message
      });
    }
    
    if (error.name === 'MongoError' || error.name === 'MongoServerError') {
      return res.status(500).json({
        message: "Database error occurred",
        error: "Please try again later"
      });
    }

    return res.status(500).json({
      message: "Error processing file",
      error: error.message
    });
  }
};


// OPTIMIZED: Streaming upload function with multipart support
async function streamUploadToS3({ bucket, key, body, contentType, contentDisposition, contentLength }) {
  const uploadParams = {
    Bucket: bucket,
    Key: key,
    Body: body,
    ContentType: contentType,
    ...(contentDisposition && { ContentDisposition: contentDisposition }),
    ...(contentLength && { ContentLength: contentLength })
  };

  // For large files, use multipart upload
  if (body.length > 100 * 1024 * 1024) { // 100MB threshold
    return await s3.upload(uploadParams, {
      partSize: 10 * 1024 * 1024, // 10MB parts
      queueSize: 4, // Upload 4 parts concurrently
      leavePartsOnError: false
    }).promise();
  } else {
    return await s3.upload(uploadParams).promise();
  }
}

// OPTIMIZED: Conversion function with streaming
async function convertDocxToPdf(buffer, originalName) {
  const base64 = buffer.toString('base64');
  const convertResp = await axios.post(
    "https://v2.convertapi.com/convert/docx/to/pdf",
    {
      Parameters: [
        { Name: "File", FileValue: { Name: originalName, Data: base64 } },
        { Name: "StoreFile", Value: true }
      ]
    },
    {
      headers: {
        Authorization: `Bearer DgxdX08QYXeXpZHNjeMuhtpva7wXTPlu`,
        "Content-Type": "application/json"
      },
      timeout: 120000 // 2 minutes timeout
    }
  );

  const pdfUrl = convertResp.data.Files[0].Url;
  const pdfResponse = await axios.get(pdfUrl, { 
    responseType: 'arraybuffer',
    timeout: 120000 // 2 minutes timeout
  });
  
  return Buffer.from(pdfResponse.data);
}



async function getTotalPages(pdfUrl) {
  try {
    // Check cache first
    if (pageCountCache.has(pdfUrl)) {
      return pageCountCache.get(pdfUrl);
    }

    const pdfjsLib = await import("pdfjs-dist/build/pdf.mjs");
    const response = await axios.get(pdfUrl, { 
      responseType: "arraybuffer",
      timeout: 60000 // 1 minute timeout
    });
    
    const pdfData = new Uint8Array(response.data);
    const pdfDocument = await pdfjsLib.getDocument({ data: pdfData }).promise;
    const pageCount = pdfDocument.numPages;
    
    // Cache the result
    pageCountCache.set(pdfUrl, pageCount);
    
    return pageCount;
  } catch (error) {
    console.error("Error fetching PDF or counting pages:", error);
    throw new Error("Failed to count pages in the PDF.");
  }
}

// Function to get total pages using pdf.js
async function getTotalPages(pdfUrl) {
  try {
    const pdfjsLib = await import("pdfjs-dist/build/pdf.mjs");
    const response = await axios.get(pdfUrl, { responseType: "arraybuffer" });
    const pdfData = new Uint8Array(response.data);
    const pdfDocument = await pdfjsLib.getDocument({ data: pdfData }).promise;
    return pdfDocument.numPages;
  } catch (error) {
    console.error("Error fetching PDF or counting pages:", error);
    throw new Error("Failed to count pages in the PDF.");
  }
}


// Helper function to fetch page count using PDF.co API with a timeout
// Helper function to fetch page count using PDF.co API with a timeout
const getParsedDocumentDataWithTimeout = async (pdfUrl) => {
  const timeout = 15000; // 15 seconds timeout
  const fallbackPageCount = 10; // Static page count to use when API fails or times out

  // Create a promise for the API call (call the original getParsedDocumentData function)
  const apiCall = getParsedDocumentData(pdfUrl); // Ensure getParsedDocumentData is referenced correctly

  // Create a timeout promise that rejects after the specified time
  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("API request timed out")), timeout)
  );

  // Use Promise.race to race the API call and timeout
  try {
    const pageCount = await Promise.race([apiCall, timeoutPromise]);
    return pageCount;
  } catch (error) {
    console.error("Error or timeout during page count retrieval:", error);
    // Return the fallback page count if API call fails or times out
    return fallbackPageCount;
  }
};

// Original helper function (make sure this function is defined in the same file)
const getParsedDocumentData = async (pdfUrl) => {
  const apiKey = "wejolox271@hosintoy.com_Unn8vEA8uggCcVckt859adGOVo0m5sSsHLb9XgKvsNhHwUJxSCG9P8LnyQO0VXQfs"; // Replace with your PDF.co API key
  const url = "https://api.pdf.co/v1/pdf/documentparser";

  const headers = {
    "Content-Type": "application/json",
    "x-api-key": apiKey,
  };

  const body = JSON.stringify({
    url: pdfUrl,
    outputFormat: "JSON",
    templateId: "1", // Ensure this template ID matches your setup on PDF.co
    async: false,
    inline: "true",
    password: "",  // If your PDF is password-protected, add the password here
    profiles: ""    // Add any profiles if needed
  });

  try {
    const response = await axios.post(url, body, { headers });

    if (response.data && response.data.pageCount) {
      const pageCount = response.data.pageCount;  // Extract total page count from the response
      console.log("Parsed Document Data:", response.data);  // Log the response for debugging
      return pageCount;  // Return the total page count
    } else {
      throw new Error("Failed to retrieve page count from PDF.co");
    }
  } catch (error) {
    console.error("Error parsing document:", error);
    throw error;
  }
};





// ------------------------
// UPLOAD URL ENDPOINT
// ------------------------

const uploadurl = async (req, res) => {
  try {
    const { originalUrl, shortId, uuid } = req.body;

    if (!originalUrl || !shortId || !uuid) {
      return res
        .status(400)
        .json({ message: "Original URL, Short ID, and UUID are required." });
    }

    // Normalize input URL
    let normalizedUrl = originalUrl.trim();
    if (/^www\./i.test(normalizedUrl)) {
      normalizedUrl = "https://" + normalizedUrl;
    } else if (!/^https?:\/\//i.test(normalizedUrl)) {
      return res
        .status(400)
        .json({ message: "URL must start with http://, https:// or www." });
    }

    // Parse hostname
    let hostname;
    try {
      hostname = new URL(normalizedUrl).hostname.toLowerCase();
      if (hostname.startsWith("www.")) hostname = hostname.slice(4);
    } catch (err) {
      console.error("❌ URL parsing failed:", err.message);
      return res.status(400).json({ message: "Invalid URL format." });
    }

    // Blacklist check
    for (const banned of TOP_SITES_BLACKLIST) {
      if (hostname === banned || hostname.endsWith(`.${banned}`)) {
        console.warn(`⚠️ Blocked URL attempt to banned domain: ${hostname}`);
        return res
          .status(403)
          .json({ message: `Links to ${banned} are not allowed.` });
      }
    }

    // Authenticate and assign limits
    let countLimit = 3;
    let expirationDays = 7;

    const auth = await authenticateUser(uuid);
    if (auth.active) {
      if (auth.planType === "basic") {
        countLimit = 15;
        expirationDays = 60;
      } else if (auth.planType === "pro") {
        countLimit = 100;
        expirationDays = 180;
      }
    }

    // Check upload limit
    const existingCount = await ShortenedUrl.countDocuments({ userUuid: uuid });
    if (existingCount >= countLimit) {
      return res.status(400).json({
        message: `Upload limit reached (${existingCount}/${countLimit}).`,
      });
    }

    const effectiveDate = new Date();
    const expirationDate = new Date(
      effectiveDate.getTime() + expirationDays * 24 * 60 * 60 * 1000
    );

    const shortenedUrl = new ShortenedUrl({
      originalUrl,
      fileName: originalUrl,
      shortId,
      mimeType: "weblink",
      userUuid: uuid,
      effectiveDate,
      expirationDate,
      totalPages: 0,
      duration: 0,
      fileSizeMB: 0.5,
    });

    await shortenedUrl.save();

    res.status(200).json({
      message: "URL saved successfully",
      shortenedUrl,
    });
  } catch (error) {
    console.error("❌ Unexpected error in uploadurl controller:", error);
    res.status(500).json({
      message: "Server error while saving URL",
      error: error.message,
    });
  }
};


const dashboardData = async (req, res) => {
  try {
    const { uuid } = req.body;
    if (!uuid) {
      return res.status(400).json({ message: "UUID is required" });
    }

    // Find all URL records associated with the given user UUID.
    const urls = await ShortenedUrl.find({ userUuid: uuid });

    // Prepare grouped data by category - ADD POWERPOINT CATEGORY
    const groupedData = {
      web: [],
      docx: [],
      pdf: [],
      video: [],
      powerpoint: [] // NEW: Add PowerPoint category
    };

    // Function to calculate the expiration in human-readable format
    const getExpirationText = (expirationDate) => {
      if (!expirationDate) {
        return "No expiration";
      }

      const now = new Date();
      const diffMs = new Date(expirationDate) - now;
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      const diffMonths = Math.floor(diffDays / 30);
      const diffYears = Math.floor(diffDays / 365);

      if (diffMs <= 0) {
        return "Expired";
      } else if (diffYears > 0) {
        return `${diffYears} year`;
      } else if (diffMonths > 0) {
        return `${diffMonths} month`;
      } else if (diffDays > 7) {
        return `${Math.floor(diffDays / 7)} week`;
      } else {
        return `${diffDays} day`;
      }
    };

    // OPTIMIZED: Get field name based on mimeType
    const getFieldNameFromMimeType = (mimeType) => {
      if (mimeType === "weblink") {
        return "weblink";
      } else if (
        mimeType === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
        mimeType === "application/msword"
      ) {
        return "docx";
      } else if (mimeType === "application/pdf") {
        return "pdf";
      } else if (mimeType.startsWith("video/")) {
        return "video";
      } else if (
        mimeType === "application/vnd.openxmlformats-officedocument.presentationml.presentation" ||
        mimeType === "application/vnd.ms-powerpoint"
      ) {
        return "powerpoint"; // NEW: PowerPoint field mapping
      } else {
        return "weblink"; // Default
      }
    };

    // OPTIMIZED: Batch fetch all views and downloads data at once
    const shortIds = urls.map(url => url.shortId);
    
    // Batch fetch all newUser documents
    const allNewUserDocs = await newUser.find({ documentId: { $in: shortIds } });
    
    // Batch fetch all returnedUser documents  
    const allReturnedUserDocs = await ReturnedUser.find({ documentId: { $in: shortIds } });
    
    // Batch fetch all download documents
    const allDownloadDocs = await DocumentDownloads.find({ documentId: { $in: shortIds } });
    
    // Create lookup maps for faster access
    const newUserMap = new Map();
    const returnedUserMap = new Map();
    const downloadMap = new Map();
    
    // Group newUser docs by documentId
    allNewUserDocs.forEach(doc => {
      if (!newUserMap.has(doc.documentId)) {
        newUserMap.set(doc.documentId, []);
      }
      newUserMap.get(doc.documentId).push(doc);
    });
    
    // Group returnedUser docs by documentId
    allReturnedUserDocs.forEach(doc => {
      if (!returnedUserMap.has(doc.documentId)) {
        returnedUserMap.set(doc.documentId, []);
      }
      returnedUserMap.get(doc.documentId).push(doc);
    });
    
    // Group download docs by documentId
    allDownloadDocs.forEach(doc => {
      if (!downloadMap.has(doc.documentId)) {
        downloadMap.set(doc.documentId, []);
      }
      downloadMap.get(doc.documentId).push(doc);
    });

    // OPTIMIZED: Function to get total views count for a shortId using lookup maps
    const getTotalViews = (shortId, mimeType) => {
      const fieldName = getFieldNameFromMimeType(mimeType);
      let totalCount = 0;

      // Get newUser count from map
      const newUserDocs = newUserMap.get(shortId) || [];
      newUserDocs.forEach(doc => {
        if (doc.count && doc.count[fieldName]) {
          totalCount += doc.count[fieldName];
        }
      });

      // Get returnedUser count from map
      const returnedUserDocs = returnedUserMap.get(shortId) || [];
      returnedUserDocs.forEach(doc => {
        if (doc.count && doc.count[fieldName] && doc.count[fieldName] > 1) {
          totalCount += doc.count[fieldName];
        }
      });

      return totalCount;
    };

    // OPTIMIZED: Function to get total downloads count for a shortId using lookup maps
    const getTotalDownloads = (shortId) => {
      const downloadDocs = downloadMap.get(shortId) || [];
      let totalDownloads = 0;
      
      downloadDocs.forEach(doc => {
        if (doc.downloadCount) {
          totalDownloads += doc.downloadCount;
        }
      });

      return totalDownloads;
    };

    // Process each URL document
    for (const urlDoc of urls) {
    
      
      // UPDATED: Determine the category based on the MIME type - ADD POWERPOINT
      let category = "";
      if (urlDoc.mimeType === "weblink") {
        category = "web";
      } else if (
        urlDoc.mimeType === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
        urlDoc.mimeType === "application/msword"
      ) {
        category = "docx";
      } else if (urlDoc.mimeType === "application/pdf") {
        category = "pdf";
      } else if (urlDoc.mimeType.startsWith("video/")) {
        category = "video";
      } else if (
        urlDoc.mimeType === "application/vnd.openxmlformats-officedocument.presentationml.presentation" ||
        urlDoc.mimeType === "application/vnd.ms-powerpoint"
      ) {
        category = "powerpoint"; // NEW: PowerPoint category
      } else {
        category = "web"; // Default to web if no match.
      }

      // Calculate the time difference based on the createdAt timestamp.
      const createdDateObj = new Date(urlDoc.createdAt);
      const now = new Date();
      const diffMs = now - createdDateObj;
      const diffSeconds = Math.floor(diffMs / 1000);
      let timeAgo = "";

      if (diffSeconds < 60) {
        timeAgo = `${diffSeconds} seconds ago`;
      } else if (diffSeconds < 3600) {
        timeAgo = `${Math.floor(diffSeconds / 60)} minutes ago`;
      } else if (diffSeconds < 86400) {
        timeAgo = `${Math.floor(diffSeconds / 3600)} hours ago`;
      } else if (diffSeconds < 2592000) {
        timeAgo = `${Math.floor(diffSeconds / 86400)} days ago`;
      } else if (diffSeconds < 31536000) {
        timeAgo = `${Math.floor(diffSeconds / 2592000)} month(s) ago`;
      } else {
        timeAgo = `${Math.floor(diffSeconds / 31536000)} year(s) ago`;
      }

      // Get expiration date
      const expirationText = getExpirationText(urlDoc.expirationDate);

      // OPTIMIZED: Get total views and downloads using lookup maps (no await needed)
      const totalViews = getTotalViews(urlDoc.shortId, urlDoc.mimeType);
      const totalDownloads = getTotalDownloads(urlDoc.shortId);

      // Add the record to the appropriate group.
      groupedData[category].push({
        url: `https://sd4.live/${urlDoc.shortId}`,
        fileName: urlDoc.fileName || "N/A",
        createdDate: createdDateObj.toISOString().split("T")[0],
        timeAgo: timeAgo,
        expiration: expirationText,
        totalviews: totalViews,
        totaldownloads: totalDownloads
      });
    }

    return res.status(200).json({
      status: "success",
      message: "Dashboard data fetched successfully",
      data: groupedData
    });
  } catch (error) {
    console.error("Error fetching dashboard data:", error);
    return res.status(500).json({
      message: "Error fetching dashboard data",
      error: error.message
    });
  }
};


const Pdf_pdfanalytics = async (req, res) => {
  try {
    const { uuid, url, category } = req.body;
    console.log(req.body, "Request Body");

    // First check if uuid and shortId are matching
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Normalize category to lowercase
    const normalizedCategory = category.toLowerCase();
    console.log(normalizedCategory, "Normalized Category");

    // Extract the document ID from the URL (assuming the ID is the last segment)
    const pdfId = url.split('/').pop();
    console.log(pdfId, "pdfId");

    // Fetch all analytics data for the given pdfId
    const pdfAnalytics = await Pdfanalytics.find({ pdfId });
    console.log(pdfAnalytics, "pdfAnalytics");

    if (!pdfAnalytics || pdfAnalytics.length === 0) {
      return res.status(404).json({ message: 'PDF document not found' });
    }

    let totalTimeSpent = 0;
    let totalPagesVisited = 0;
    let mostVisitedPage = '';
    let bounceSessions = 0;

    pdfAnalytics.forEach((doc) => {
      totalTimeSpent += doc.totalTimeSpent;
      totalPagesVisited += doc.totalPagesVisited;

      if (!mostVisitedPage && doc.mostVisitedPage) {
        mostVisitedPage = doc.mostVisitedPage;
      }

      // Bounce session condition (if only 1 page was visited)
      if (doc.totalPagesVisited === 1) {
        bounceSessions += 1;
      }
    });

    // Total sessions count (without Set)
    const totalSessions = pdfAnalytics.length;
    console.log("Total sessions for this PDF:", totalSessions);

    // Average Time Spent Calculation
    let averageTimeSpent = totalPagesVisited > 0 ? totalTimeSpent / totalPagesVisited : 0;
    console.log(averageTimeSpent, "Average Time Spent");

    // NEW USER COUNT
    const newUsers = await newUser.find({
      documentId: pdfId,
      [`count.${normalizedCategory}`]: { $gt: 0 },
    });

    const newUserCategoryCount = newUsers.reduce(
      (sum, user) => sum + (user.count[normalizedCategory] || 0),
      0
    );
    console.log("New user count for", normalizedCategory, ":", newUserCategoryCount);

    // RETURNED USER COUNT
    const returnedUsers = await ReturnedUser.find({
      documentId: pdfId,
      [`count.${normalizedCategory}`]: { $gt: 0 },
    });

    const returnedUserCategoryCount = returnedUsers.reduce(
      (sum, user) => sum + (user.count[normalizedCategory] || 0),
      0
    );
    console.log("Returned user count for", normalizedCategory, ":", returnedUserCategoryCount);

    // Bounce Rate Calculation
    const bounceRate = totalSessions > 0 ? (bounceSessions / totalSessions) * 100 : 0;
    console.log("Bounce Rate:", bounceRate.toFixed(2) + "%");

    // Prepare the response data
    const responseData = {
      totalPagesVisited,
      totalTimeSpent,
      averageTimeSpent,
      userCounts: {
        newuser: { [normalizedCategory]: newUserCategoryCount },
        returneduser: { [normalizedCategory]: (returnedUserCategoryCount - newUserCategoryCount) },
      },
      mostVisitedPage,
      totalsession: totalSessions,  // Now using direct length instead of Set
      bounceRate
    };

    console.log(responseData, "Response Data");
    res.json(responseData);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: 'An error occurred while processing the metrics',
      error: error.message,
    });
  }
};

const PowerPoint_analytics = async (req, res) => {
  try {
    const { uuid, url, category } = req.body;
    console.log(req.body, "Request Body");

    // First check if uuid and shortId are matching
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Normalize category to lowercase
    const normalizedCategory = category.toLowerCase();
    console.log(normalizedCategory, "Normalized Category");

    // Extract the document ID from the URL (assuming the ID is the last segment)
    const pdfId = url.split('/').pop();
    console.log(pdfId, "pdfId");

    // Fetch all analytics data for the given pdfId
    const pdfAnalytics = await PowerPointAnalytics.find({ pdfId });
    console.log(pdfAnalytics, "pdfAnalytics");

    if (!pdfAnalytics || pdfAnalytics.length === 0) {
      return res.status(404).json({ message: 'PDF document not found' });
    }

    let totalTimeSpent = 0;
    let totalPagesVisited = 0;
    let mostVisitedPage = '';
    let bounceSessions = 0;

    pdfAnalytics.forEach((doc) => {
      totalTimeSpent += doc.totalTimeSpent;
      totalPagesVisited += doc.totalPagesVisited;

      if (!mostVisitedPage && doc.mostVisitedPage) {
        mostVisitedPage = doc.mostVisitedPage;
      }

      // Bounce session condition (if only 1 page was visited)
      if (doc.totalPagesVisited === 1) {
        bounceSessions += 1;
      }
    });

    // Total sessions count (without Set)
    const totalSessions = pdfAnalytics.length;
    console.log("Total sessions for this PDF:", totalSessions);

    // Average Time Spent Calculation
    let averageTimeSpent = totalPagesVisited > 0 ? totalTimeSpent / totalPagesVisited : 0;
    console.log(averageTimeSpent, "Average Time Spent");

    // NEW USER COUNT
    const newUsers = await newUser.find({
      documentId: pdfId,
      [`count.${normalizedCategory}`]: { $gt: 0 },
    });

    const newUserCategoryCount = newUsers.reduce(
      (sum, user) => sum + (user.count[normalizedCategory] || 0),
      0
    );
    console.log("New user count for", normalizedCategory, ":", newUserCategoryCount);

    // RETURNED USER COUNT
    const returnedUsers = await ReturnedUser.find({
      documentId: pdfId,
      [`count.${normalizedCategory}`]: { $gt: 0 },
    });

    const returnedUserCategoryCount = returnedUsers.reduce(
      (sum, user) => sum + (user.count[normalizedCategory] || 0),
      0
    );
    console.log("Returned user count for", normalizedCategory, ":", returnedUserCategoryCount);

    // Bounce Rate Calculation
    const bounceRate = totalSessions > 0 ? (bounceSessions / totalSessions) * 100 : 0;
    console.log("Bounce Rate:", bounceRate.toFixed(2) + "%");

    // Prepare the response data
    const responseData = {
      totalPagesVisited,
      totalTimeSpent,
      averageTimeSpent,
      userCounts: {
        newuser: { [normalizedCategory]: newUserCategoryCount },
        returneduser: { [normalizedCategory]: (returnedUserCategoryCount - newUserCategoryCount) },
      },
      mostVisitedPage,
      totalsession: totalSessions,  // Now using direct length instead of Set
      bounceRate
    };

    console.log(responseData, "Response Data");
    res.json(responseData);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: 'An error occurred while processing the metrics',
      error: error.message,
    });
  }
};

const Docx_docxanalytics = async (req, res) => {
  try {
    const { url, category, uuid } = req.body;
    console.log(req.body, "Request Body");

    // Validate input
    if (!url || !category) {
      return res.status(400).json({ message: "URL and category are required" });
    }

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Normalize category to lowercase
    const normalizedCategory = category.toLowerCase();
    console.log(normalizedCategory, "Normalized Category");

    // Extract document ID from URL
    const docxId = url.split('/').pop();
    if (!docxId) {
      return res.status(400).json({ message: "Invalid document URL" });
    }
    console.log(docxId, "docxId");

    // Fetch analytics data
    const docxAnalytics = await Docxanalytics.find({ pdfId: docxId });
    if (!docxAnalytics.length) {
      return res.status(404).json({ message: "DOCX document not found" });
    }
    console.log(docxAnalytics, "docxAnalytics");

    // Compute metrics
    let totalTimeSpent = docxAnalytics.reduce((sum, doc) => sum + doc.totalTimeSpent, 0);
    let totalPagesVisited = docxAnalytics.reduce((sum, doc) => sum + doc.totalPagesVisited, 0);
    let mostVisitedPage = docxAnalytics
      .filter(doc => doc.mostVisitedPage)
      .sort((a, b) => b.totalPagesVisited - a.totalPagesVisited)[0]?.mostVisitedPage || "";

    let bounceSessions = docxAnalytics.filter(doc => doc.totalPagesVisited === 1).length;
    let totalSessions = docxAnalytics.length;
    let averageTimeSpent = totalPagesVisited > 0 ? totalTimeSpent / totalPagesVisited : 0;
    let bounceRate = totalSessions > 0 ? (bounceSessions / totalSessions) * 100 : 0;

    console.log({ averageTimeSpent, bounceRate }, "Computed Metrics");

    // Fetch New Users Count
    const newUsers = await newUser.find({
      documentId: docxId,
      [`count.${normalizedCategory}`]: { $gt: 0 },
    });
    let newUserCategoryCount = newUsers.reduce(
      (sum, user) => sum + (user.count[normalizedCategory] || 0),
      0
    );

    // Fetch Returned Users Count
    const returnedUsers = await ReturnedUser.find({
      documentId: docxId,
      [`count.${normalizedCategory}`]: { $gt: 0 },
    });
    let returnedUserCategoryCount = returnedUsers.reduce(
      (sum, user) => sum + (user.count[normalizedCategory] || 0),
      0
    );

    console.log("User Counts:", { newUserCategoryCount, returnedUserCategoryCount });

    // Prepare response
    const responseData = {
      totalPagesVisited,
      totalTimeSpent,
      averageTimeSpent,
      userCounts: {
        newuser: { [normalizedCategory]: newUserCategoryCount },
        returneduser: { [normalizedCategory]: (returnedUserCategoryCount - newUserCategoryCount) },
      },
      mostVisitedPage,
      totalsession: totalSessions,
      bounceRate,
    };

    console.log(responseData, "Response Data");
    res.json(responseData);
  } catch (error) {
    console.error("Error processing DOCX metrics:", error);
    res.status(500).json({
      message: "An error occurred while processing the DOCX metrics",
      error: error.message,
    });
  }
};







const DeleteSession = async (req, res) => {
  try {
    const { shortId, mimeType } = req.body;

    console.log("ShortID:", shortId, "MimeType:", mimeType);

    if (!shortId || !mimeType) {
      return res.status(400).json({ message: "Short ID and mimeType are required." });
    }

    // 1. Find and delete record from MongoDB
    const deletedRecord = await ShortenedUrl.findOneAndDelete({ shortId });

    if (!deletedRecord) {
      return res.status(404).json({ message: "Record not found." });
    }

    // 2. Extract key from originalUrl
    const fileUrl = deletedRecord.originalUrl;
    const url = new URL(fileUrl);
    const key = decodeURIComponent(url.pathname.slice(1)); // remove leading slash

    console.log("S3 Key to delete:", key);

    // 3. Delete file from S3 (v2 SDK)
    await s3.deleteObject({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: key,
    }).promise();

    // 4. Delete associated analytics based on mimeType
    switch (mimeType) {
      case "web":
        await Webanalytics.deleteMany({ shortId });
        break;
      case "application/pdf":
        await Pdfanalytics.deleteMany({ shortId });
        break;
      case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        await DocxAnalytics.deleteMany({ shortId });
        break;
      case "video":
      case "video/mp4":
      case "video/webm":
        await VideoAnalytics.deleteMany({ shortId });
        break;
      default:
        console.warn("Unknown or unsupported mimeType:", mimeType);
    }

    return res.status(200).json({
      message: "File, record, and analytics deleted successfully.",
      data: deletedRecord,
    });

  } catch (error) {
    console.error("Error deleting record:", error);
    return res.status(500).json({
      message: "Internal Server Error",
      error: error.message,
    });
  }
};



// Controller function to get documents filtered by pdfId and return only the createdAt field


const getUserActivitiesByPdfId = async (req, res) => {
  try {
    // Extract the pdfId from the URL in the request body
    const pdfIdFromUrl = req.body.url.split("/").pop();
    const uuid = req.body.uuid;
    const { dateRange } = req.body; // Get the date range from the request body

     // First check if uuid and shortId are matching
     try {
      await validateShortenedUrl(uuid, pdfIdFromUrl);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }


    // Set date filters based on the provided date range
    let matchDateFilter = {};
    const today = moment().utc().startOf("day");

    switch (dateRange) {
      case "today":
        matchDateFilter = { createdAt: { $gte: today.toDate() } };
        break;
      case "yesterday":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(1, "days").startOf("day").toDate(),
            $lt: moment().utc().subtract(1, "days").endOf("day").toDate(),
          },
        };
        break;
      case "lastWeek":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(7, "days").startOf("day").toDate(),
            $lte: today.toDate(),
          },
        };
        break;
      case "lastMonth":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(1, "months").startOf("month").toDate(),
            $lte: moment().utc().subtract(1, "months").endOf("month").toDate(),
          },
        };
        break;
      default:
        matchDateFilter = {}; // Fetch all records if no range is provided
    }

    // Aggregation pipeline for fetching user activities
    const aggregatePipeline = [
      { $match: { pdfId: pdfIdFromUrl, ...matchDateFilter } },
      {
        $project: {
          date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          hour: { $hour: "$createdAt" },
        },
      },
      {
        $project: {
          date: 1,
          timeRange: {
            $cond: {
              if: { $lt: ["$hour", 12] },
              then: "00:00-12:00",
              else: "12:00-24:00",
            },
          },
        },
      },
      {
        $group: {
          _id: { date: "$date", timeRange: "$timeRange" },
          userCount: { $sum: 1 },
        },
      },
      { $sort: { "_id.date": 1, "_id.timeRange": 1 } },
    ];

    let userActivities = await Pdfanalytics.aggregate(aggregatePipeline);
    let response = [];

    if (userActivities.length > 0) {
      response = userActivities.map((item) => ({
        date: item._id.date,
        timeRange: item._id.timeRange,
        users: item.userCount,
      }));
    } else if (dateRange === "yesterday") {
      // Fetch all records from yesterday if no specific time-range data exists
      const fallbackData = await Pdfanalytics.find({
        pdfId: pdfIdFromUrl,
        createdAt: {
          $gte: moment().utc().subtract(1, "days").startOf("day").toDate(),
          $lt: moment().utc().subtract(1, "days").endOf("day").toDate(),
        },
      });

      response = fallbackData.map((record) => ({
        date: moment(record.createdAt).format("YYYY-MM-DD"),
        timeRange: "00:00-24:00",
        users: 1, // Assuming each record represents one user visit
      }));

      if (response.length === 0) {
        response = [
          {
            date: moment().utc().subtract(1, "days").format("YYYY-MM-DD"),
            timeRange: "00:00-12:00",
            users: 0,
          },
          {
            date: moment().utc().subtract(1, "days").format("YYYY-MM-DD"),
            timeRange: "12:00-24:00",
            users: 0,
          },
        ];
      }
    } else {
      // Default response when no data is found
      response = [
        {
          date: moment().utc().format("YYYY-MM-DD"),
          timeRange: "00:00-12:00",
          users: 0,
        },
        {
          date: moment().utc().format("YYYY-MM-DD"),
          timeRange: "12:00-24:00",
          users: 0,
        },
      ];
    }

    return res.status(200).json({
      success: true,
      data: response,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Server error, unable to fetch user activities",
    });
  }
};


const getUserActivitiesByPowerPointId = async (req, res) => {
  try {
    // Extract the pdfId from the URL in the request body
    const pdfIdFromUrl = req.body.url.split("/").pop();
    const uuid = req.body.uuid;
    const { dateRange } = req.body; // Get the date range from the request body

     // First check if uuid and shortId are matching
     try {
      await validateShortenedUrl(uuid, pdfIdFromUrl);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }


    // Set date filters based on the provided date range
    let matchDateFilter = {};
    const today = moment().utc().startOf("day");

    switch (dateRange) {
      case "today":
        matchDateFilter = { createdAt: { $gte: today.toDate() } };
        break;
      case "yesterday":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(1, "days").startOf("day").toDate(),
            $lt: moment().utc().subtract(1, "days").endOf("day").toDate(),
          },
        };
        break;
      case "lastWeek":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(7, "days").startOf("day").toDate(),
            $lte: today.toDate(),
          },
        };
        break;
      case "lastMonth":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(1, "months").startOf("month").toDate(),
            $lte: moment().utc().subtract(1, "months").endOf("month").toDate(),
          },
        };
        break;
      default:
        matchDateFilter = {}; // Fetch all records if no range is provided
    }

    // Aggregation pipeline for fetching user activities
    const aggregatePipeline = [
      { $match: { pdfId: pdfIdFromUrl, ...matchDateFilter } },
      {
        $project: {
          date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          hour: { $hour: "$createdAt" },
        },
      },
      {
        $project: {
          date: 1,
          timeRange: {
            $cond: {
              if: { $lt: ["$hour", 12] },
              then: "00:00-12:00",
              else: "12:00-24:00",
            },
          },
        },
      },
      {
        $group: {
          _id: { date: "$date", timeRange: "$timeRange" },
          userCount: { $sum: 1 },
        },
      },
      { $sort: { "_id.date": 1, "_id.timeRange": 1 } },
    ];

    let userActivities = await PowerPointAnalytics.aggregate(aggregatePipeline);
    let response = [];

    if (userActivities.length > 0) {
      response = userActivities.map((item) => ({
        date: item._id.date,
        timeRange: item._id.timeRange,
        users: item.userCount,
      }));
    } else if (dateRange === "yesterday") {
      // Fetch all records from yesterday if no specific time-range data exists
      const fallbackData = await PowerPointAnalytics.find({
        pdfId: pdfIdFromUrl,
        createdAt: {
          $gte: moment().utc().subtract(1, "days").startOf("day").toDate(),
          $lt: moment().utc().subtract(1, "days").endOf("day").toDate(),
        },
      });

      response = fallbackData.map((record) => ({
        date: moment(record.createdAt).format("YYYY-MM-DD"),
        timeRange: "00:00-24:00",
        users: 1, // Assuming each record represents one user visit
      }));

      if (response.length === 0) {
        response = [
          {
            date: moment().utc().subtract(1, "days").format("YYYY-MM-DD"),
            timeRange: "00:00-12:00",
            users: 0,
          },
          {
            date: moment().utc().subtract(1, "days").format("YYYY-MM-DD"),
            timeRange: "12:00-24:00",
            users: 0,
          },
        ];
      }
    } else {
      // Default response when no data is found
      response = [
        {
          date: moment().utc().format("YYYY-MM-DD"),
          timeRange: "00:00-12:00",
          users: 0,
        },
        {
          date: moment().utc().format("YYYY-MM-DD"),
          timeRange: "12:00-24:00",
          users: 0,
        },
      ];
    }

    return res.status(200).json({
      success: true,
      data: response,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Server error, unable to fetch user activities",
    });
  }
};



const getUserActivitiesByDocxId = async (req, res) => {
  try {
    console.log("Incoming Request:", req.body); // Log request body

    // Extract the pdfId from the URL in the request body (assuming docx uses pdfId)
    const pdfIdFromUrl = req.body.url.split("/").pop();
    const uuid = req.body.uuid;


    console.log("Extracted pdfId:", pdfIdFromUrl); // Log extracted pdfId

    try {
      await validateShortenedUrl(uuid, pdfIdFromUrl);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    const { dateRange } = req.body; // Get the date range from the request body
    console.log("Selected Date Range:", dateRange); // Log selected date range

    // Set date filters based on the provided date range
    let matchDateFilter = {};
    const today = moment().utc().startOf("day");

    switch (dateRange) {
      case "today":
        matchDateFilter = { createdAt: { $gte: today.toDate() } };
        break;
      case "yesterday":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(1, "days").startOf("day").toDate(),
            $lt: moment().utc().subtract(1, "days").endOf("day").toDate(),
          },
        };
        break;
      case "lastWeek":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(7, "days").startOf("day").toDate(),
            $lte: today.toDate(),
          },
        };
        break;
      case "lastMonth":
        matchDateFilter = {
          createdAt: {
            $gte: moment().utc().subtract(1, "months").startOf("month").toDate(),
            $lte: moment().utc().subtract(1, "months").endOf("month").toDate(),
          },
        };
        break;
      default:
        matchDateFilter = {}; // Fetch all records if no range is provided
    }

    console.log("Match Date Filter:", matchDateFilter); // Log date filter

    // Aggregation pipeline for fetching user activities
    const aggregatePipeline = [
      { $match: { pdfId: pdfIdFromUrl, ...matchDateFilter } }, // Using pdfId
      {
        $project: {
          date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          hour: { $hour: "$createdAt" },
        },
      },
      {
        $project: {
          date: 1,
          timeRange: {
            $cond: {
              if: { $lt: ["$hour", 12] },
              then: "00:00-12:00",
              else: "12:00-24:00",
            },
          },
        },
      },
      {
        $group: {
          _id: { date: "$date", timeRange: "$timeRange" },
          userCount: { $sum: 1 },
        },
      },
      { $sort: { "_id.date": 1, "_id.timeRange": 1 } },
    ];

    console.log("Aggregation Pipeline:", JSON.stringify(aggregatePipeline, null, 2)); // Log pipeline

    let userActivities = await Docxanalytics.aggregate(aggregatePipeline);
    console.log("Fetched User Activities:", userActivities); // Log fetched activities

    let response = [];

    if (userActivities.length > 0) {
      response = userActivities.map((item) => ({
        date: item._id.date,
        timeRange: item._id.timeRange,
        users: item.userCount,
      }));
    } else if (dateRange === "yesterday") {
      // Fetch all records from yesterday if no specific time-range data exists
      const fallbackData = await Docxanalytics.find({
        pdfId: pdfIdFromUrl,
        createdAt: {
          $gte: moment().utc().subtract(1, "days").startOf("day").toDate(),
          $lt: moment().utc().subtract(1, "days").endOf("day").toDate(),
        },
      });

      response = fallbackData.map((record) => ({
        date: moment(record.createdAt).format("YYYY-MM-DD"),
        timeRange: "00:00-24:00",
        users: 1, // Assuming each record represents one user visit
      }));

      if (response.length === 0) {
        response = [
          {
            date: moment().utc().subtract(1, "days").format("YYYY-MM-DD"),
            timeRange: "00:00-12:00",
            users: 0,
          },
          {
            date: moment().utc().subtract(1, "days").format("YYYY-MM-DD"),
            timeRange: "12:00-24:00",
            users: 0,
          },
        ];
      }
    } else {
      // Default response when no data is found
      response = [
        {
          date: moment().utc().format("YYYY-MM-DD"),
          timeRange: "00:00-12:00",
          users: 0,
        },
        {
          date: moment().utc().format("YYYY-MM-DD"),
          timeRange: "12:00-24:00",
          users: 0,
        },
      ];
    }

    console.log("Final Response:", response); // Log final response

    return res.status(200).json({
      success: true,
      data: response,
    });
  } catch (error) {
    console.error("Error Occurred:", error); // Log error details
    return res.status(500).json({
      success: false,
      message: "Server error, unable to fetch user activities",
    });
  }
};

const getUserActivitiesByWebId = async (req, res) => {
  try {
    console.log("Incoming Request:", req.body); // Log request body

    // Extract the webId from the URL in the request body
    const webId = req.body.url.split("/").pop();

    const uuid = req.body.uuid;

    if (!webId) {
      return res.status(400).json({ message: "Invalid webId" });
    }

    if (!uuid) {
      return res.status(400).json({ message: "UUID is required" });
    }

    try {
      await validateShortenedUrl(uuid, webId);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    console.log("Extracted webId:", webId); // Log extracted webId

    const { dateRange } = req.body; // Get the date range from the request body
    console.log("Selected Date Range:", dateRange); // Log selected date range

    // Set date filters based on the provided date range
    let matchDateFilter = {};
    const today = moment().utc().startOf("day");

    switch (dateRange) {
      case "today":
        matchDateFilter = { inTime: { $gte: today.toDate() } };
        break;
      case "yesterday":
        matchDateFilter = {
          inTime: {
            $gte: moment().utc().subtract(1, "days").startOf("day").toDate(),
            $lt: moment().utc().subtract(1, "days").endOf("day").toDate(),
          },
        };
        break;
      case "lastWeek":
        matchDateFilter = {
          inTime: {
            $gte: moment().utc().subtract(7, "days").startOf("day").toDate(),
            $lte: today.toDate(),
          },
        };
        break;
      case "lastMonth":
        matchDateFilter = {
          inTime: {
            $gte: moment().utc().subtract(1, "months").startOf("month").toDate(),
            $lte: moment().utc().subtract(1, "months").endOf("month").toDate(),
          },
        };
        break;
      default:
        matchDateFilter = {}; // Fetch all records if no range is provided
    }

    console.log("Match Date Filter:", matchDateFilter); // Log date filter

    // Aggregation pipeline for fetching user activities
    const aggregatePipeline = [
      { $match: { webId: webId, ...matchDateFilter } }, // Using webId
      {
        $project: {
          date: { $dateToString: { format: "%Y-%m-%d", date: "$inTime" } },
          hour: { $hour: "$inTime" },
        },
      },
      {
        $project: {
          date: 1,
          timeRange: {
            $cond: {
              if: { $lt: ["$hour", 12] },
              then: "00:00-12:00",
              else: "12:00-24:00",
            },
          },
        },
      },
      {
        $group: {
          _id: { date: "$date", timeRange: "$timeRange" },
          userCount: { $sum: 1 },
        },
      },
      { $sort: { "_id.date": 1, "_id.timeRange": 1 } },
    ];

    console.log("Aggregation Pipeline:", JSON.stringify(aggregatePipeline, null, 2)); // Log pipeline

    const userActivities = await Webanalytics.aggregate(aggregatePipeline); // Using Webanalytics collection
    console.log("Fetched User Activities:", userActivities); // Log fetched activities

    let response = [];

    if (userActivities.length > 0) {
      response = userActivities.map((item) => ({
        date: item._id.date,
        timeRange: item._id.timeRange,
        users: item.userCount,
      }));
    } else if (dateRange === "yesterday") {
      // Fetch all records from yesterday if no specific time-range data exists
      const fallbackData = await Webanalytics.find({
        webId: webId,
        inTime: {
          $gte: moment().utc().subtract(1, "days").startOf("day").toDate(),
          $lt: moment().utc().subtract(1, "days").endOf("day").toDate(),
        },
      });

      response = fallbackData.map((record) => ({
        date: moment(record.inTime).format("YYYY-MM-DD"),
        timeRange: "00:00-24:00",
        users: 1, // Assuming each record represents one user visit
      }));

      if (response.length === 0) {
        response = [
          {
            date: moment().utc().subtract(1, "days").format("YYYY-MM-DD"),
            timeRange: "00:00-12:00",
            users: 0,
          },
          {
            date: moment().utc().subtract(1, "days").format("YYYY-MM-DD"),
            timeRange: "12:00-24:00",
            users: 0,
          },
        ];
      }
    } else {
      // Default response when no data is found
      response = [
        {
          date: moment().utc().format("YYYY-MM-DD"),
          timeRange: "00:00-12:00",
          users: 0,
        },
        {
          date: moment().utc().format("YYYY-MM-DD"),
          timeRange: "12:00-24:00",
          users: 0,
        },
      ];
    }

    console.log("Final Response:", response); // Log final response

    return res.status(200).json({
      success: true,
      data: response,
    });
  } catch (error) {
    console.error("Error Occurred:", error); // Log error details
    return res.status(500).json({
      success: false,
      message: "Server error, unable to fetch user activities",
    });
  }
};






// Fetch coordinates dynamically based on location using a geocoding service
const fetchCoordinates = async (location) => {
  try {
    const apiKey = "8ff2824aad56454c81eb83de0ed489bd"; // OpenCage API Key
    const geocodingUrl = `https://api.opencagedata.com/geocode/v1/json?q=${encodeURIComponent(location)}&key=${apiKey}`;

    const response = await axios.get(geocodingUrl);

    if (response.data && response.data.results && response.data.results.length > 0) {
      const { lat, lng } = response.data.results[0].geometry;
      return [lng, lat]; // Returning coordinates [longitude, latitude]
    } else {
      console.warn(`No coordinates found for location: ${location}`);
      return [0, 0]; // Default fallback
    }
  } catch (error) {
    console.error("Error fetching coordinates:", error);
    return [0, 0]; // Default fallback
  }
};

// Fetch dynamic districts for each city (dynamically based on location)
const getDistricts = async (location) => {
  try {
    const apiKey = "8ff2824aad56454c81eb83de0ed489bd"; // OpenCage API Key
    const geocodingUrl = `https://api.opencagedata.com/geocode/v1/json?q=${encodeURIComponent(location)}&key=${apiKey}`;

    const response = await axios.get(geocodingUrl);

    if (response.data && response.data.results && response.data.results.length > 0) {
      const components = response.data.results[0].components;

      // Extract districts, city, or suburb if available
      const districts = components.city || components.suburb || components.town || [];
      return Array.isArray(districts) ? districts : [districts];
    } else {
      return []; // Return empty if no districts found
    }
  } catch (error) {
    console.error("Error fetching districts:", error);
    return []; // Fallback if API call fails
  }
};

// Calculate daily average percentage based on visit timestamps
const calculateDailyAvg = (visits) => {
  const days = visits.map(visit => visit.toISOString().split('T')[0]); // Extract date (YYYY-MM-DD)
  const uniqueDays = [...new Set(days)];
  return (visits.length / uniqueDays.length).toFixed(2); // Daily average views per day
};

// Calculate percentage change based on visits' views from first to last day
// Calculate percentage change comparing the most recent day (today) versus the previous day.
// If an entry for yesterday does not exist, use the next available prior date.
const calculateChange = (visits) => {
  // Group visits by date (YYYY-MM-DD)
  const dailyCounts = {};
  visits.forEach(visit => {
    const date = visit.toISOString().split('T')[0];
    dailyCounts[date] = (dailyCounts[date] || 0) + 1;
  });

  const dates = Object.keys(dailyCounts).sort(); // Sorted ascending (oldest to newest)

  if (dates.length < 2) return 'no change'; // Not enough days to compare

  // Last date (today-like)
  const lastDate = dates[dates.length - 1];

  // Try to get "yesterday": subtract one day from lastDate
  let yesterdayDate = new Date(lastDate);
  yesterdayDate.setDate(yesterdayDate.getDate() - 1);
  const yesterdayStr = yesterdayDate.toISOString().split('T')[0];

  // If an exact yesterday exists use it; otherwise, use the day immediately before the last date.
  let compareDate = dailyCounts[yesterdayStr] !== undefined ? yesterdayStr : dates[dates.length - 2];

  const lastCount = dailyCounts[lastDate];
  const compareCount = dailyCounts[compareDate];

  if (lastCount === compareCount) return 'no change';
  return lastCount > compareCount ? 'up' : 'down';
};

// Calculate progress based on the number of visits over time (simplified for demo)
// (Progress here is computed by the timespan between the first and last visit in days, multiplied by 100)
const calculateProgress = (visits) => {
  if (visits.length === 0) return 0;
  const timeSpan = visits[visits.length - 1] - visits[0]; // Time span in milliseconds
  const progress = (timeSpan / (1000 * 60 * 60 * 24)) * 100; // Convert days to a percentage value
  return progress;
};

const getPdfTraffic = async (req, res) => {
  try {
    const { url, uuid } = req.body;

    // Input validation
    if (!url) {
      return res.status(400).json({ success: false, message: 'URL is required' });
    }
    if (!uuid) {
      return res.status(400).json({ success: false, message: 'UUID is required' });
    }

    // Validate the shortened URL
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ success: false, message: err.message });
    }

    const pdfId = url.split('/').pop();
    if (!pdfId) {
      return res.status(400).json({ success: false, message: 'Invalid URL format' });
    }

    // Fetch analytics
    const analyticsData = await Pdfanalytics.find({ pdfId });
    if (!analyticsData.length) {
      return res.status(404).json({ success: false, message: 'No analytics found' });
    }

    const visitIds = [...new Set(analyticsData.map(a => a.userVisit.toString()))];
    const visits = await UserVisit.find({ _id: { $in: visitIds } });
    if (!visits.length) {
      return res.status(404).json({ success: false, message: 'No visits found' });
    }

    // Global browser counter
    const globalBrowserCounts = {};

    // Country-level aggregation
    const countryAgg = visits.reduce((acc, v) => {
      const browser = v.browser?.trim() || 'Unknown';
      // tally global
      globalBrowserCounts[browser] = (globalBrowserCounts[browser] || 0) + 1;

      const locParts = v.location.split(',').map(s => s.trim());
      const country  = locParts.pop();
      const district = locParts.join(', ');
      const state    = v.region;

      if (!acc[country]) {
        acc[country] = {
          country,
          views: 0,
          visits: [],
          stateDistrictMap: {},
        };
      }
      const entry = acc[country];
      entry.views += 1;
      entry.visits.push(v.createdAt);

      if (state) {
        entry.stateDistrictMap[state] = entry.stateDistrictMap[state] || new Set();
        if (district) {
          entry.stateDistrictMap[state].add(district);
        }
      }

      return acc;
    }, {});

    // Build listViewData
    const listViewData = await Promise.all(
      Object.values(countryAgg).map(async item => {
        const coords   = await fetchCoordinates(item.country);
        const dailyAvg = calculateDailyAvg(item.visits);
        const change   = calculateChange(item.visits);
        const progress = calculateProgress(item.visits);

        // convert stateDistrictMap sets to arrays
        const stateDistrictObj = {};
        for (const [st, distSet] of Object.entries(item.stateDistrictMap)) {
          stateDistrictObj[st] = Array.from(distSet);
        }

        return {
          country:       item.country,
          dailyAvg:      `${dailyAvg}%`,
          change,
          views:         item.views.toString(),
          progress,
          coordinates:   coords,
          stateDistrict: stateDistrictObj,
        };
      })
    );

    return res.status(200).json({
      success: true,
      data: {
        listViewData,
        browsers: globalBrowserCounts,
      },
    });
  } catch (err) {
    console.error('Error fetching PDF traffic data:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

const getpowerpointTraffic = async (req, res) => {
  try {
    const { url, uuid } = req.body;

    // Input validation
    if (!url) {
      return res.status(400).json({ success: false, message: 'URL is required' });
    }
    if (!uuid) {
      return res.status(400).json({ success: false, message: 'UUID is required' });
    }

    // Validate the shortened URL
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ success: false, message: err.message });
    }

    const pdfId = url.split('/').pop();
    if (!pdfId) {
      return res.status(400).json({ success: false, message: 'Invalid URL format' });
    }

    // Fetch analytics
    const analyticsData = await PowerPointAnalytics.find({ pdfId });
    if (!analyticsData.length) {
      return res.status(404).json({ success: false, message: 'No analytics found' });
    }

    const visitIds = [...new Set(analyticsData.map(a => a.userVisit.toString()))];
    const visits = await UserVisit.find({ _id: { $in: visitIds } });
    if (!visits.length) {
      return res.status(404).json({ success: false, message: 'No visits found' });
    }

    // Global browser counter
    const globalBrowserCounts = {};

    // Country-level aggregation
    const countryAgg = visits.reduce((acc, v) => {
      const browser = v.browser?.trim() || 'Unknown';
      // tally global
      globalBrowserCounts[browser] = (globalBrowserCounts[browser] || 0) + 1;

      const locParts = v.location.split(',').map(s => s.trim());
      const country  = locParts.pop();
      const district = locParts.join(', ');
      const state    = v.region;

      if (!acc[country]) {
        acc[country] = {
          country,
          views: 0,
          visits: [],
          stateDistrictMap: {},
        };
      }
      const entry = acc[country];
      entry.views += 1;
      entry.visits.push(v.createdAt);

      if (state) {
        entry.stateDistrictMap[state] = entry.stateDistrictMap[state] || new Set();
        if (district) {
          entry.stateDistrictMap[state].add(district);
        }
      }

      return acc;
    }, {});

    // Build listViewData
    const listViewData = await Promise.all(
      Object.values(countryAgg).map(async item => {
        const coords   = await fetchCoordinates(item.country);
        const dailyAvg = calculateDailyAvg(item.visits);
        const change   = calculateChange(item.visits);
        const progress = calculateProgress(item.visits);

        // convert stateDistrictMap sets to arrays
        const stateDistrictObj = {};
        for (const [st, distSet] of Object.entries(item.stateDistrictMap)) {
          stateDistrictObj[st] = Array.from(distSet);
        }

        return {
          country:       item.country,
          dailyAvg:      `${dailyAvg}%`,
          change,
          views:         item.views.toString(),
          progress,
          coordinates:   coords,
          stateDistrict: stateDistrictObj,
        };
      })
    );

    return res.status(200).json({
      success: true,
      data: {
        listViewData,
        browsers: globalBrowserCounts,
      },
    });
  } catch (err) {
    console.error('Error fetching PDF traffic data:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};



const getdocxTraffic = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    if (!url) {
      return res.status(400).json({ success: false, message: "URL is required" });
    }
    if (!uuid) {
      return res.status(400).json({ success: false, message: "UUID is required" });
    }

    // Validate shortened URL
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ success: false, message: err.message });
    }

    // Extract docx ID from URL
    const docxId = url.split("/").pop();
    if (!docxId) {
      return res.status(400).json({ success: false, message: "Invalid URL format" });
    }

    // Fetch analytics data
    const analyticsData = await DocxAnalytics.find({ pdfId: docxId });
    if (!analyticsData.length) {
      return res.status(404).json({ success: false, message: "No analytics found" });
    }

    const visitIds = [...new Set(analyticsData.map(a => a.userVisit.toString()))];
    const visits = await UserVisit.find({ _id: { $in: visitIds } });
    if (!visits.length) {
      return res.status(404).json({ success: false, message: "No visits found" });
    }

    // Global browser counter
    const globalBrowserCounts = {};

    // Country‐level aggregation
    const countryAgg = visits.reduce((acc, v) => {
      const browser = v.browser?.trim() || "Unknown";
      globalBrowserCounts[browser] = (globalBrowserCounts[browser] || 0) + 1;

      const locParts = v.location.split(",").map(s => s.trim());
      const country = locParts.pop();
      const district = locParts.join(", ");
      const state = v.region;

      if (!acc[country]) {
        acc[country] = {
          country,
          views: 0,
          visits: [],
          stateDistrictMap: {},
        };
      }

      const entry = acc[country];
      entry.views += 1;
      entry.visits.push(v.createdAt);

      if (state) {
        if (!entry.stateDistrictMap[state]) {
          entry.stateDistrictMap[state] = new Set();
        }
        if (district) {
          entry.stateDistrictMap[state].add(district);
        }
      }

      return acc;
    }, {});

    // Build final listViewData
    const listViewData = await Promise.all(
      Object.values(countryAgg).map(async item => {
        const coords   = await fetchCoordinates(item.country);
        const dailyAvg = calculateDailyAvg(item.visits);
        const change   = calculateChange(item.visits);
        const progress = calculateProgress(item.visits);

        const stateDistrictObj = {};
        for (const [st, distSet] of Object.entries(item.stateDistrictMap)) {
          stateDistrictObj[st] = Array.from(distSet);
        }

        return {
          country:      item.country,
          dailyAvg:     `${dailyAvg}%`,
          change,
          views:        item.views.toString(),
          progress,
          coordinates:  coords,
          stateDistrict: stateDistrictObj,
        };
      })
    );

    return res.status(200).json({
      success: true,
      data: {
        listViewData,
        browsers: globalBrowserCounts,
      },
    });
  } catch (err) {
    console.error("Error fetching DOCX traffic data:", err);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};


const getTimeSpentByWeekpowerpoint = async (req, res) => {
  try {
    // Extract PDF ID from URL
    const { url, uuid } = req.body;
    const pdfId = url.split("/").pop();

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Get the last 7 days (including today)
    const startDate = moment().subtract(6, "days").startOf("day");
    const endDate = moment().endOf("day");

    // Fetch documents matching pdfId and createdAt range
    const records = await PowerPointAnalytics.find({
      pdfId: pdfId,
      createdAt: { $gte: startDate.toDate(), $lte: endDate.toDate() },
    });

    // Initialize an object for last 7 days with default time as 0
    const timeSpentPerDay = {};
    for (let i = 0; i < 7; i++) {
      const day = moment().subtract(6 - i, "days").format("ddd"); // Generate last 7 days
      timeSpentPerDay[day] = 0;
    }

    // Aggregate time spent from records
    records.forEach((record) => {
      const dayName = moment(record.createdAt).format("ddd"); // Get day name
      if (timeSpentPerDay.hasOwnProperty(dayName)) {
        timeSpentPerDay[dayName] += record.totalTimeSpent || 0;
      }
    });

    // Convert to response format (ensuring exactly 7 unique days)
    const response = Object.entries(timeSpentPerDay).map(([day, time]) => ({
      name: day,
      time: time,
    }));

    return res.json(response);
  } catch (error) {
    console.error("Error fetching time spent by week:", error);
    return res.status(500).json({ message: "Server error" });
  }
};



const getTimeSpentByWeek = async (req, res) => {
  try {
    // Extract PDF ID from URL
    const { url, uuid } = req.body;
    const pdfId = url.split("/").pop();

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Get the last 7 days (including today)
    const startDate = moment().subtract(6, "days").startOf("day");
    const endDate = moment().endOf("day");

    // Fetch documents matching pdfId and createdAt range
    const records = await Pdfanalytics.find({
      pdfId: pdfId,
      createdAt: { $gte: startDate.toDate(), $lte: endDate.toDate() },
    });

    // Initialize an object for last 7 days with default time as 0
    const timeSpentPerDay = {};
    for (let i = 0; i < 7; i++) {
      const day = moment().subtract(6 - i, "days").format("ddd"); // Generate last 7 days
      timeSpentPerDay[day] = 0;
    }

    // Aggregate time spent from records
    records.forEach((record) => {
      const dayName = moment(record.createdAt).format("ddd"); // Get day name
      if (timeSpentPerDay.hasOwnProperty(dayName)) {
        timeSpentPerDay[dayName] += record.totalTimeSpent || 0;
      }
    });

    // Convert to response format (ensuring exactly 7 unique days)
    const response = Object.entries(timeSpentPerDay).map(([day, time]) => ({
      name: day,
      time: time,
    }));

    return res.json(response);
  } catch (error) {
    console.error("Error fetching time spent by week:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

const getTimeSpentByWeekDocx = async (req, res) => {
  try {
    // Extract PDF ID from URL
    const { url, uuid } = req.body;
    const pdfId = url.split("/").pop();

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Get the last 7 days (including today)
    const startDate = moment().subtract(6, "days").startOf("day");
    const endDate = moment().endOf("day");

    // Fetch documents matching pdfId and createdAt range
    const records = await Docxanalytics.find({
      pdfId: pdfId,
      createdAt: { $gte: startDate.toDate(), $lte: endDate.toDate() },
    });

    // Initialize an object for last 7 days with default time as 0
    const timeSpentPerDay = {};
    for (let i = 0; i < 7; i++) {
      const day = moment().subtract(6 - i, "days").format("ddd"); // Generate last 7 days
      timeSpentPerDay[day] = 0;
    }

    // Aggregate time spent from records
    records.forEach((record) => {
      const dayName = moment(record.createdAt).format("ddd"); // Get day name
      if (timeSpentPerDay.hasOwnProperty(dayName)) {
        timeSpentPerDay[dayName] += record.totalTimeSpent || 0;
      }
    });

    // Convert to response format (ensuring exactly 7 unique days)
    const response = Object.entries(timeSpentPerDay).map(([day, time]) => ({
      name: day,
      time: time,
    }));

    return res.json(response);
  } catch (error) {
    console.error("Error fetching time spent by week:", error);
    return res.status(500).json({ message: "Server error" });
  }
};



const getDeviceAnalytics = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    const pdfId = url.split("/").pop();

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    if (!pdfId) {
      return res.status(400).json({ message: "PDF ID is required" });
    }

    // Option 1: Direct query using documentId (most efficient)
    const devices = await UserVisit.find({ documentId: pdfId });

    if (!devices.length) {
      return res.status(404).json({ message: "No device data found for this PDF ID" });
    }

    // Count the number of devices per OS
    const osCount = {};
    devices.forEach((device) => {
      osCount[device.os] = (osCount[device.os] || 0) + 1;
    });

    // Convert OS data into required format
    const osData = Object.keys(osCount).map((os) => ({
      name: os,
      value: osCount[os],
    }));

    return res.status(200).json({
      totalDevices: devices.length,
      osData,
    });
  } catch (error) {
    console.error("Error fetching device analytics:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

const getDeviceAnalyticsPowerpoint = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    const pdfId = url.split("/").pop();

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    if (!pdfId) {
      return res.status(400).json({ message: "PDF ID is required" });
    }

    // Option 1: Direct query using documentId (most efficient)
    const devices = await UserVisit.find({ documentId: pdfId });

    if (!devices.length) {
      return res.status(404).json({ message: "No device data found for this PDF ID" });
    }

    // Count the number of devices per OS
    const osCount = {};
    devices.forEach((device) => {
      osCount[device.os] = (osCount[device.os] || 0) + 1;
    });

    // Convert OS data into required format
    const osData = Object.keys(osCount).map((os) => ({
      name: os,
      value: osCount[os],
    }));

    return res.status(200).json({
      totalDevices: devices.length,
      osData,
    });
  } catch (error) {
    console.error("Error fetching device analytics:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

const getDeviceAnalyticsdocx = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    const docxId = url.split("/").pop(); // Changed variable name to be more semantic

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    if (!docxId) {
      return res.status(400).json({ message: "Document ID is required" });
    }

    // Option 1: Direct query using documentId (most efficient)
    const devices = await UserVisit.find({ documentId: docxId });

    console.log(devices, "devices found for docx");

    if (!devices.length) {
      return res.status(404).json({ message: "No device data found for this Document ID" });
    }

    // Count the number of devices per OS
    const osCount = {};
    devices.forEach((device) => {
      osCount[device.os] = (osCount[device.os] || 0) + 1;
    });

    // Convert OS data into required format
    const osData = Object.keys(osCount).map((os) => ({
      name: os,
      value: osCount[os],
    }));

    return res.status(200).json({
      totalDevices: devices.length,
      osData,
    });
  } catch (error) {
    console.error("Error fetching device analytics:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};


const getVideoAnalytics = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    if (!url) return res.status(400).json({ message: "URL is required." });

    // Extract videoId from URL
    const videoId = url.split("/").pop();


    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }
    if (!videoId)
      return res.status(400).json({ message: "Video ID is required." });

    // Fetch all analytics data for the given videoId
    const videoAnalytics = await VideoAnalytics.find({ videoId });
    // If no analytics data exists, return dummy data
    if (!videoAnalytics || videoAnalytics.length === 0) {
      return res.json({
        totalTimeSpent: 0,
        playCount: 0,
        pauseCount: 0,
        seekCount: 0,
        averageWatchTime: 0,
        userCounts: { newuser: { video: 0 }, returneduser: { video: 0 } },
        totalsession: 0,
        bounceRate: 0,
        durationAnalytics: [],
      });
    }

    // ============================
    // Part 1: Overall Video Metrics
    // ============================


    let totalWatchTime = 0,
      playCount = 0,
      pauseCount = 0,
      seekCount = 0,
      totalSessions = videoAnalytics.length,
      bounceSessions = 0;

    videoAnalytics.forEach((video) => {
      totalWatchTime += video.totalWatchTime;
      playCount += video.playCount;
      pauseCount += video.pauseCount;
      seekCount += video.seekCount;
      // Bounce session logic: Adjust as needed
      if (video.playCount === 1 && video.totalWatchTime > 10) {
        bounceSessions++;
      }
    });

    let averageWatchTime = totalSessions > 0 ? totalWatchTime / totalSessions : 0;
    let bounceRate = totalSessions > 0 ? (bounceSessions / totalSessions) * 100 : 0;

    // Fetch user counts (new and returned) using videoId
    const newUsers = await newUser.find({ documentId: videoId, "count.video": { $gt: 0 } });
    let newUserVideoCount = newUsers.reduce((sum, user) => sum + user.count.video, 0);

    const returnedUsers = await ReturnedUser.find({ documentId: videoId, "count.video": { $gt: 0 } });
    let returnedUserVideoCount = returnedUsers.reduce((sum, user) => sum + user.count.video, 0);

    // ============================
    // Part 2: Duration Range Analytics
    // ============================
    // Initialize a mapping to store views and unique users for each duration range
    let durationViewsMap = {};

    videoAnalytics.forEach((data) => {
      // Process skip events (forward/backward)
      data.skipEvents.forEach((event) => {
        const from = Math.round(event.from);
        const to = Math.round(event.to);
        const start = Math.min(from, to);
        const end = Math.max(from, to);
        if (start === end) return; // ignore single point ranges

        const durationRange = `${start} to ${end}`;
        if (!durationViewsMap[durationRange]) {
          durationViewsMap[durationRange] = { views: 0, users: new Set() };
        }
        durationViewsMap[durationRange].views += 1;
        durationViewsMap[durationRange].users.add(data.userVisit.toString());
      });

      // Process jump events (e.g., replays)
      data.jumpEvents.forEach((event) => {
        const from = Math.round(event.from);
        const to = Math.round(event.to);
        const start = Math.min(from, to);
        const end = Math.max(from, to);
        if (start === end) return;

        const jumpRange = `${start} to ${end}`;
        if (!durationViewsMap[jumpRange]) {
          durationViewsMap[jumpRange] = { views: 0, users: new Set() };
        }
        durationViewsMap[jumpRange].views += 1;
        durationViewsMap[jumpRange].users.add(data.userVisit.toString());
      });
    });

    // Prepare a list from the mapping
    const finalDurationList = Object.keys(durationViewsMap).map((range) => {
      const segment = durationViewsMap[range];
      return {
        durationRange: range,
        views: segment.views,
        usersCount: segment.users.size,
      };
    });

    // Merge similar (overlapping or adjacent) ranges
    let mergedDurationList = [];
    finalDurationList.forEach((item) => {
      let found = false;
      mergedDurationList = mergedDurationList.map((existingItem) => {
        const [existingStart, existingEnd] = existingItem.durationRange
          .split(" to ")
          .map(Number);
        const [newStart, newEnd] = item.durationRange.split(" to ").map(Number);

        // If ranges are overlapping or adjacent, merge them
        if (
          (existingStart <= newStart && existingEnd >= newStart) ||
          (existingStart <= newEnd && existingEnd >= newEnd)
        ) {
          existingItem.views += item.views;
          existingItem.usersCount += item.usersCount;
          found = true;
        }
        return existingItem;
      });
      if (!found) {
        mergedDurationList.push({ ...item });
      }
    });

    // Sort by views (ascending) and then by usersCount (descending)
    mergedDurationList.sort((a, b) => {
      if (a.views === b.views) {
        return b.usersCount - a.usersCount;
      }
      return a.views - b.views;
    });

    // Filter out any ranges with less than 1 view (if necessary)
    const filteredDurationList = mergedDurationList.filter((item) => item.views >= 1);

    // ============================
    // Part 3: Prepare Final Response
    // ============================
    // Fetch the original URL for the video using the shortened URL model
    const shortenedUrl = await ShortenedUrl.findOne({ shortId: videoId });
    if (!shortenedUrl) {
      return res
        .status(404)
        .json({ message: "No original URL found for this video ID" });
    }

    const responseData = {
      totalTimeSpent: totalWatchTime,
      playCount,
      pauseCount,
      seekCount,
      averageWatchTime,
      userCounts: {
        newuser: { video: newUserVideoCount },
        returneduser: { video: (returnedUserVideoCount - newUserVideoCount) },
      },
      totalsession: totalSessions,
      bounceRate,
      durationAnalytics: filteredDurationList, // merged & sorted duration ranges
      Videosourceurl: shortenedUrl.originalUrl,
    };

    return res.json(responseData);
  } catch (error) {
    console.error("Error processing video metrics:", error);
    return res.status(500).json({
      message: "An error occurred while processing the video metrics",
      error: error.message,
    });
  }
};




const getUserActivitiesByVideoId = async (req, res) => {
  try {
    // Extract the pdfId from the URL in the request body
    const pdfIdFromUrl = req.body.url.split("/").pop();
    const { dateRange } = req.body; // Get the date range from the request body
    const uuid = req.body.uuid;


    try {
      await validateShortenedUrl(uuid, pdfIdFromUrl);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Set date filters based on the provided date range
    let matchDateFilter = {};
    const today = moment().startOf("day");

    switch (dateRange) {
      case "today":
        matchDateFilter = { createdAt: { $gte: today.toDate() } };
        break;
      case "yesterday":
        matchDateFilter = {
          createdAt: {
            $gte: moment().subtract(1, "days").startOf("day").toDate(),
            $lt: moment().subtract(1, "days").endOf("day").toDate(),
          },
        };
        break;
      case "lastWeek":
        matchDateFilter = {
          createdAt: {
            $gte: moment().subtract(1, "weeks").startOf("week").toDate(),
            $lte: moment().subtract(1, "weeks").endOf("week").toDate(),
          },
        };
        break;
      case "lastMonth":
        matchDateFilter = {
          createdAt: {
            $gte: moment().subtract(1, "months").startOf("month").toDate(),
            $lte: moment().subtract(1, "months").endOf("month").toDate(),
          },
        };
        break;
      default:
        matchDateFilter = {}; // Fetch all records if no range is provided
    }

    // Aggregation pipeline for fetching user activities
    const aggregatePipeline = [
      { $match: { videoId: pdfIdFromUrl, ...matchDateFilter } },
      {
        $project: {
          date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          hour: { $hour: "$createdAt" },
        },
      },
      {
        $project: {
          date: 1,
          timeRange: {
            $cond: {
              if: { $lt: ["$hour", 12] },
              then: "00:00-12:00",
              else: "12:00-24:00",
            },
          },
        },
      },
      {
        $group: {
          _id: { date: "$date", timeRange: "$timeRange" },
          userCount: { $sum: 1 },
        },
      },
      { $sort: { "_id.date": 1, "_id.timeRange": 1 } },
    ];

    const userActivities = await VideoAnalytics.aggregate(aggregatePipeline);

    let response = [];

    if (userActivities.length > 0) {
      response = userActivities.map((item) => ({
        date: item._id.date,
        timeRange: item._id.timeRange,
        users: item.userCount,
      }));
    } else {
      // If no data, return today's date with 0 users
      response = [
        {
          date: moment().format("YYYY-MM-DD"),
          timeRange: "00:00-12:00",
          users: 0,
        },
        {
          date: moment().format("YYYY-MM-DD"),
          timeRange: "12:00-24:00",
          users: 0,
        },
      ];
    }

    return res.status(200).json({
      success: true,
      data: response,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Server error, unable to fetch user activities",
    });
  }
};



const getVideoTraffic = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    if (!url) {
      return res
        .status(400)
        .json({ success: false, message: "URL is required" });
    }
    if (!uuid) {
      return res
        .status(400)
        .json({ success: false, message: "UUID is required" });
    }

    // 1) Short link validation
    try {
      await validateShortenedUrl(uuid, url);
    } catch (err) {
      return res.status(401).json({ success: false, message: err.message });
    }

    // 2) Extract videoId
    const videoId = url.split("/").pop();
    if (!videoId) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid URL format" });
    }

    // 3) Fetch analytics
    const analyticsData = await VideoAnalytics.find({ videoId });
    if (!analyticsData.length) {
      return res
        .status(404)
        .json({ success: false, message: "No analytics found" });
    }

    // 4) Resolve UserVisit records
    const visitIds = [
      ...new Set(analyticsData.map((a) => a.userVisit.toString())),
    ];
    const visits = await UserVisit.find({ _id: { $in: visitIds } });
    if (!visits.length) {
      return res
        .status(404)
        .json({ success: false, message: "No visits found" });
    }

    // 5) Build global browser counts
    const globalBrowserCounts = {};
    visits.forEach((v) => {
      const browser = v.browser?.trim() || "Unknown";
      globalBrowserCounts[browser] =
        (globalBrowserCounts[browser] || 0) + 1;
    });

    // 6) Country‐level aggregation
    const countryAgg = visits.reduce((acc, v) => {
      const parts = v.location.split(",").map((s) => s.trim());
      const country = parts.pop();
      const district = parts.join(", ");
      const state = v.region;

      if (!acc[country]) {
        acc[country] = {
          country,
          views: 0,
          visits: [],
          stateDistrictMap: {},
        };
      }
      const entry = acc[country];
      entry.views += 1;
      entry.visits.push(v.createdAt);

      if (state) {
        entry.stateDistrictMap[state] =
          entry.stateDistrictMap[state] || new Set();
        if (district) {
          entry.stateDistrictMap[state].add(district);
        }
      }
      return acc;
    }, {});

    // 7) Build listViewData
    const listViewData = await Promise.all(
      Object.values(countryAgg).map(async (item) => {
        const coords = await fetchCoordinates(item.country);
        const dailyAvg = calculateDailyAvg(item.visits);
        const change = calculateChange(item.visits);
        const progress = calculateProgress(item.visits);

        // Convert Set → Array
        const stateDistrictObj = {};
        for (const [st, distSet] of Object.entries(
          item.stateDistrictMap
        )) {
          stateDistrictObj[st] = Array.from(distSet);
        }

        return {
          country: item.country,
          dailyAvg: `${dailyAvg}%`,
          change,
          views: item.views.toString(),
          progress,
          coordinates: coords,
          stateDistrict: stateDistrictObj,
        };
      })
    );

    // 8) Respond with both data & browser summary
    return res.status(200).json({
      success: true,
      data: {
        listViewData,
        browsers: globalBrowserCounts,
      },
    });
  } catch (error) {
    console.error("Error fetching video traffic data:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};




const getWebTraffic = async (req, res) => {
  try {
    const { url, uuid } = req.body;

    // Input validation
    if (!url) {
      return res.status(400).json({ success: false, message: 'URL is required' });
    }
    if (!uuid) {
      return res.status(400).json({ success: false, message: 'UUID is required' });
    }

    // Validate the shortened URL
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ success: false, message: err.message });
    }

    const webId = url.split('/').pop();
    if (!webId) {
      return res.status(400).json({ success: false, message: 'Invalid URL format' });
    }

    // Fetch analytics
    const analyticsData = await Webanalytics.find({ webId });
    if (!analyticsData.length) {
      return res.status(404).json({ success: false, message: 'No analytics found' });
    }

    const visitIds = [...new Set(analyticsData.map(a => a.userVisit.toString()))];
    const visits = await UserVisit.find({ _id: { $in: visitIds } });
    if (!visits.length) {
      return res.status(404).json({ success: false, message: 'No visits found' });
    }

    // Global browser counter
    const globalBrowserCounts = {};

    // Country-level aggregation
    const countryAgg = visits.reduce((acc, v) => {
      const browser = v.browser?.trim() || 'Unknown';

      // Add to global browser stats
      globalBrowserCounts[browser] = (globalBrowserCounts[browser] || 0) + 1;

      const locParts = v.location.split(',').map(s => s.trim());
      const country = locParts.pop();
      const district = locParts.join(', ');
      const state = v.region;

      if (!acc[country]) {
        acc[country] = {
          country,
          views: 0,
          visits: [],
          stateDistrictMap: {},
        };
      }

      const entry = acc[country];
      entry.views += 1;
      entry.visits.push(v.createdAt);

      // State → Districts
      if (state) {
        if (!entry.stateDistrictMap[state]) {
          entry.stateDistrictMap[state] = new Set();
        }
        if (district) {
          entry.stateDistrictMap[state].add(district);
        }
      }

      return acc;
    }, {});

    // Convert countryAgg to listViewData
    const listViewData = await Promise.all(
      Object.values(countryAgg).map(async item => {
        const coords = await fetchCoordinates(item.country);
        const dailyAvg = calculateDailyAvg(item.visits);
        const change = calculateChange(item.visits);
        const progress = calculateProgress(item.visits);

        const stateDistrictObj = {};
        for (const [state, distSet] of Object.entries(item.stateDistrictMap)) {
          stateDistrictObj[state] = Array.from(distSet);
        }

        return {
          country: item.country,
          dailyAvg: `${dailyAvg}%`,
          change,
          views: item.views.toString(),
          progress,
          coordinates: coords,
          stateDistrict: stateDistrictObj,
        };
      })
    );

    return res.status(200).json({
      success: true,
      data: {
        listViewData,
        browsers: globalBrowserCounts,
      },
    });

  } catch (err) {
    console.error('Error fetching web traffic data:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};





const getTimeSpentByWeekVideo = async (req, res) => {
  try {
    // Extract PDF ID from URL
    const { url, uuid } = req.body;
    const videoId = url.split("/").pop();
    console.log(videoId, "videoid")


    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }



    // Get the last 7 days (including today)
    const startDate = moment().subtract(6, "days").startOf("day");
    const endDate = moment().endOf("day");

    // Fetch documents matching pdfId and createdAt range
    const records = await VideoAnalytics.find({
      videoId: videoId,
      createdAt: { $gte: startDate.toDate(), $lte: endDate.toDate() },
    });

    console.log(records, 'records')

    // Initialize an object for last 7 days with default time as 0
    const timeSpentPerDay = {};
    for (let i = 0; i < 7; i++) {
      const day = moment().subtract(6 - i, "days").format("ddd"); // Generate last 7 days
      timeSpentPerDay[day] = 0;
    }

    console.log(timeSpentPerDay, "Initialized timeSpentPerDay");

    // Aggregate time spent from records
    records.forEach((record) => {
      const dayName = moment(record.createdAt).format("ddd"); // Get day name
      if (timeSpentPerDay.hasOwnProperty(dayName)) {
        timeSpentPerDay[dayName] += record.totalWatchTime || 0; // Use totalWatchTime instead of totalTimeSpent
      }
    });

    // Convert to response format (ensuring exactly 7 unique days)
    const response = Object.entries(timeSpentPerDay).map(([day, time]) => ({
      name: day,
      time: time,
    }));

    return res.json(response);
  } catch (error) {
    console.error("Error fetching time spent by week:", error);
    return res.status(500).json({ message: "Server error" });
  }
};


const getTimeSpentByWeekWeb = async (req, res) => {
  try {
    // Extract webId from URL
    const { url } = req.body;
    const webId = url.split("/").pop();

    const uuid = req.body.uuid;

    if (!webId) {
      return res.status(400).json({ message: "webId is required" });
    }
    if (!uuid) {
      return res.status(400).json({ message: "UUID is required" });
    }
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    console.log(webId, "webId");

    // Get the last 7 days (including today)
    const startDate = moment().subtract(6, "days").startOf("day");
    const endDate = moment().endOf("day");

    // Fetch documents matching webId and createdAt range
    const records = await Webanalytics.find({
      webId: webId,
      createdAt: { $gte: startDate.toDate(), $lte: endDate.toDate() },
    });

    console.log(records, 'records');

    // Initialize an object for last 7 days with default time as 0
    const timeSpentPerDay = {};
    for (let i = 0; i < 7; i++) {
      const day = moment().subtract(6 - i, "days").format("ddd"); // Generate last 7 days
      timeSpentPerDay[day] = 0;
    }

    console.log(timeSpentPerDay, "Initialized timeSpentPerDay");

    // Aggregate time spent from records
    records.forEach((record) => {
      const dayName = moment(record.createdAt).format("ddd"); // Get day name
      if (timeSpentPerDay.hasOwnProperty(dayName)) {
        timeSpentPerDay[dayName] += record.totalTimeSpent || 0; // Use totalTimeSpent
      }
    });

    // Convert to response format (ensuring exactly 7 unique days)
    const response = Object.entries(timeSpentPerDay).map(([day, time]) => ({
      name: day,
      time: time,
    }));

    return res.json(response);
  } catch (error) {
    console.error("Error fetching time spent by week:", error);
    return res.status(500).json({ message: "Server error" });
  }
};



const getDeviceAnalyticsVideo = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    const videoId = url.split("/").pop();

    if (!videoId) {
      return res.status(400).json({ message: "Video ID is required" });
    }

    if (!uuid) {
      return res.status(400).json({ message: "UUID is required" });
    }

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Option 1: Direct query using documentId (most efficient)
    const devices = await UserVisit.find({ documentId: videoId });

    console.log(devices, "devices found for video");

    if (!devices.length) {
      return res.status(404).json({ message: "No device data found for this Video ID" });
    }

    // Count the number of devices per OS
    const osCount = {};
    devices.forEach((device) => {
      osCount[device.os] = (osCount[device.os] || 0) + 1;
    });

    // Convert OS data into required format
    const osData = Object.keys(osCount).map((os) => ({
      name: os,
      value: osCount[os],
    }));

    return res.status(200).json({
      totalDevices: devices.length,
      osData,
    });
  } catch (error) {
    console.error("Error fetching device analytics:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};


const getPdfviewanalytics = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    if (!url)
      return res.status(400).json({ message: "URL is required." });

    if (!uuid)
      return res.status(400).json({ message: "UUID is required." });

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    const pdfId = url.split("/").pop();

    // Fetch URL details from ShortenedUrl collection
    const urlData = await ShortenedUrl.findOne({ shortId: pdfId }).lean();
    if (!urlData) {
      return res
        .status(404)
        .json({ message: "No URL data found for this shortId." });
    }

    const { totalPages } = urlData; // Extract total pages

    // Fetch all analytics for the given pdfId
    const analyticsData = await Pdfanalytics.find({ pdfId }).lean();
    if (!analyticsData.length) {
      return res
        .status(404)
        .json({ message: "No analytics data found for this PDF." });
    }

    // Calculate total time spent per page
    const totalPageTime = {};
    let totalTimeSpent = 0; // Total time spent across all users
    let totalUsers = analyticsData.length; // Total number of users who viewed the PDF


    analyticsData.forEach((doc) => {
      totalTimeSpent += doc.totalTimeSpent; // Sum total time spent
      Object.entries(doc.pageTimeSpent || {}).forEach(([page, time]) => {
        totalPageTime[page] = (totalPageTime[page] || 0) + time;
      });
    });

    // Convert totalTimeSpent (in seconds) to hours, minutes, and seconds
    const totalTimeInMinutes = totalTimeSpent / 60;
    const totalTimeInHours = totalTimeInMinutes / 60;
    const remainingMinutes = Math.floor(totalTimeInMinutes % 60);
    const remainingSeconds = Math.floor(totalTimeSpent % 60);

    const totalTimeReadable = {
      hours: Math.floor(totalTimeInHours),
      minutes: remainingMinutes,
      seconds: remainingSeconds,
    };

    // Calculate average time spent per user (in seconds)
    const averageTimeSpent = totalTimeSpent / totalUsers;
    const averageTimeInMinutes = averageTimeSpent / 60;
    const averageTimeInHours = averageTimeInMinutes / 60;
    const avgRemainingMinutes = Math.floor(averageTimeInMinutes % 60);
    const avgRemainingSeconds = Math.floor(averageTimeSpent % 60);

    const averageTimeReadable = {
      hours: Math.floor(averageTimeInHours),
      minutes: avgRemainingMinutes,
      seconds: avgRemainingSeconds,
    };

    // Select only the **top 7 pages** based on the most time spent
    const topPages = Object.entries(totalPageTime)
      .sort((a, b) => b[1] - a[1]) // Sort pages by time spent in descending order
      .slice(0, 7) // Take only the top 7 pages
      .map(([page]) => parseInt(page)); // Extract page numbers

    // Track most selected text dynamically but only for the top 7 pages
    const textCountMap = new Map();
    analyticsData.forEach((doc) => {
      doc.selectedTexts.forEach(({ selectedText, count, page }) => {
        if (!topPages.includes(page)) return; // Skip pages not in top 7

        const key = `${selectedText}|||${page}`; // Unique key (text + page)
        if (!textCountMap.has(key)) {
          textCountMap.set(key, { selectedText, count, page });
        } else {
          textCountMap.get(key).count += count;
        }
      });
    });

    // Convert to sorted array based on most selected text with count > 3
    const mostSelectedTexts = Array.from(textCountMap.values())
      .filter(item => item.count > 3)
      .sort((a, b) => b.count - a.count || a.page - b.page);

    // ------------------------------------------------------------
    // Aggregate clicked links similarly to selected texts
    // ------------------------------------------------------------
    const linkClickMap = new Map();
    const keywordCountMap = new Map(); //keyword map
    analyticsData.forEach((doc) => {
      (doc.linkClicks || []).forEach(({ page, clickedLink }) => {
        // Only consider pages within the topPages if needed
        // If you want to filter clicks similarly, uncomment the following line:
        // if (!topPages.includes(page)) return;

        const key = `${clickedLink}|||${page}`;
        if (!linkClickMap.has(key)) {
          linkClickMap.set(key, { clickedLink, count: 1, page });
        } else {
          linkClickMap.get(key).count += 1;
        }
      });
    });

    // Convert the link click map to an array and sort it by count (and page)
    const mostClickedLinks = Array.from(linkClickMap.values()).sort(
      (a, b) => b.count - a.count || a.page - b.page
    );

    analyticsData.forEach((doc) => {
  (doc.searchKeywords || []).forEach((keyword) => {
    const lowerKeyword = keyword.toLowerCase(); // Normalize for case-insensitive match
    if (!keywordCountMap.has(lowerKeyword)) {
      keywordCountMap.set(lowerKeyword, 1);
    } else {
      keywordCountMap.set(lowerKeyword, keywordCountMap.get(lowerKeyword) + 1);
    }
  });
});

// Convert to array of objects: [{ keyword: "test", count: 10 }, ...]
const searchedKeywords = Array.from(keywordCountMap.entries())
  .map(([keyword, count]) => ({ keyword, count }))
  .sort((a, b) => b.count - a.count); // Sort by count descending


    // ------------------------------------------------------------
    // Return aggregated analytics with new clickedLinks field.
    // ------------------------------------------------------------
    res.json({
      totalPageTime,
      mostSelectedTexts,      // Most selected texts (only with count > 3)
      mostClickedLinks,       // Newly aggregated clicked links with page and count
      searchedKeywords,      //keywords searched
      totalPages,
      topPages,               // Top 7 pages
      totalTimeReadable,      // Total time spent in readable format
      averageTimeReadable,    // Average time spent per user in readable format
    });
  } catch (error) {
    console.error("Error fetching analytics data:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

const getDeviceAnalyticsWeb = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    const webId = url.split("/").pop();

    if (!webId) {
      return res.status(400).json({ message: "Web ID is required" });
    }

    if (!uuid) {
      return res.status(400).json({ message: "UUID is required" });
    }

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Option 1: Direct query using documentId (most efficient)
    const devices = await UserVisit.find({ documentId: webId });

    console.log(devices, "devices found for web");

    if (!devices.length) {
      return res.status(404).json({ message: "No device data found for this Web ID" });
    }

    // Count the number of devices per OS
    const osCount = {};
    devices.forEach((device) => {
      osCount[device.os] = (osCount[device.os] || 0) + 1;
    });

    // Convert OS data into required format
    const osData = Object.keys(osCount).map((os) => ({
      name: os,
      value: osCount[os],
    }));

    return res.status(200).json({
      totalDevices: devices.length,
      osData,
    });
  } catch (error) {
    console.error("Error fetching device analytics:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};



const getDocxviewanalytics = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    if (!url) {
      return res.status(400).json({ message: "URL is required." });
    }

    if (!uuid) {
      return res.status(400).json({ message: "UUID is required." });
    }
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    const pdfId = url.split("/").pop();
    console.log("pdfId extracted from URL:", pdfId);

    // Fetch URL details from ShortenedUrl collection
    const urlData = await ShortenedUrl.findOne({ shortId: pdfId }).lean();
    if (!urlData) {
      return res.status(404).json({ message: "No URL data found for this shortId." });
    }

    console.log("URL Data found:", urlData);

    const { totalPages } = urlData; // Extract total pages
    console.log("Total Pages in the document:", totalPages);

    // Fetch all analytics for the given pdfId
    const analyticsData = await Docxanalytics.find({ pdfId }).lean();
    if (!analyticsData.length) {
      return res.status(404).json({ message: "No analytics data found for this PDF." });
    }

    console.log("Analytics Data:", analyticsData);

    // Calculate total time spent per page and other metrics
    const totalPageTime = {};
    let totalTimeSpent = 0; // Variable to store total time spent across all users
    let totalUsers = analyticsData.length; // Total number of users who viewed the PDF

    analyticsData.forEach((doc, index) => {
      console.log(`Processing analytics for user ${index + 1}`);
      totalTimeSpent += doc.totalTimeSpent; // Sum up all the time spent
      console.log(`Total Time Spent by user ${index + 1}: ${doc.totalTimeSpent}`);

      // Process pageTimeSpent data
      Object.entries(doc.pageTimeSpent || {}).forEach(([page, time]) => {
        totalPageTime[page] = (totalPageTime[page] || 0) + time;
        console.log(`Added time for page ${page}: ${time}`);
      });
    });

    console.log("Total Time Spent Across All Users:", totalTimeSpent);
    console.log("Total Time Spent per Page:", totalPageTime);

    // Convert totalTimeSpent (in seconds) to hours, minutes, and seconds
    const totalTimeInMinutes = totalTimeSpent / 60;
    const totalTimeInHours = totalTimeInMinutes / 60;
    const remainingMinutes = Math.floor(totalTimeInMinutes % 60);
    const remainingSeconds = Math.floor(totalTimeSpent % 60);

    const totalTimeReadable = {
      hours: Math.floor(totalTimeInHours),
      minutes: remainingMinutes,
      seconds: remainingSeconds,
    };
    console.log("Total Time Readable:", totalTimeReadable);

    // Calculate average time spent per user (in seconds)
    const averageTimeSpent = totalTimeSpent / totalUsers;
    const averageTimeInMinutes = averageTimeSpent / 60;
    const averageTimeInHours = averageTimeInMinutes / 60;
    const avgRemainingMinutes = Math.floor(averageTimeInMinutes % 60);
    const avgRemainingSeconds = Math.floor(averageTimeSpent % 60);

    const averageTimeReadable = {
      hours: Math.floor(averageTimeInHours),
      minutes: avgRemainingMinutes,
      seconds: avgRemainingSeconds,
    };
    console.log("Average Time Readable:", averageTimeReadable);

    // Select only the **top 7 pages** based on the most time spent
    const topPages = Object.entries(totalPageTime)
      .sort((a, b) => b[1] - a[1]) // Sort pages by time spent (descending)
      .slice(0, 7) // Take only the top 7 pages
      .map(([page]) => parseInt(page)); // Extract page numbers
    console.log("Top 7 Pages by Time Spent:", topPages);

    // Track most selected text dynamically but only for the top 7 pages
    const textCountMap = new Map();
    analyticsData.forEach((doc, index) => {
      console.log(`Processing selected texts for user ${index + 1}`);
      doc.selectedTexts.forEach((selectedTextObj) => {
        console.log(`Selected Text Object:`, selectedTextObj); // Log the entire selected text object

        const { selectedText, count, page } = selectedTextObj;
        console.log(`User ${index + 1} selected text "${selectedText}" on page ${page} with count ${count}`);

        // If the page is in the top pages, we process it
        if (!topPages.includes(page)) {
          console.log(`Skipping page ${page} as it's not in the top pages.`);
          return; // Skip pages not in top 7
        }

        const key = `${selectedText}|||${page}`; // Unique key (text + page)
        if (!textCountMap.has(key)) {
          textCountMap.set(key, { selectedText, count, page });
        } else {
          textCountMap.get(key).count += count;
        }
      });
    });

    console.log("Text Count Map After Processing Selected Texts:", textCountMap);

    // Convert to sorted array based on most selected text and filter for counts > 3
    const mostSelectedTexts = Array.from(textCountMap.values())
      .filter(item => item.count > 3) // Only include texts with count > 3
      .sort((a, b) => b.count - a.count || a.page - b.page); // Sort by count, then page

    console.log("Most Selected Texts (Filtered and Sorted):", mostSelectedTexts);

    // Respond with the calculated analytics data
    res.json({
      totalPageTime,
      mostSelectedTexts, // Only most selected texts with count > 3
      totalPages,
      topPages, // Send back the top 7 pages calculated
      totalTimeReadable, // Return total time spent in readable format
      averageTimeReadable, // Return average time spent per user in readable format
    });
  } catch (error) {
    console.error("Error fetching analytics data:", error);
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
};

const getpowerpointanalytics = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    if (!url) {
      return res.status(400).json({ message: "URL is required." });
    }

    if (!uuid) {
      return res.status(400).json({ message: "UUID is required." });
    }
    
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    const pdfId = url.split("/").pop();
    console.log("pdfId extracted from URL:", pdfId);

    // Fetch URL details from ShortenedUrl collection
    const urlData = await ShortenedUrl.findOne({ shortId: pdfId }).lean();
    if (!urlData) {
      return res.status(404).json({ message: "No URL data found for this shortId." });
    }

    console.log("URL Data found:", urlData);

    const { totalPages } = urlData; // Extract total pages
    console.log("Total Pages in the document:", totalPages);

    // Fetch all analytics for the given pdfId
    const analyticsData = await PowerPointAnalytics.find({ pdfId }).lean();
    if (!analyticsData.length) {
      return res.status(404).json({ message: "No analytics data found for this PDF." });
    }

    console.log("Analytics Data:", analyticsData);

    // Calculate total time spent per page and other metrics
    const totalPageTime = {};
    let totalTimeSpent = 0; // Variable to store total time spent across all users
    let totalUsers = analyticsData.length; // Total number of users who viewed the PDF

    analyticsData.forEach((doc, index) => {
      console.log(`Processing analytics for user ${index + 1}`);
      totalTimeSpent += doc.totalTimeSpent; // Sum up all the time spent
      console.log(`Total Time Spent by user ${index + 1}: ${doc.totalTimeSpent}`);

      // Process pageTimeSpent data
      Object.entries(doc.pageTimeSpent || {}).forEach(([page, time]) => {
        totalPageTime[page] = (totalPageTime[page] || 0) + time;
        console.log(`Added time for page ${page}: ${time}`);
      });
    });

    console.log("Total Time Spent Across All Users:", totalTimeSpent);
    console.log("Total Time Spent per Page:", totalPageTime);

    // Convert totalTimeSpent (in seconds) to hours, minutes, and seconds
    const totalTimeInMinutes = totalTimeSpent / 60;
    const totalTimeInHours = totalTimeInMinutes / 60;
    const remainingMinutes = Math.floor(totalTimeInMinutes % 60);
    const remainingSeconds = Math.floor(totalTimeSpent % 60);

    const totalTimeReadable = {
      hours: Math.floor(totalTimeInHours),
      minutes: remainingMinutes,
      seconds: remainingSeconds,
    };
    console.log("Total Time Readable:", totalTimeReadable);

    // Calculate average time spent per user (in seconds)
    const averageTimeSpent = totalTimeSpent / totalUsers;
    const averageTimeInMinutes = averageTimeSpent / 60;
    const averageTimeInHours = averageTimeInMinutes / 60;
    const avgRemainingMinutes = Math.floor(averageTimeInMinutes % 60);
    const avgRemainingSeconds = Math.floor(averageTimeSpent % 60);

    const averageTimeReadable = {
      hours: Math.floor(averageTimeInHours),
      minutes: avgRemainingMinutes,
      seconds: avgRemainingSeconds,
    };
    console.log("Average Time Readable:", averageTimeReadable);

    // Select only the **top 7 pages** based on the most time spent
    const topPages = Object.entries(totalPageTime)
      .sort((a, b) => b[1] - a[1]) // Sort pages by time spent (descending)
      .slice(0, 7) // Take only the top 7 pages
      .map(([page]) => parseInt(page)); // Extract page numbers
    console.log("Top 7 Pages by Time Spent:", topPages);

    // Track most selected text dynamically but only for the top 7 pages
    const textCountMap = new Map();
    analyticsData.forEach((doc, index) => {
      console.log(`Processing selected texts for user ${index + 1}`);
      doc.selectedTexts.forEach((selectedTextObj) => {
        console.log(`Selected Text Object:`, selectedTextObj); // Log the entire selected text object

        const { selectedText, count, page } = selectedTextObj;
        console.log(`User ${index + 1} selected text "${selectedText}" on page ${page} with count ${count}`);

        // If the page is in the top pages, we process it
        if (!topPages.includes(page)) {
          console.log(`Skipping page ${page} as it's not in the top pages.`);
          return; // Skip pages not in top 7
        }

        const key = `${selectedText}|||${page}`; // Unique key (text + page)
        if (!textCountMap.has(key)) {
          textCountMap.set(key, { selectedText, count, page });
        } else {
          textCountMap.get(key).count += count;
        }
      });
    });

    console.log("Text Count Map After Processing Selected Texts:", textCountMap);

    // Convert to sorted array based on most selected text and filter for counts > 3
    const mostSelectedTexts = Array.from(textCountMap.values())
      .filter(item => item.count > 3) // Only include texts with count > 3
      .sort((a, b) => b.count - a.count || a.page - b.page); // Sort by count, then page

    console.log("Most Selected Texts (Filtered and Sorted):", mostSelectedTexts);

    // ------------------------------------------------------------
    // Aggregate clicked links (NEW ADDITION)
    // ------------------------------------------------------------
    const linkClickMap = new Map();
    analyticsData.forEach((doc, index) => {
      console.log(`Processing clicked links for user ${index + 1}`);
      (doc.linkClicks || []).forEach(({ page, clickedLink }) => {
        console.log(`User ${index + 1} clicked link "${clickedLink}" on page ${page}`);
        
        // Only consider pages within the topPages if you want to filter
        // If you want to filter clicks similarly to selected texts, uncomment the following lines:
        // if (!topPages.includes(page)) {
        //   console.log(`Skipping page ${page} as it's not in the top pages.`);
        //   return;
        // }

        const key = `${clickedLink}|||${page}`;
        if (!linkClickMap.has(key)) {
          linkClickMap.set(key, { clickedLink, count: 1, page });
        } else {
          linkClickMap.get(key).count += 1;
        }
      });
    });

    // Convert the link click map to an array and sort it by count (and page)
    const mostClickedLinks = Array.from(linkClickMap.values()).sort(
      (a, b) => b.count - a.count || a.page - b.page
    );

    console.log("Most Clicked Links:", mostClickedLinks);

    // ------------------------------------------------------------
    // Aggregate searched keywords (NEW ADDITION)
    // ------------------------------------------------------------
    const keywordCountMap = new Map();
    analyticsData.forEach((doc, index) => {
      console.log(`Processing search keywords for user ${index + 1}`);
      (doc.searchKeywords || []).forEach((keyword) => {
        const lowerKeyword = keyword.toLowerCase(); // Normalize for case-insensitive match
        console.log(`User ${index + 1} searched for keyword: "${lowerKeyword}"`);
        
        if (!keywordCountMap.has(lowerKeyword)) {
          keywordCountMap.set(lowerKeyword, 1);
        } else {
          keywordCountMap.set(lowerKeyword, keywordCountMap.get(lowerKeyword) + 1);
        }
      });
    });

    // Convert to array of objects: [{ keyword: "test", count: 10 }, ...]
    const searchedKeywords = Array.from(keywordCountMap.entries())
      .map(([keyword, count]) => ({ keyword, count }))
      .sort((a, b) => b.count - a.count); // Sort by count descending

    console.log("Searched Keywords:", searchedKeywords);

    // ------------------------------------------------------------
    // Return aggregated analytics with new clickedLinks and searchedKeywords fields
    // ------------------------------------------------------------
    res.json({
      totalPageTime,
      mostSelectedTexts,      // Most selected texts (only with count > 3)
      mostClickedLinks,       // Newly aggregated clicked links with page and count
      searchedKeywords,       // Keywords searched
      totalPages,
      topPages,               // Top 7 pages
      totalTimeReadable,      // Total time spent in readable format
      averageTimeReadable,    // Average time spent per user in readable format
    });
  } catch (error) {
    console.error("Error fetching analytics data:", error);
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
};

const getVideoViewAnalytics = async (req, res) => {
  const { url, uuid } = req.body;
  if (!url) return res.status(400).json({ message: "URL is required." });
  console.log(req.body)

  if (!uuid) return res.status(400).json({ message: "UUID is required." });

  try {
    await validateShortenedUrl(uuid, url);
    console.log("UUID and ShortID validation passed");
  } catch (err) {
    return res.status(401).json({ message: err.message });
  }

  const videoId = url.split("/").pop(); // Extract videoId from URL
  console.log(videoId)

  try {
    // Step 1: Fetch all video analytics documents for a given video ID
    if (!videoId) return res.status(400).json({ message: "Video ID is required." });

    let videoData = await VideoAnalytics.find({ videoId });

    // If no data is found, set the videoData to an empty array with sample data structure
    if (!videoData || videoData.length === 0) {
      videoData = [{
        skipEvents: [],
        jumpEvents: [],
        userVisit: { toString: () => "sampleUser" }
      }];
    }

    // Step 2: Initialize a mapping to store the views for each duration range
    let durationViewsMap = {};

    // Step 3: Loop through all video data documents
    videoData.forEach((data) => {
      // Process skip events (Forward and Backward)
      data.skipEvents.forEach((event) => {
        const from = Math.round(event.from);
        const to = Math.round(event.to);

        const start = Math.min(from, to);
        const end = Math.max(from, to);

        // Ignore single point ranges (e.g., "7 to 7")
        if (start === end) return;

        const durationRange = `${start} to ${end}`;

        // Add views to the duration range
        if (!durationViewsMap[durationRange]) {
          durationViewsMap[durationRange] = { views: 0, users: new Set() };
        }
        durationViewsMap[durationRange].views += 1;
        durationViewsMap[durationRange].users.add(data.userVisit.toString()); // Add user to the set
      });

      // Process jump events (e.g., replay)
      data.jumpEvents.forEach((event) => {
        const from = Math.round(event.from);
        const to = Math.round(event.to);

        const start = Math.min(from, to);
        const end = Math.max(from, to);

        // Ignore single point ranges (e.g., "7 to 7")
        if (start === end) return;

        const jumpRange = `${start} to ${end}`;

        // Add views to the jump range
        if (!durationViewsMap[jumpRange]) {
          durationViewsMap[jumpRange] = { views: 0, users: new Set() };
        }
        durationViewsMap[jumpRange].views += 1;
        durationViewsMap[jumpRange].users.add(data.userVisit.toString());
      });
    });

    // Step 4: Prepare the final list of durations with their aggregated views
    const finalDurationList = Object.keys(durationViewsMap).map((durationRange) => {
      const segment = durationViewsMap[durationRange];
      return {
        durationRange: durationRange,
        views: segment.views,
        usersCount: segment.users.size,  // Number of unique users for the range
      };
    });

    // Step 5: Merge similar ranges dynamically (ranges that are almost the same)
    let mergedDurationList = [];

    finalDurationList.forEach((item) => {
      let found = false;

      // Try to merge with an existing range in mergedDurationList
      mergedDurationList = mergedDurationList.map((existingItem) => {
        const [existingStart, existingEnd] = existingItem.durationRange.split(' to ').map(Number);
        const [newStart, newEnd] = item.durationRange.split(' to ').map(Number);

        // Check if the ranges are adjacent or overlap
        if (
          (existingStart <= newStart && existingEnd >= newStart) ||  // Overlapping or adjacent
          (existingStart <= newEnd && existingEnd >= newEnd)
        ) {
          // Merge the views and users
          existingItem.views += item.views;
          existingItem.usersCount += item.usersCount; // Add users count
          found = true;
        }
        return existingItem;
      });

      // If not merged, add as a new range
      if (!found) {
        mergedDurationList.push({ ...item });
      }
    });

    // Step 6: Sort by views (least to most), and then by usersCount (most to least)
    mergedDurationList.sort((a, b) => {
      // First compare by views (ascending)
      if (a.views === b.views) {
        // If views are equal, then compare by usersCount (descending)
        return b.usersCount - a.usersCount;
      }
      return a.views - b.views;  // Sort by views (ascending)
    });

    // Step 7: Filter out any ranges with low views if needed
    const filteredDurationList = mergedDurationList.filter((item) => item.views >= 1); // Keep those with views greater than or equal to 1

    // Step 8: Fetch the original URL corresponding to the video ID
    const shortenedUrl = await ShortenedUrl.findOne({ shortId: videoId });

    if (!shortenedUrl) {
      return res.status(404).json({ message: "No original URL found for this video ID" });
    }

    // Step 9: Return the final merged and sorted list with Videosourceurl
    return res.json({
      Videosourceurl: shortenedUrl.originalUrl, // The original URL corresponding to the shortened URL
      videoAnalytics: filteredDurationList,     // The filtered and sorted video analytics
    });
  } catch (error) {
    console.error("Error in getVideoViewAnalytics:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};


const Web_analytics = async (req, res) => {
  try {
    const { url, uuid } = req.body;
    console.log(req.body, "Request Body");

    if (!url) {
      return res.status(400).json({ message: "URL is required" });
    }

    if (!uuid) {
      return res.status(400).json({ message: "UUID is required" });
    }

    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Normalize category to lowercase
    const normalizedCategory = "weblink";
    console.log(normalizedCategory, "Normalized Category");

    // Extract the webId from the URL (assuming the ID is the last segment)
    const webId = url.split('/').pop();
    console.log(webId, "webId");

    // Fetch all analytics data for the given webId
    const webAnalyticsData = await Webanalytics.find({ webId: webId });
    console.log(webAnalyticsData, "webAnalyticsData");

    if (!webAnalyticsData || webAnalyticsData.length === 0) {
      return res.status(404).json({ message: 'Web document not found' });
    }

    let totalTimeSpent = 0;
    let totalPagesVisited = 0;
    let mostVisitedPage = '';
    let bounceSessions = 0;

    // Process web analytics data to calculate metrics
    webAnalyticsData.forEach((doc) => {
      totalTimeSpent += doc.totalTimeSpent;
      totalPagesVisited += doc.totalPagesVisited;

      if (!mostVisitedPage && doc.mostVisitedPage) {
        mostVisitedPage = doc.mostVisitedPage;
      }

      // Count bounce sessions (sessions with time spent less than 10 seconds)
      if (doc.totalTimeSpent < 10) {
        bounceSessions += 1;
      }
    });

    // Total sessions count
    const totalSessions = webAnalyticsData.length;
    // Calculate average time spent per page
    let averageTimeSpent = totalPagesVisited > 0 ? totalTimeSpent / totalPagesVisited : 0;
    console.log(averageTimeSpent, "Average Time Spent");

    // ------------------------------
    // NEW USER COUNT using documentId similar to pdf analytics
    const newUsers = await newUser.find({
      documentId: webId,
      [`count.${normalizedCategory}`]: { $gt: 0 },
    });

    const newUserCategoryCount = newUsers.reduce(
      (sum, user) => sum + (user.count[normalizedCategory] || 0),
      0
    );
    console.log("New user count for", normalizedCategory, ":", newUserCategoryCount);

    // ------------------------------
    // RETURNED USER COUNT using documentId similar to pdf analytics
    const returnedUsers = await ReturnedUser.find({
      documentId: webId,
      [`count.${normalizedCategory}`]: { $gt: 0 },
    });

    const returnedUserCategoryCount = returnedUsers.reduce(
      (sum, user) => sum + (user.count[normalizedCategory] || 0),
      0
    );
    console.log("Returned user count for", normalizedCategory, ":", returnedUserCategoryCount);

    // ------------------------------
    // Calculate the Bounce Rate
    const bounceRate = totalSessions > 0 ? (bounceSessions / totalSessions) * 100 : 0;
    console.log("Bounce Rate:", bounceRate);

    // Prepare the response data
    const responseData = {
      totalPagesVisited,
      totalTimeSpent,
      averageTimeSpent,
      userCounts: {
        newuser: { [normalizedCategory]: newUserCategoryCount },
        returneduser: { [normalizedCategory]: (returnedUserCategoryCount - newUserCategoryCount) },
      },
      mostVisitedPage,
      totalsession: totalSessions,
      bounceRate,
    };

    console.log(responseData, "Response Data");
    res.json(responseData);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: 'An error occurred while processing the Web analytics data',
      error: error.message,
    });
  }
};







const getHeatmapAnalytics = async (req, res) => {
  try {
    const { url, uuid } = req.body; // Extract URL from request body

    if (!url) {
      return res.status(400).json({ message: "URL is required" });
    }

    if (!uuid) {
      return res.status(400).json({ message: "UUID is required" });
    }
    try {
      await validateShortenedUrl(uuid, url);
      console.log("UUID and ShortID validation passed");
    } catch (err) {
      return res.status(401).json({ message: err.message });
    }

    // Extract webId from URL (Assuming the webId is the last part of the URL)
    const webId = url.split('/').pop();
    console.log(webId, "webId");

    // Step 1: Fetch all user visits related to the given webId from Webanalytics model
    const webAnalyticsData = await Webanalytics.find({ webId });
    console.log(webAnalyticsData, "user visits");

    if (!webAnalyticsData.length) {
      return res.status(404).json({ message: "No data found for this webId" });
    }

    // Step 2: Process all pointers for the heatmap
    let allPointers = [];
    webAnalyticsData.forEach((visit) => {
      const { pointerHeatmap } = visit; // Get the pointer data from each visit

      pointerHeatmap.forEach((pointer) => {
        const existingPointer = allPointers.find(
          (p) => p.position === pointer.position
        );

        if (existingPointer) {
          // If the position already exists, add the timeSpent to the existing pointer
          existingPointer.timeSpent += pointer.timeSpent;
        } else {
          // Otherwise, add a new pointer to the array
          allPointers.push({ position: pointer.position, timeSpent: pointer.timeSpent });
        }
      });
    });

    // Step 3: Retrieve the original URL from the ShortenedUrl model using the webId
    const shortenedUrl = await ShortenedUrl.findOne({ shortId: webId });

    if (!shortenedUrl) {
      return res.status(404).json({ message: "No original URL found for this webId" });
    }

    // Step 4: Return the aggregated heatmap pointers and the original URL
    return res.status(200).json({
      sourceurl: shortenedUrl.originalUrl, // The original URL corresponding to the shortened URL
      heapmappointers: allPointers, // The aggregated heatmap pointers
    });

  } catch (error) {
    console.error("Error fetching heatmap analytics:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

const validateLeadCaptureForm = [
  // Trigger validation - only one can be active at a time

  body('buttonText')
  .optional()
  .trim()
  .isLength({ min: 1, max: 50 })
  .withMessage('Button text must be between 1 and 50 characters')
  .custom((value) => {
    // Optional: Add custom validation to prevent inappropriate text
    if (value && value.toLowerCase().includes('spam')) {
      throw new Error('Button text contains inappropriate content');
    }
    return true;
  }),
  
  body('delaySeconds')
    .optional()
    .isInt({ min: 0, max: 60 })
    .withMessage('Delay seconds must be between 0 and 60'),
  
  body('scrollPercent')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Scroll percent must be between 0 and 100'),

  // Custom validation to ensure only one trigger is active
  body().custom((value, { req }) => {
    const { delaySeconds, scrollPercent } = req.body;
    
    // Check if both are provided and greater than 0
    const hasDelay = delaySeconds !== undefined && delaySeconds > 0;
    const hasScroll = scrollPercent !== undefined && scrollPercent > 0;
    
    // Ensure at least one trigger is active
    if (!hasDelay && !hasScroll) {
      throw new Error('Either delaySeconds (greater than 0) or scrollPercent (greater than 0) must be provided');
    }
    
    // Ensure only one trigger is active
    if (hasDelay && hasScroll) {
      throw new Error('Only one trigger can be active at a time - either delaySeconds or scrollPercent, not both');
    }
    
    // Clean up the opposite field - set to null if the other is active
    if (hasDelay) {
      req.body.scrollPercent = null;
    }
    
    if (hasScroll) {
      req.body.delaySeconds = null;
    }
    
    return true;
  }),

  // Custom fields validation
  body('customFields')
    .isArray({ min: 1, max: 6 })
    .withMessage('At least 1 custom field is required and maximum 6 fields are allowed'),
  
  body('customFields.*.label')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Field label is required and must be less than 100 characters'),
  
  body('customFields.*.placeholder')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Field placeholder is required and must be less than 200 characters'),
  
  body('customFields.*.fieldType')
    .isIn(['input', 'textarea'])
    .withMessage('Field type must be either input or textarea'),
  
  body('customFields.*.required')
    .isBoolean()
    .withMessage('Required field must be a boolean'),

  // Optional fields validation
  body('formWidth')
    .optional()
    .isInt({ min: 280, max: 600 })
    .withMessage('Form width must be between 280 and 600'),
  
  body('formPadding')
    .optional()
    .isInt({ min: 16, max: 40 })
    .withMessage('Form padding must be between 16 and 40'),
  
  body('formColor')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Form color must be a valid hex color code'),
  
  body('headerColor')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Header color must be a valid hex color code'),
  
  body('labelColor')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Label color must be a valid hex color code'),
  
  body('buttonBackgroundColor')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Button background color must be a valid hex color code'),
  
  body('buttonColor')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i)
    .withMessage('Button color must be a valid hex color code'),
  
  body('formHeader')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Form header must be less than 200 characters'),
  
  body('formSubHeader')
    .optional()
    .trim()
    .isLength({ max: 300 })
    .withMessage('Form sub header must be less than 300 characters'),
    
  
  body('thankYouMessage')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Thank you message must be less than 500 characters'),
  
  body('headerFontSize')
    .optional()
    .isInt({ min: 16, max: 28 })
    .withMessage('Header font size must be between 16 and 28'),
  
  body('labelFontSize')
    .optional()
    .isInt({ min: 12, max: 18 })
    .withMessage('Label font size must be between 12 and 18'),
  
  body('fontFamily')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Font family must be less than 200 characters')
];

// Create or Update Lead Capture Form Controller
const createOrUpdateLeadCaptureForm = async (req, res) => {
  try {
    // Check for validation errors (from express-validator middleware)
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    // Extract uuid from middleware (attached to req.body by authenticationMiddleware)
    const uuid = req.body.uuid;
    
    // Extract documentId from request body
    const { documentId, ...formData } = req.body;

    console.log('UUID from middleware:', uuid);
    console.log('DocumentId from body:', documentId);
    console.log('Form data before cleanup:', formData);

    // Additional cleanup logic to ensure mutual exclusivity
    const { delaySeconds, scrollPercent } = formData;
    
    // If delaySeconds is provided and > 0, set scrollPercent to null
    if (delaySeconds !== undefined && delaySeconds > 0) {
      formData.scrollPercent = null;
    }
    
    // If scrollPercent is provided and > 0, set delaySeconds to null
    if (scrollPercent !== undefined && scrollPercent > 0) {
      formData.delaySeconds = null;
    }

    console.log('Form data after cleanup:', formData);

    // Validate required fields
    if (!documentId) {
      return res.status(400).json({
        success: false,
        message: 'documentId is required in request body'
      });
    }

    if (!uuid) {
      return res.status(400).json({
        success: false,
        message: 'uuid is required (should be set by authentication middleware)'
      });
    }

    // Check if form already exists
    const existingForm = await LeadCaptureForm.findOne({ documentId, uuid });

    let leadCaptureForm;
    
    if (existingForm) {
      // Update existing form
      leadCaptureForm = await LeadCaptureForm.findOneAndUpdate(
        { documentId, uuid },
        { ...formData, documentId, uuid },
        { new: true, runValidators: true }
      );
    } else {
      // Create new form
      leadCaptureForm = new LeadCaptureForm({
        ...formData,
        documentId,
        uuid
      });
      await leadCaptureForm.save();
    }

    res.status(200).json({
      success: true,
      message: existingForm ? 'Lead capture form updated successfully' : 'Lead capture form created successfully',
      data: leadCaptureForm
    });

  } catch (error) {
    console.error('Error in createOrUpdateLeadCaptureForm:', error);
    
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(err => ({
        field: err.path,
        message: err.message
      }));
      
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Get Lead Capture Form

const getLeadCaptureForm = async (req, res) => {
  try {
    // Extract uuid from middleware (now available in multiple places)
    const uuid = req.uuid || req.user?.uid || req.body.uuid;
    
    // Extract documentId from query parameters or request body
    const documentId = req.query.documentId || req.body.documentId || req.params.documentId;

    console.log()

    console.log('UUID from middleware:', uuid);
    console.log('DocumentId from request:', documentId);

    // Validate required fields
    if (!documentId) {
      return res.status(400).json({
        success: false,
        message: 'documentId is required as query parameter, body field, or route parameter'
      });
    }

    if (!uuid) {
      return res.status(400).json({
        success: false,
        message: 'uuid is required (should be set by authentication middleware)'
      });
    }

    const leadCaptureForm = await LeadCaptureForm.findOne({ documentId, uuid });

    if (!leadCaptureForm) {
      return res.status(404).json({
        success: false,
        message: 'Lead capture form not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Lead capture form retrieved successfully',
      data: leadCaptureForm
    });

  } catch (error) {
    console.error('Error in getLeadCaptureForm:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};


module.exports = {
  login,
  register,
  uploadFile,
  uploadurl,
  dashboardData,
  DeleteSession,
  Pdf_pdfanalytics,
  Docx_docxanalytics,
  getUserActivitiesByPdfId,
  getUserActivitiesByDocxId,
  getPdfTraffic,
  getTimeSpentByWeek,
  getDeviceAnalytics,
  getVideoAnalytics,
  getUserActivitiesByVideoId,
  getVideoTraffic,
  getTimeSpentByWeekVideo,
  getDeviceAnalyticsVideo,
  getPdfviewanalytics,
  getDocxviewanalytics,
  getVideoViewAnalytics,
  getdocxTraffic,
  getTimeSpentByWeekDocx,
  getDeviceAnalyticsdocx,
  Web_analytics,
  getUserActivitiesByWebId,
  getWebTraffic,
  getTimeSpentByWeekWeb,
  getDeviceAnalyticsWeb,
  getHeatmapAnalytics,
  createOrUpdateUser,
  getUserPlanDetails,
  saveDocumentSettings,
  getDocumentConfiguration,
  createOrUpdateLeadCaptureForm,
  getLeadCaptureForm,
  validateLeadCaptureForm,
  checkCustomIdAvailability,
  saveCustomId,
  PowerPoint_analytics,
  getUserActivitiesByPowerPointId,
  getpowerpointanalytics,
  getpowerpointTraffic,
    getTimeSpentByWeekpowerpoint,
  getDeviceAnalyticsPowerpoint

};
