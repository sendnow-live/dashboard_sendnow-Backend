const express = require("express");
const router = express.Router();
const multer = require('multer');
// Multer setup (no file uploads, just fields)
const storage = multer.memoryStorage(); // or diskStorage if you want to save files
const upload = multer({ storage: storage });


const { login, register , uploadurl, uploadFile,dashboardData , Pdf_pdfanalytics, Docx_docxanalytics, DeleteSession , getUserActivitiesByPdfId , getPdfTraffic , getTimeSpentByWeek, getDeviceAnalytics, getUserActivitiesByDocxId, getVideoAnalytics , getUserActivitiesByVideoId , getVideoTraffic , getTimeSpentByWeekVideo, getDeviceAnalyticsVideo , getPdfviewanalytics,getDocxviewanalytics, getVideoViewAnalytics, getdocxTraffic , getTimeSpentByWeekDocx, getDeviceAnalyticsdocx , Web_analytics, getUserActivitiesByWebId, getWebTraffic, getTimeSpentByWeekWeb, getDeviceAnalyticsWeb, getHeatmapAnalytics, createOrUpdateUser,getUserPlanDetails,saveDocumentSettings, getDocumentConfiguration, createOrUpdateLeadCaptureForm,getLeadCaptureForm, validateLeadCaptureForm, checkCustomIdAvailability, saveCustomId,PowerPoint_analytics,getUserActivitiesByPowerPointId, getpowerpointanalytics,getpowerpointTraffic,getTimeSpentByWeekpowerpoint, getDeviceAnalyticsPowerpoint } = require("../controllers/user");
const authMiddleware = require('../middleware/auth')
const fcmVerificationMiddleware = require('../middleware/FCMMiddleware')

// Complete the FCM token route handler
router.post("/client/fcm-token", fcmVerificationMiddleware, async (req, res) => {
  try {
    const { uuid, fcmToken } = req.body; // uuid is set by middleware
    const { uid } = req.user; // From verified Firebase token

    // Validate FCM token presence
    if (!fcmToken) {
      return res.status(400).json({ 
        success: false,
        error: 'FCM token is required' 
      });
    }

    // Additional validation (optional)
    if (fcmToken.length < 100) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid FCM token format' 
      });
    }

    // The middleware already processed and stored the FCM token
    // You can add additional business logic here if needed
    
    console.log(`✅ FCM Token registered for user: ${uid}`);

    res.status(200).json({ 
      success: true,
      message: 'FCM token registered successfully',
      data: {
        uuid: uuid,
        tokenRegistered: true,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('❌ FCM Token registration error:', error.message);
    res.status(500).json({ 
      success: false,
      error: 'Failed to register FCM token',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


router.post("/save-custom-id",authMiddleware, saveCustomId);
router.post("/check-custom-id", authMiddleware, checkCustomIdAvailability);


router.route("/login").post(login);
router.route("/register").post(register);
router.post("/user/entry", createOrUpdateUser);
// router.route("/dashboard").get(authMiddleware, dashboard);
// router.route("/users").get(getAllUsers);

// File upload route
router.post("/fileupload", upload.single("file"), authMiddleware, uploadFile);


router.post("/linkupload", authMiddleware, uploadurl);

router.get("/client/dashboard", authMiddleware, dashboardData);
router.post("/client/authcheck", authMiddleware, getUserPlanDetails);

//document locks
router.post(
  "/document/configuration",
  upload.fields([
    { name: "customLogo", maxCount: 1 }, // Allow file upload
  ]),
  authMiddleware,
  saveDocumentSettings
);

router.get("/document/configuration/:documentId", authMiddleware, getDocumentConfiguration);
router.post("/lead-capture-settings", authMiddleware, validateLeadCaptureForm,createOrUpdateLeadCaptureForm);

router.get("/lead-capture-settings", authMiddleware, getLeadCaptureForm);


//pdf

router.post("/pdf/analytics", authMiddleware, Pdf_pdfanalytics);

router.post("/pdf/session",authMiddleware, getUserActivitiesByPdfId);

router.post("/pdf/traffic", authMiddleware,getPdfTraffic);

router.post("/pdf/timespend",authMiddleware, getTimeSpentByWeek);

router.post("/pdf/device", authMiddleware,getDeviceAnalytics);

//powerPoint

router.post("/Powerpoint/analytics", authMiddleware, PowerPoint_analytics);

router.post("/Powerpoint/session",authMiddleware, getUserActivitiesByPowerPointId);

router.post("/Powerpoint/traffic",authMiddleware, getpowerpointTraffic);


router.post("/Powerpoint/timespend",authMiddleware, getTimeSpentByWeekpowerpoint);


router.post("/Powerpoint/device",authMiddleware, getDeviceAnalyticsPowerpoint);

//docx

router.post("/docx/analytics", authMiddleware, Docx_docxanalytics);

router.post("/docx/session",authMiddleware, getUserActivitiesByDocxId);

router.post("/docx/traffic", authMiddleware,getdocxTraffic);

router.post("/docx/timespend", authMiddleware,getTimeSpentByWeekDocx);

router.post("/docx/device",authMiddleware, getDeviceAnalyticsdocx);

router.delete("/removesession",authMiddleware, DeleteSession);

//video

router.post("/video/analytics",authMiddleware, getVideoAnalytics);

router.post("/video/session",authMiddleware, getUserActivitiesByVideoId);

router.post("/video/traffic", authMiddleware,getVideoTraffic);

router.post("/video/timespend", authMiddleware,getTimeSpentByWeekVideo);

router.post("/video/device", authMiddleware,getDeviceAnalyticsVideo);


//web


router.post("/web/analytics", authMiddleware, Web_analytics);

router.post("/web/session", authMiddleware,getUserActivitiesByWebId);

router.post("/web/traffic",authMiddleware, getWebTraffic);

router.post("/web/timespend",authMiddleware, getTimeSpentByWeekWeb);

router.post("/web/device", authMiddleware, getDeviceAnalyticsWeb);



//pdfadmin view

router.post("/pdf/viewanalytics",authMiddleware, getPdfviewanalytics);

//pptx view powerpoint

router.post("/powerpoint/viewanalytics",authMiddleware, getpowerpointanalytics);

//webheatmap view

router.post("/web/heatmap", authMiddleware ,getHeatmapAnalytics);

//docxadmin most page view 
router.post("/docx/viewanalytics",authMiddleware, getDocxviewanalytics);


//video
router.post("/video/viewanalytics", authMiddleware, getVideoViewAnalytics);


module.exports = router;
