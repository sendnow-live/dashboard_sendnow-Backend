const express = require("express");
const { DocumentSummarize } = require("../controllers/DocumentAiSummary");

const router = express.Router();

router.post("/summarize", DocumentSummarize);

module.exports = router;
