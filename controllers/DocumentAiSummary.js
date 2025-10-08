const axios = require("axios");
const pdfParse = require("pdf-parse");
const Urls = require("../models/test");
const PdfSummary = require("../models/DocumentSummary");

// OpenRouter API Config
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions";

// Step 1: Extract text from PDF (by page)
async function fetchAndExtractTextByPage(pdfUrl) {
  const response = await axios.get(pdfUrl, { responseType: "arraybuffer" });
  const dataBuffer = response.data;
  const pdfData = await pdfParse(dataBuffer);

  const textByLine = pdfData.text.split("\n");
  const approxLinesPerPage = 30;
  const pages = [];

  const maxLines = approxLinesPerPage * 10;
  const linesToProcess = Math.min(textByLine.length, maxLines);

  for (let i = 0; i < linesToProcess; i += approxLinesPerPage) {
    const lines = textByLine.slice(i, i + approxLinesPerPage);
    pages.push({
      page: pages.length + 1,
      text: lines.join("\n").trim()
    });

    if (pages.length >= 10) break;
  }

  return pages;
}

// Step 2: Call OpenRouter AI to summarize
async function openRouterSummarize(text) {
  const payload = {
    model: "anthropic/claude-3.5-sonnet",
    messages: [
      {
        role: "user",
        content: `You're an expert document analyst. Carefully analyze the following PDF page content and extract:
- 🔑 Key points
- 🎯 Main purpose
- 🧠 Key takeaway

PDF Content: ${text}`
      }
    ],
    max_tokens: 1000,
    temperature: 0.7
  };

  try {
    const response = await axios.post(OPENROUTER_API_URL, payload, {
      headers: {
        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json"
      }
    });

    return response.data.choices[0].message.content;
  } catch (error) {
    console.error("❌ OpenRouter API Error:", error.response?.data || error.message);
    return "Summary failed: OpenRouter error.";
  }
}

// Step 3: Main Controller Function
const DocumentSummarize = async (req, res) => {
  const { pdfUrl } = req.body;

  if (!pdfUrl) {
    return res.status(400).json({ error: "pdfUrl is required in request body." });
  }

  try {
    // 🔍 Check if PDF exists and is active
    const urlRecord = await Urls.findOne({ originalUrl: pdfUrl, active: "Y" });
    if (!urlRecord) {
      return res.status(404).json({ error: "No active PDF found for the given URL." });
    }

    const userUuid = urlRecord.userUuid;

    // ✅ Step 0: Check if already summarized
    const existingSummary = await PdfSummary.findOne({ originalUrl: pdfUrl, userUuid });
    if (existingSummary) {
      return res.json({
        message: "Summary retrieved from database.",
        totalPages: existingSummary.totalPages,
        summaries: existingSummary.summaries
      });
    }

    // 🧾 Step 1: Extract and summarize
    const pages = await fetchAndExtractTextByPage(pdfUrl);
    const summaries = [];

    for (const page of pages) {
      const trimmedText = page.text.slice(0, 4000);

      if (!trimmedText.trim()) {
        summaries.push({ page: page.page, summary: "This page is empty." });
        continue;
      }

      const summary = await openRouterSummarize(trimmedText);
      summaries.push({ page: page.page, summary });

      await new Promise(res => setTimeout(res, 500)); // avoid API rate-limit
    }

    // 💾 Step 2: Store in DB
    const savedSummary = await PdfSummary.create({
      originalUrl: pdfUrl,
      userUuid,
      totalPages: pages.length,
      summaries
    });

    res.json({
      message: "Summarization complete.",
      totalPages: pages.length,
      summaries
    });
  } catch (err) {
    console.error("❌ Server Error:", err.message);
    res.status(500).json({ error: "Server error: " + err.message });
  }
};

module.exports = {
  DocumentSummarize
};
