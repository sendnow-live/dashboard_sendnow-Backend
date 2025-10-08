const mongoose = require("mongoose");

const pageSummarySchema = new mongoose.Schema({
  page: {
    type: Number,
    required: true,
  },
  summary: {
    type: String,
    required: true,
  },
});

const pdfSummarySchema = new mongoose.Schema(
  {
    originalUrl: {
      type: String,
      required: true,
    },
    userUuid: {
      type: String,
      required: true,
    },
    totalPages: {
      type: Number,
      required: true,
    },
    summaries: {
      type: [pageSummarySchema],
      required: true,
    },
  },
  {
    timestamps: true,
    collection: "pdf_summaries", // 📂 Collection name
  }
);

const DocumentSummarize = mongoose.model("DocumentSummarize", pdfSummarySchema);
module.exports = DocumentSummarize;
