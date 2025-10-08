const mongoose = require('mongoose');

const downloadSchema = new mongoose.Schema({
    downloadCount: {
        type: Number,
        required: true
    },
    userId: {
        type: String,
        required: true
    },
    documentId: {
        type: String,
        required: true
    }
}, { timestamps: true }); // automatically adds createdAt & updatedAt

module.exports = mongoose.model('DocumentDownloads', downloadSchema);
