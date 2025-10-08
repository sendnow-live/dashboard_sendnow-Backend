const mongoose = require('mongoose');

const customFieldSchema = new mongoose.Schema({
  label: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  placeholder: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  required: {
    type: Boolean,
    default: false
  },
  fieldType: {
    type: String,
    required: true,
    enum: ['input', 'textarea'],
    default: 'input'
  }
}, { _id: false });

const leadCaptureFormSchema = new mongoose.Schema({
  documentId: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  uuid: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  // Required fields
  delaySeconds: {
    type: Number,

    min: 0,
    max: 60,
    default: 3
  },
  scrollPercent: {
    type: Number,
 
    min: 0,
    max: 100,
    default: 40
  },
  // Optional styling fields with defaults
  formWidth: {
    type: Number,
    min: 280,
    max: 600,
    default: 380
  },
  formPadding: {
    type: Number,
    min: 16,
    max: 40,
    default: 24
  },
  formColor: {
    type: String,
    default: "#ffffff",
    validate: {
      validator: function(v) {
        return /^#[0-9A-F]{6}$/i.test(v);
      },
      message: 'Color must be a valid hex color code'
    }
  },
  formBorderRadius: {
    type: Number,
    min: 0,
    max: 24,
    default: 16
  },
  inputBorderRadius: {
    type: Number,
    min: 0,
    max: 16,
    default: 8
  },
  buttonBorderRadius: {
    type: Number,
    min: 0,
    max: 16,
    default: 8
  },
  fontFamily: {
    type: String,
    default: "Inter, Arial, sans-serif",
    maxlength: 200
  },
  headerFontSize: {
    type: Number,
    min: 16,
    max: 28,
    default: 20
  },
  labelFontSize: {
    type: Number,
    min: 12,
    max: 18,
    default: 14
  },
  headerColor: {
    type: String,
    default: "#1a1a1a",
    validate: {
      validator: function(v) {
        return /^#[0-9A-F]{6}$/i.test(v);
      },
      message: 'Header color must be a valid hex color code'
    }
  },
  labelColor: {
    type: String,
    default: "#333333",
    validate: {
      validator: function(v) {
        return /^#[0-9A-F]{6}$/i.test(v);
      },
      message: 'Label color must be a valid hex color code'
    }
  },
  buttonBackgroundColor: {
    type: String,
    default: "#3b82f6",
    validate: {
      validator: function(v) {
        return /^#[0-9A-F]{6}$/i.test(v);
      },
      message: 'Button background color must be a valid hex color code'
    }
  },
  buttonColor: {
    type: String,
    default: "#ffffff",
    validate: {
      validator: function(v) {
        return /^#[0-9A-F]{6}$/i.test(v);
      },
      message: 'Button color must be a valid hex color code'
    }
  },
  // Add this field to your leadCaptureFormSchema in the mongoose model
// Insert this after the thankYouMessage field

buttonText: {
  type: String,
  default: "Get My Free Consultation",
  maxlength: 50,
  trim: true,
  validate: {
    validator: function(v) {
      return v && v.length >= 1;
    },
    message: 'Button text is required and cannot be empty'
  }
},

  formHeader: {
    type: String,
    default: "Get Your Free Consultation",
    maxlength: 200,
    trim: true
  },
  formSubHeader: {
    type: String,
    default: "",
    maxlength: 300,
    trim: true
  },
  thankYouMessage: {
    type: String,
    default: "Thank you! We'll get back to you within 24 hours.",
    maxlength: 500,
    trim: true
  },
  // Custom fields - at least one required
  customFields: {
    type: [customFieldSchema],
    required: true,
    validate: {
      validator: function(v) {
        return v && v.length >= 1 && v.length <= 6;
      },
      message: 'At least 1 custom field is required and maximum 6 fields are allowed'
    }
  }
}, {
  timestamps: true,
  versionKey: false
});

// Create compound index for efficient querying
leadCaptureFormSchema.index({ documentId: 1, uuid: 1 }, { unique: true });

module.exports = mongoose.model('LeadCaptureForm', leadCaptureFormSchema);
