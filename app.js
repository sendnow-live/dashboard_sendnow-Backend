require("dotenv").config();
require("express-async-errors");

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");

const connectDB = require("./db/connect");
const mainRouter = require("./routes/user");
const cron = require("./routes/cronRoute");
const AisummaryRoutes = require("./routes/Aisummary");

const app = express();

// ✅ Trust proxy (for secure headers, rate limit, etc.)
app.set("trust proxy", 1);

// ✅ Logging
app.use(morgan("combined"));


// ✅ Secure HTTP headers
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "img-src": ["'self'", "data:", "https:"],
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    },
  })
);
app.use(helmet.frameguard({ action: "deny" }));
app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  })
);

// ✅ Enforce HTTPS in production
if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.redirect("https://" + req.headers.host + req.url);
    }
    next();
  });
}

// ✅ Limit body size
app.use(express.json({ limit: "10kb" }));

// ✅ Sanitize user input (use xss-clean after parsing JSON)
app.use(xss()); // Apply XSS sanitization after body parsing
app.use(mongoSanitize()); // MongoDB sanitization

// ✅ Prevent HTTP parameter pollution
app.use(hpp());

// ✅ Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: "Too many requests, please try again later.",
});
app.use(limiter);

// ✅ Parse cookies
app.use(cookieParser());

// ✅ CORS configuration
const corsOptions = {
  origin: [
    'https://sendnow-admin-uat.vercel.app',
    'http://localhost:3000',
    'http://localhost:3001',
    'https://dashboard.sendnow.live',
    'http://sd4.live',
  ],
  credentials: true,
  methods: 'GET,HEAD,OPTIONS,POST,PUT,DELETE',
  allowedHeaders: 'Origin, X-Requested-With, Content-Type, Accept, Authorization, csrf-token',
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ✅ Root test route
app.get("/", (req, res) => {
  res.send("Welcome to the API root endpoint of the admin dashboard.");
});

// ✅ Test Route for sanitizing XSS
app.post("/test-sanitize", (req, res) => {
  res.send(req.body);  // Send the sanitized body back
});

// API routes
app.use("/api/v1", mainRouter);
app.use("/api/v1", cron)
app.use("/api/v1", AisummaryRoutes);


// ✅ Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err);
  res.status(500).json({ message: "Internal Server Error" });
});

// ✅ Start server
const port = process.env.PORT || 3000;
const start = async () => {
  try {
    await connectDB(process.env.MONGO_URI);
    app.listen(port, () => {
      console.log(`🚀 Server is running on port ${port}`);
    });
  } catch (error) {
    console.error("❌ Error starting server:", error);
  }
};

start();
