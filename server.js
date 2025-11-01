require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("./passport");
const path = require("path");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const User = require("./models/Users");
const UrlCheck = require("./models/UrlCheck");

const app = express();

// -----------------------------
// 1️⃣ Environment Variables
// -----------------------------
const port = process.env.PORT || 3000;
const FLASK_URL = process.env.FLASK_URL || process.env.FLASK_SERVICE_URL;
const MONGODB_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

// -----------------------------
// 2️⃣ Warnings
// -----------------------------
if (!MONGODB_URI) {
  console.error("❌ FATAL: MONGO_URI not set in .env!");
  process.exit(1);
}

if (!FLASK_URL) {
  console.warn("⚠️ WARNING: FLASK_URL not set — AI features will not work.");
}

// -----------------------------
// 3️⃣ Middleware Setup
// -----------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.set('trust proxy', 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// -----------------------------
// 4️⃣ MongoDB Connection
// -----------------------------
mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

// -----------------------------
// 5️⃣ Routes
// -----------------------------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "homepage.html")));
app.get("/homepage", (req, res) => res.sendFile(path.join(__dirname, "homepage.html")));
app.get("/signup", (req, res) => res.sendFile(path.join(__dirname, "signup.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "login.html")));

app.get("/phishing", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  res.sendFile(path.join(__dirname, "phishing.html"));
});

app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

// -----------------------------
// 6️⃣ Authentication & User
// -----------------------------
app.post("/api/signup", async (req, res) => {
  const { email, password, name } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword, name });
    await newUser.save();

    res.status(201).json({ message: "Signup success" });
  } catch (err) {
    res.status(500).json({ message: "Signup error", error: err.message });
  }
});

app.post("/api/login", passport.authenticate("local"), (req, res) => {
  res.status(200).json({
    message: "Login success",
    username: req.user.name || req.user.email.split("@")[0],
  });
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => res.redirect("/")
);

app.get("/api/current_user", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      loggedIn: true,
      username: req.user.name || req.user.email.split("@")[0],
      email: req.user.email,
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// -----------------------------
// 7️⃣ AI Scan (Flask Integration)
// -----------------------------
app.post("/api/scan-url", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: "URL is required" });

    if (!FLASK_URL) {
      return res.status(503).json({
        message: "AI service is not configured.",
        error: "FLASK_SERVICE_NOT_CONFIGURED",
      });
    }

    console.log(`🔍 Scanning URL: ${url}`);

    // Helper: call Flask predict with simple retry/backoff and better headers
    async function callFlaskPredict(targetUrl, userId) {
      const payload = { url: targetUrl, user: userId };
      const maxAttempts = 2;
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          return await axios.post(`${FLASK_URL}/predict`, payload, {
            timeout: 120000,
            headers: {
              "Content-Type": "application/json",
              "User-Agent": "PhishGuard/1.0 (+https://example.local)"
            },
          });
        } catch (err) {
          console.warn(`Flask predict attempt ${attempt} failed:`, err.code || err.message || err);
          if (attempt === maxAttempts) throw err;
          // small backoff
          await new Promise((r) => setTimeout(r, 250 * attempt));
        }
      }
    }

    const flaskResponse = await callFlaskPredict(
      url,
      req.isAuthenticated() ? req.user._id.toString() : "anonymous"
    );

    const result = flaskResponse.data;
    console.log(`✅ Flask result: ${result.prediction} (${result.confidence}%)`);


    if (req.isAuthenticated()) {
      // Save using UrlCheck schema: url, prediction, confidence, checkedAt (default), user
      const newCheck = new UrlCheck({
        url: url,
        prediction: result.prediction,
        confidence: result.confidence,
        user: req.user._id,
      });

      await newCheck.save();
      console.log("✓ Saved to database");
    }

    res.json({
      url,
      prediction: result.prediction,
      confidence: result.confidence,
      timestamp: new Date().toISOString(),
      message:
        result.prediction === "phishing"
          ? "Potential phishing site detected!"
          : "URL appears to be legitimate.",
    });
  } catch (error) {
    // Log detailed error info to help debug network/Flask issues
    try {
      console.error("❌ Scan error:", error && error.message);
      if (error && error.code) console.error("Error code:", error.code);
      if (error && error.response) {
        console.error("Flask response status:", error.response.status);
        console.error("Flask response data:", error.response.data);
      }
      if (error && error.stack) console.error(error.stack);
    } catch (logErr) {
      console.error("Error while logging scan error:", logErr);
    }

    // Return a helpful error payload to the client
    const errMsg = (error && (error.message || (error.response && JSON.stringify(error.response.data)))) || "Unknown scan error";
    res.status(500).json({ message: "Scan failed", error: errMsg });
  }
});

// -----------------------------
// 8️⃣ Scan History Routes
// -----------------------------
app.get("/api/recent-scans", async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.json({ scans: [], message: "Login to see scan history", total: 0 });
    }

    const recentScans = await UrlCheck.find({ user: req.user._id })
      .sort({ checkedAt: -1 })
      .limit(10)
      .select("url prediction confidence checkedAt");

    const totalScans = await UrlCheck.countDocuments({ userId: req.user._id });
    const phishingCount = await UrlCheck.countDocuments({
      userId: req.user._id,
      prediction: "phishing",
    });

    res.json({
      scans: recentScans,
      total: totalScans,
      phishingFound: phishingCount,
      legitimateFound: totalScans - phishingCount,
    });
  } catch (error) {
    console.error("Error fetching scans:", error);
    res.status(500).json({ message: "Error fetching scan history" });
  }
});

// -----------------------------
// 9️⃣ Health & Utility Routes
// -----------------------------
app.get("/api/health", async (req, res) => {
  try {
    let flaskStatus = "offline";
    if (FLASK_URL) {
      try {
        const flaskResponse = await axios.get(`${FLASK_URL}/health`, { timeout: 5000 });
        flaskStatus = flaskResponse.status === 200 ? "online" : "offline";
      } catch {
        flaskStatus = "offline";
      }
    }

    const mongoStatus = mongoose.connection.readyState === 1 ? "online" : "offline";

    res.json({
      status: "online",
      services: {
        nodejs: "online",
        mongodb: mongoStatus,
        flask_ai: flaskStatus,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// -----------------------------
// 🔟 Logout & Error Handlers
// -----------------------------
app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/"));
});

app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({
    message: "Internal server error",
    error: process.env.NODE_ENV === "development" ? error.message : "Something went wrong",
  });
});

app.use((req, res) => res.status(404).json({ message: "Page not found" }));

// -----------------------------
// 🚀 Server Start
// -----------------------------
app.listen(port, "0.0.0.0", () => {
  console.log("\n" + "=".repeat(60));
  console.log("PHISHGUARD SERVER");
  console.log("=".repeat(60));
  console.log(`Server running on port ${port}`);
  console.log(`MongoDB: ${mongoose.connection.readyState === 1 ? "✓ Connected" : "✗ Disconnected"}`);
  console.log(`Flask AI: ${FLASK_URL ? "✓ Configured" : "✗ Not configured"}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
  console.log("=".repeat(60) + "\n");
});
