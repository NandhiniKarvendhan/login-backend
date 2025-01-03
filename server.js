const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const admin = require("firebase-admin");
require("dotenv").config();

const User = require("./models/User");

const app = express();
const PORT = process.env.PORT || 8000;
const MONGO_URI = process.env.MONGO_URI;

// Firebase Admin Initialization
admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  }),
});

// Middleware
app.use(express.json()); // Parse JSON payloads

// COOP and COEP Headers for enhanced security
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

// CORS Configuration
const allowedOrigins = [
  "http://localhost:3000",
   "https://sms-gateway-demo.onrender.com", // React Development URL
  process.env.FRONTEND_URL, // Frontend Production URL from environment
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true); // Allow access
      } else {
        console.error(`Blocked by CORS policy: ${origin}`);
        callback(new Error("CORS policy does not allow access from this origin."));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Allowed HTTP methods
    allowedHeaders: ["Content-Type", "Authorization"], // Allowed headers
    credentials: true, // Allow cookies and credentials
  })
);

// Handle Preflight Requests
app.options("*", cors());

// Connect to MongoDB
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Routes

// Health Check Route
app.get("/", (req, res) => {
  res.status(200).send("Login Backend is running!");
});

// Register User
app.post("/register", async (req, res) => {
  const { username, password } = req.body; // Directly map to frontend structure
  console.log("Request Body:", req.body);

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password are required!" });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "User already exists!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ success: true, message: "User registered successfully!" });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});



// Login User
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password are required!" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found!" });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ success: false, message: "Invalid credentials!" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({ success: true, message: "Login successful!", token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// Google Sign-In
app.post("/google-signin", async (req, res) => {
  const { idToken } = req.body;

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { email, name } = decodedToken;

    let user = await User.findOne({ username: email });
    if (!user) {
      user = new User({ username: email, name, password: null });
      await user.save();
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ success: true, message: "Google Sign-In successful!", token });
  } catch (error) {
    console.error("Google Sign-In error:", error);
    res.status(400).json({ success: false, message: "Invalid Google ID token." });
  }
});

// Start Server
app.listen(PORT, "0.0.0.0", () =>
  console.log(`Server running on http://localhost:${PORT} or ${process.env.FRONTEND_URL}`)
);
