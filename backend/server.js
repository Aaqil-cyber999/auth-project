const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key";
const app = express();
const PORT = 5000;

// MongoDB connection URI
const uri = "mongodb+srv://aaqils766_db_user:Aaqils%402608@mywebsite.9vec6i2.mongodb.net/myapp?appName=MyWebsite";

// ------------------ MONGODB CONNECT ------------------
mongoose.connect(uri)
  .then(() => console.log("MongoDB connected successfully"))
  .catch(err => console.error("MongoDB connection failed", err));

// ------------------ USER SCHEMA ------------------
const userSchema = new mongoose.Schema({
  name: { type: String, required: false},
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);

// ------------------ MIDDLEWARE ------------------
app.use(express.static("/home/kali/html"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------ REQUEST LOGGER ------------------
app.use((req, res, next) => {
  const safeBody = { ...req.body };
  Object.keys(safeBody).forEach(k => {
    if (typeof k === 'string' && k.toLowerCase().includes('password')) {
      safeBody[k] = '****';
    }
  });
  console.log(new Date().toISOString(), req.method, req.url, safeBody);
  next();
});

// ------------------ ROUTES ------------------
app.get("/", (req, res) => {
  res.sendFile("/home/kali/html/index.html");
});

// -------- SIGNUP --------
app.post("/signup", async (req, res) => {
  try {
    const { Name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name: Name,
      email,
      password: hashedPassword
    });

    await newUser.save();

    res.json({ success: true, message: "User signed up successfully!" });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ success: false, message: "Signup failed" });
  }
});

// -------- LOGIN --------
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

   const payload = {
  userId: user._id.toString(),  // Always from DB, not client
  name: user.name || user.email,
  role: "employer"               // or jobseeker depending on user
};

// Create token
const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
console.log("JWT token generated:", token);
res.json({ success: true, message: "Logged in successfully!", token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

function isAuthenticatedJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // attach payload to request
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}

app.get("/dashboard", isAuthenticatedJWT, (req, res) => {
  res.json({
    success: true,
    message: `Welcome ${req.user.name}`
  });
});

// -------- LOGOUT --------
app.post("/logout", (req, res) => {
  res.json({ success: true, message: "Logged out" });
});

// ------------------ SERVER ------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});