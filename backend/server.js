const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const app = express();
const FRONTEND = path.join(__dirname, "..", "frontend");
app.set("trust proxy", 1);
const isProduction = process.env.NODE_ENV === "production";
app.use(express.json());

// ---------- Secret code needed to create an admin account ----------
const ADMIN_CODE = process.env.ADMIN_CODE;
if (!ADMIN_CODE) {
  console.log("ERROR: No ADMIN_CODE found. Check your .env file.");
  process.exit(1);
}

// ---------- Database ----------
const db = new DatabaseSync("reports.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    photo TEXT NOT NULL,
    notes TEXT,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'Reported',
    admin_note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT
  );
`);

const insertUser = db.prepare(
  "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)"
);
const findUserByEmail = db.prepare("SELECT * FROM users WHERE email = ?");
const findUserById = db.prepare("SELECT id, name, email, role FROM users WHERE id = ?");

const insertReport = db.prepare(
  "INSERT INTO reports (user_id, photo, notes, latitude, longitude) VALUES (?, ?, ?, ?, ?)"
);
const getReportsByUser = db.prepare(
  "SELECT * FROM reports WHERE user_id = ? ORDER BY id DESC"
);

const getAllReports = db.prepare("SELECT * FROM reports ORDER BY id DESC");
const getReportsByStatus = db.prepare(
  "SELECT * FROM reports WHERE status = ? ORDER BY id DESC"
);
const updateStatus = db.prepare(
  "UPDATE reports SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
);

const ALLOWED_STATUSES = ["Reported", "Seen", "In progress", "Fixed"];

// ---------- Password scrambling (hashing) ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return salt + ":" + hash;
}

function checkPassword(password, stored) {
  const parts = stored.split(":");
  const salt = parts[0];
  const hash = Buffer.from(parts[1], "hex");
  const test = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(test, hash);
}

function sameText(a, b) {
  const x = crypto.createHash("sha256").update(String(a)).digest();
  const y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

// ---------- Too many wrong tries ----------
const failures = new Map();

function isLocked(ip) {
  const record = failures.get(ip);
  return Boolean(record && record.lockedUntil > Date.now());
}

function recordFailure(ip) {
  const record = failures.get(ip) || { count: 0, lockedUntil: 0 };
  record.count += 1;
  if (record.count >= 5) {
    record.lockedUntil = Date.now() + 5 * 60 * 1000;
    record.count = 0;
  }
  failures.set(ip, record);
}

function clearFailures(ip) {
  failures.delete(ip);
}

// ---------- Login sessions ----------
const sessions = new Map();

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  const parts = header.split(";");
  for (const part of parts) {
    const pieces = part.trim().split("=");
    const key = pieces.shift();
    if (key === name) return pieces.join("=");
  }
  return null;
}

function currentUser(req) {
  const token = getCookie(req, "session");
  if (!token || !sessions.has(token)) return null;
  return findUserById.get(sessions.get(token)) || null;
}

function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, userId);
  res.setHeader(
    "Set-Cookie",
    "session=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800" +
      (isProduction ? "; Secure" : "")
  );
}

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) {
    return res.status(401).json({ message: "Please log in." });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user) {
    return res.status(401).json({ message: "Please log in." });
  }
  if (user.role !== "admin") {
    return res.status(403).json({ message: "Admins only." });
  }
  req.user = user;
  next();
}

// ---------- Sign up ----------
app.post("/api/signup", function (req, res) {
  const ip = req.ip;
  const body = req.body || {};
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const role = body.role === "admin" ? "admin" : "user";

  if (name.length < 2 || name.length > 60) {
    return res.status(400).json({ message: "Please enter your name (2 to 60 letters)." });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) {
    return res.status(400).json({ message: "Please enter a valid email." });
  }
  if (password.length < 8 || password.length > 100) {
    return res.status(400).json({ message: "Password must be 8 to 100 characters." });
  }

  if (role === "admin") {
    if (isLocked(ip)) {
      return res.status(429).json({ message: "Too many wrong tries. Wait 5 minutes." });
    }
    if (!sameText(body.adminCode || "", ADMIN_CODE)) {
      recordFailure(ip);
      return res.status(403).json({ message: "Wrong official access code." });
    }
    clearFailures(ip);
  }

  if (findUserByEmail.get(email)) {
    return res.status(409).json({ message: "This email is already registered." });
  }

  insertUser.run(name, email, hashPassword(password), role);
  res.json({ message: "Account created. Please sign in." });
});

// ---------- Sign in ----------
app.post("/api/login", function (req, res) {
  const ip = req.ip;
  if (isLocked(ip)) {
    return res.status(429).json({ message: "Too many wrong tries. Wait 5 minutes." });
  }

  const body = req.body || {};
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  const user = findUserByEmail.get(email);
  if (!user || !checkPassword(password, user.password_hash)) {
    recordFailure(ip);
    return res.status(401).json({ message: "Wrong email or password." });
  }

  clearFailures(ip);
  startSession(res, user.id);
  res.json({ message: "Logged in", role: user.role });
});

// ---------- Sign out ----------
app.post("/api/logout", function (req, res) {
  const token = getCookie(req, "session");
  if (token) {
    sessions.delete(token);
  }
  res.setHeader("Set-Cookie", "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
  res.json({ message: "Logged out" });
});

// ---------- Who am I? ----------
app.get("/api/me", function (req, res) {
  const user = currentUser(req);
  if (!user) {
    return res.json({ loggedIn: false });
  }
  res.json({ loggedIn: true, name: user.name, email: user.email, role: user.role });
});

// ---------- Photo saving ----------
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only images are allowed"));
    }
  }
});

// ---------- Pages ----------
app.get("/", function (req, res) {
  if (!currentUser(req)) {
    return res.redirect("/login");
  }
  res.sendFile(path.join(FRONTEND, "index.html"));
});

app.get("/my-complaints", function (req, res) {
  if (!currentUser(req)) {
    return res.redirect("/login");
  }
  res.sendFile(path.join(FRONTEND, "my-complaints.html"));
});

app.get("/map", function (req, res) {
  res.sendFile(path.join(FRONTEND, "map.html"));
});

app.get("/admin", function (req, res) {
  res.sendFile(path.join(FRONTEND, "admin.html"));
});

app.get("/login", function (req, res) {
  res.sendFile(path.join(FRONTEND, "login.html"));
});

app.get("/home", function (req, res) {
  res.sendFile(path.join(FRONTEND, "home.html"));
});

app.use("/uploads", express.static("uploads"));

// ---------- Receive a report ----------
app.post("/report", requireLogin, upload.single("photo"), function (req, res) {
  const lat = Number(req.body.latitude);
  const lng = Number(req.body.longitude);
  const notes = (req.body.notes || "").trim().slice(0, 1000);

  if (!req.file) {
    return res.status(400).json({ message: "Please add a photo." });
  }

  const locationIsValid =
    Number.isFinite(lat) && Number.isFinite(lng) &&
    lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;

  if (!locationIsValid) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ message: "Location is not valid." });
  }

  insertReport.run(req.user.id, req.file.filename, notes, lat, lng);
  console.log("Report saved:", req.file.filename);

  res.json({ message: "Report received. Thank you!" });
});

// ---------- Reports ----------
app.get("/api/reports", function (req, res) {
  const status = req.query.status;

  if (status) {
    if (!ALLOWED_STATUSES.includes(status)) {
      return res.status(400).json({ message: "Invalid status." });
    }
    return res.json(getReportsByStatus.all(status));
  }

  res.json(getAllReports.all());
});

// Only the logged-in user's own reports
app.get("/api/my-reports", requireLogin, function (req, res) {
  res.json(getReportsByUser.all(req.user.id));
});

app.post("/api/reports/:id/status", requireAdmin, function (req, res) {
  const id = Number(req.params.id);
  const status = req.body ? req.body.status : null;

  if (!Number.isInteger(id) || !ALLOWED_STATUSES.includes(status)) {
    return res.status(400).json({ message: "Invalid request." });
  }

  updateStatus.run(status, id);
  res.json({ message: "Status updated" });
});

// ---------- Error handling ----------
app.use(function (err, req, res, next) {
  res.status(400).json({ message: err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log("Server is running on port " + PORT);
});