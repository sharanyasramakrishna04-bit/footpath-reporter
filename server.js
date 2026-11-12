const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());

// ---------- Admin password (from the .env file) ----------
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.log("ERROR: No ADMIN_PASSWORD found. Check your .env file.");
  process.exit(1);
}

// ---------- Database ----------
const db = new DatabaseSync("reports.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    photo TEXT NOT NULL,
    notes TEXT,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'Reported',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const insertReport = db.prepare(
  "INSERT INTO reports (photo, notes, latitude, longitude) VALUES (?, ?, ?, ?)"
);
const getAllReports = db.prepare("SELECT * FROM reports ORDER BY id DESC");
const updateStatus = db.prepare("UPDATE reports SET status = ? WHERE id = ?");

const ALLOWED_STATUSES = ["Reported", "Seen", "In progress", "Fixed"];

// ---------- Login system ----------
const sessions = new Set();
const loginAttempts = new Map();

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

function isLoggedIn(req) {
  const token = getCookie(req, "session");
  return Boolean(token) && sessions.has(token);
}

function requireAdmin(req, res, next) {
  if (isLoggedIn(req)) {
    return next();
  }
  res.status(401).json({ message: "Please log in." });
}

function passwordMatches(input) {
  const a = crypto.createHash("sha256").update(String(input)).digest();
  const b = crypto.createHash("sha256").update(ADMIN_PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}

app.post("/api/login", function (req, res) {
  const ip = req.ip;
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (record.lockedUntil > now) {
    return res.status(429).json({ message: "Too many wrong tries. Wait 5 minutes." });
  }

  const password = req.body && req.body.password ? req.body.password : "";

  if (passwordMatches(password)) {
    loginAttempts.delete(ip);
    const token = crypto.randomBytes(32).toString("hex");
    sessions.add(token);
    res.setHeader(
      "Set-Cookie",
      "session=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"
    );
    return res.json({ message: "Logged in" });
  }

  record.count += 1;
  if (record.count >= 5) {
    record.lockedUntil = now + 5 * 60 * 1000;
    record.count = 0;
  }
  loginAttempts.set(ip, record);
  res.status(401).json({ message: "Wrong password." });
});

app.post("/api/logout", function (req, res) {
  const token = getCookie(req, "session");
  if (token) {
    sessions.delete(token);
  }
  res.setHeader(
      "Set-Cookie",
      "session=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800" + (req.secure ? "; Secure" : "")
    );
  res.json({ message: "Logged out" });
});

app.get("/api/me", function (req, res) {
  res.json({ loggedIn: isLoggedIn(req) });
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
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/map", function (req, res) {
  res.sendFile(path.join(__dirname, "map.html"));
});

app.get("/admin", function (req, res) {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.use("/uploads", express.static("uploads"));

// ---------- Receive a report ----------
app.post("/report", upload.single("photo"), function (req, res) {
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

  insertReport.run(req.file.filename, notes, lat, lng);
  console.log("Report saved:", req.file.filename);

  res.json({ message: "Report received. Thank you!" });
});

// ---------- Reports ----------
app.get("/api/reports", function (req, res) {
  res.json(getAllReports.all());
});

// Only a logged-in admin can change a status
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

app.listen(3000, function () {
  console.log("Server is running at http://localhost:3000");
});