const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const app = express();

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

// ---------- See all reports (temporary, for testing) ----------
app.get("/api/reports", function (req, res) {
  res.json(getAllReports.all());
});

// ---------- Error handling ----------
app.use(function (err, req, res, next) {
  res.status(400).json({ message: err.message });
});

app.listen(3000, function () {
  console.log("Server is running at http://localhost:3000");
});