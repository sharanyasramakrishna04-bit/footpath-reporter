const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const app = express();

// Make a folder called "uploads" if it doesn't exist
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Rules for saving photos
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

// Show the home page
app.get("/", function (req, res) {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Receive a report
app.post("/report", upload.single("photo"), function (req, res) {
  console.log("New report received:");
  console.log("Notes:", req.body.notes);
  console.log("Latitude:", req.body.latitude);
  console.log("Longitude:", req.body.longitude);
  console.log("Photo saved as:", req.file ? req.file.filename : "no photo");

  res.json({ message: "Report received. Thank you!" });
});

app.listen(3000, function () {
  console.log("Server is running at http://localhost:3000");
});
