const express = require("express");
const mongoose = require("mongoose");
const fs = require("fs");
const cors = require("cors");
const app = express();

app.use(express.json());
app.use(cors());

/* ==============================
   1️⃣ CONNECT TO DATABASE
============================== */

mongoose
  .connect(
    "mongodb+srv://priyadharshinip0611_db_user:dharshini@cluster0.58ux0zq.mongodb.net/cveDB?retryWrites=true&w=majority",
  )
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("DB Error:", err));

/* ==============================
   2️⃣ CREATE SCHEMA (DB STRUCTURE)
============================== */

const vulnerabilitySchema = new mongoose.Schema({
  cveId: { type: String, unique: true, required: true },
  description: String,
  publishedDate: Date,
  baseScore: Number,
  severity: String,
});

const Vulnerability = mongoose.model("Vulnerability", vulnerabilitySchema);

/* ==============================
   3️⃣ PARSE JSON & STORE IN DB
   (PS Requirement 1 & 2)
============================== */

app.get("/import", async (req, res) => {
  try {
    // Read JSON file
    const rawData = fs.readFileSync("data.json");
    const jsonData = JSON.parse(rawData);

    let insertedCount = 0;

    for (let item of jsonData.vulnerabilities) {
      const cveId = item.cve?.id;
      const description = item.cve?.descriptions?.[0]?.value;
      const publishedDate = item.published;
      const baseScore = item.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
      const severity = item.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity;

      if (!cveId) continue;

      try {
        await Vulnerability.create({
          cveId,
          description,
          publishedDate,
          baseScore,
          severity,
        });
        insertedCount++;
      } catch (err) {
        // Skip duplicates
      }
    }

    res.status(200).json({
      message: "Data Imported Successfully",
      inserted: insertedCount,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ==============================
   4️⃣ CREATE REST ENDPOINTS
   (PS Requirement 3)
============================== */

/* Get all vulnerabilities */
app.get("/vulnerabilities", async (req, res) => {
  try {
    const data = await Vulnerability.find();
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* Get vulnerability by CVE ID */
app.get("/vulnerabilities/:id", async (req, res) => {
  try {
    const data = await Vulnerability.findOne({ cveId: req.params.id });

    if (!data) {
      return res.status(404).json({ message: "Vulnerability Not Found" });
    }

    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* Filter by severity */
app.get("/filter", async (req, res) => {
  try {
    const severity = req.query.severity;

    if (!severity) {
      return res.status(400).json({ message: "Severity query required" });
    }

    const data = await Vulnerability.find({ severity });
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ==============================
   START SERVER
============================== */

app.listen(8000, () => {
  console.log("🚀 Server running on http://localhost:5000");
});
