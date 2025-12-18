import express from "express";
import cors from "cors";
import session from "express-session";
import cookieParser from "cookie-parser";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import passport from "passport";
import { connectDB } from "./config/db.js";
import setupPassport from "./config/passport.js";
import authRoutes from "./routes/auth.js";
import dotenv from "dotenv";


dotenv.config(); // 👈 load .env BEFORE using process.env

// ES module __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://your-vercel-app.vercel.app"
    ],
    credentials: true,
  })
);


app.use(express.json());
app.use(cookieParser());


// ✅ connect to Mongo
await connectDB();

// ✅ Sessions (for Passport)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret",
    resave: false,
    saveUninitialized: false,
  })
);

// ✅ Passport
setupPassport();
app.use(passport.initialize());
app.use(passport.session());


// after app initialization:
const uploadsPath = path.join(__dirname, "uploads");
app.use("/uploads", express.static(uploadsPath));

// -------- AUTH ROUTES ----------
app.use("/auth", authRoutes);

// ✅ songs directory (absolute path)
const songsDir = path.join(process.cwd(), "songs");

// ✅ Helper function: safely read a JSON file
function readJsonSync(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf-8");
  return JSON.parse(raw);
}

// --------------------
// 📀 Route: GET /api/albums
// --------------------
app.get("/api/albums", (req, res) => {
  const albumsPath = path.join(songsDir, "albums.json");

  if (!fs.existsSync(albumsPath)) {
    console.error("❌ albums.json not found at", albumsPath);
    return res.status(404).json({ error: "albums.json not found" });
  }

  try {
    const json = readJsonSync(albumsPath);
    return res.json(json);
  } catch (err) {
    console.error("⚠️ Error reading albums.json:", err);
    return res.status(500).json({ error: "Failed to read albums.json" });
  }
});

// --------------------
// 🎵 Route: GET /api/songs/:folder
// --------------------
app.get("/api/songs/:folder", (req, res) => {
  const folder = req.params.folder;
  const filePath = path.join(songsDir, folder, "songs.json");

  if (!fs.existsSync(filePath)) {
    console.error(`❌ songs.json not found for folder: ${folder}`, filePath);
    return res.status(404).json({ error: `songs.json not found for ${folder}` });
  }

  try {
    const json = readJsonSync(filePath);
    return res.json(json);
  } catch (err) {
    console.error(`⚠️ Error reading songs.json in ${folder}:`, err);
    return res.status(500).json({ error: `Failed to read songs for ${folder}` });
  }
});

// --------------------
// 🎧 Route: GET /api/songs
// Aggregates all albums
// --------------------
app.get("/api/songs", (req, res) => {
  try {
    if (!fs.existsSync(songsDir)) {
      return res.status(404).json({ error: "songs directory not found" });
    }

    const entries = fs.readdirSync(songsDir, { withFileTypes: true });
    const allSongs = [];

    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      const folder = ent.name;
      const songJsonPath = path.join(songsDir, folder, "songs.json");

      if (!fs.existsSync(songJsonPath)) continue;

      try {
        const songsJson = readJsonSync(songJsonPath);
        const songsArray = songsJson.songs || songsJson;

        for (const s of songsArray) {
          allSongs.push({
            name: s.name || s.title || s.file || "Unknown",
            file: s.file || s.filename || null,
            album: folder,
            cover: `/songs/${folder}/cover.jpeg`,
            filePath: s.file ? `/songs/${folder}/${s.file}` : null,
            _raw: s,
          });
        }
      } catch (innerErr) {
        console.error(`⚠️ Error parsing songs.json in ${folder}:`, innerErr);
      }
    }

    return res.json({ songs: allSongs });
  } catch (err) {
    console.error("⚠️ Error scanning songs folder:", err);
    return res.status(500).json({ error: "Failed to aggregate songs" });
  }
});

// --------------------
// 🖼️ Static file server for covers and mp3s
// ✅ Works for both Windows and Linux
// --------------------
app.use("/songs", express.static(songsDir, {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".mp3")) {
      res.setHeader("Content-Type", "audio/mpeg");
    }
  },
}));
const PORT = process.env.PORT || 5000;
// --------------------
// 🚀 Start Server
// --------------------
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log("🎵 Songs directory:", songsDir);
});
