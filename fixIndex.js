// fixIndex.js
import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

(async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      dbName: "geeta-music",
    });

    console.log("🔧 Connected to Mongo, dropping index googleId_1...");

    const result = await mongoose.connection
      .db
      .collection("users")
      .dropIndex("googleId_1");

    console.log("✅ Index removed:", result);
  } catch (err) {
    console.error("⚠️ Error dropping index:", err.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
})();
