import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    googleId: {
      type: String,
      // unique: true,          // either comment this
      // or do unique + sparse with an index below
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      index: true,
    },
    name: { type: String, required: true },
    
    passwordHash: { type: String },
    isVerified: { type: Boolean, default: false },
    otpCode: { type: String },
    otpExpiresAt: { type: Date },
    // 🔹 password reset OTP
    resetOtpCode: { type: String },
    resetOtpExpiresAt: { type: Date },
    avatar: { type: String },
    banner: { type: String },
    bio: { type: String, maxlength: 500 },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
   // 👇 NEW: soft ban flag
    isBanned: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// If you want googleId to be unique ONLY when present:
userSchema.index({ googleId: 1 }, { unique: true, sparse: true });

const User = mongoose.model("User", userSchema);
export default User;
