// routes/auth.js
import express from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import { requireAuth, requireRole } from "../middleware/auth.js";
import sendEmailOtp from "../utils/sendEmailOtp.js";
import User from "../models/User.js";
import multer from "multer";
import path from "path";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";

const router = express.Router();

const adminEmails =
  process.env.ADMIN_EMAILS?.split(",").map((e) => e.trim().toLowerCase()) || [];

function assignAdminIfEligible(user) {
  if (!user || !user.email) return;
  const email = user.email.toLowerCase();
  if (adminEmails.includes(email)) {
    user.role = "admin";
  }
}


// Helper to create JWT
function createToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}
// ---------- Multer setup for avatar & banner ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadsDir = path.join(__dirname, "..", "uploads");

// diskStorage for different folders
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === "avatar") {
      cb(null, path.join(uploadsDir, "avatars"));
    } else if (file.fieldname === "banner") {
      cb(null, path.join(uploadsDir, "banners"));
    } else {
      cb(null, uploadsDir);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname); // .jpg, .png
    const base = file.fieldname; // avatar or banner
    cb(null, `${base}-${req.jwtUser.id}-${Date.now()}${ext}`);
  },
});

const upload = multer({ storage });

// ---------- existing auth routes (google, callback, me, etc.) ----------
// ... keep your existing google + callback + api/me + logout routes ...

// ---------- NEW: Update profile (name, bio, avatar, banner) ----------
router.put(
  "/api/profile",
  requireAuth,
  upload.fields([
    { name: "avatar", maxCount: 1 },
    { name: "banner", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const userId = req.jwtUser.id;
      const { name, bio } = req.body;

      const updateData = {};
      if (name) updateData.name = name;
      if (bio) updateData.bio = bio;

      if (req.files?.avatar?.[0]) {
        const avatarFile = req.files.avatar[0];
        updateData.avatar = `/uploads/avatars/${avatarFile.filename}`;
      }

      if (req.files?.banner?.[0]) {
        const bannerFile = req.files.banner[0];
        updateData.banner = `/uploads/banners/${bannerFile.filename}`;
      }

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $set: updateData },
        { new: true }
      ).select("-__v");

      res.json(updatedUser);
    } catch (err) {
      console.error("Profile update error:", err);
      res.status(500).json({ message: "Failed to update profile" });
    }
  }
);

// Login link
router.get("/", (req, res) => {
  res.send("<a href='/auth/google'>Login with Google</a>");
});

// Start Google OAuth
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "https://sensational-sfogliatella-fe6cfb.netlify.app/Login",
  }),
  async (req, res) => {
    try {
      // 👇 req.user is already the MongoDB User from passport.js
      const user = req.user;

      assignAdminIfEligible(user);
      await user.save();

      // Create JWT token
      const token = jwt.sign(
        { id: user._id.toString(), role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      // Save login cookie
      res.cookie("token", token, {
        httpOnly: true,
        secure: false, // true in prod with HTTPS
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // Check whether profile is complete (decide first redirect)
      const isProfileComplete = Boolean(user.avatar && user.bio);
      console.log("Profile completed:", isProfileComplete);

      if (!isProfileComplete) {
        // New / incomplete user → go to dashboard to fill details
        return res.redirect("https://sensational-sfogliatella-fe6cfb.netlify.app/Dashboard");
      }

      // Existing user with profile → go home
      return res.redirect("https://sensational-sfogliatella-fe6cfb.netlify.app/");
    } catch (err) {
      console.error("Google callback error:", err);
      return res.redirect("https://sensational-sfogliatella-fe6cfb.netlify.app/login");
    }
  }
);
router.post("/login", async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const normalizedEmail = email.toLowerCase();

    // 1️⃣ Find user
    const user = await User.findOne({ email: normalizedEmail });

    if (!user || !user.passwordHash) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // 2️⃣ Check password
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    
    assignAdminIfEligible(user);
    await user.save();

    // 3️⃣ Create JWT
    const token = createToken(user);

    // 4️⃣ Apply cookie expiry based on Remember Me
    const maxAge = rememberMe
      ? 30 * 24 * 60 * 60 * 1000 // 30 days
      : 24 * 60 * 60 * 1000;    // 1 day

    // 5️⃣ Save token cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // set true if HTTPS
      sameSite: "lax",
      maxAge,
    });


    // 6️⃣ Send response
    res.json({
      message: "Login successful",
      user,
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Login failed" });
  }
});


// POST /auth/register
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ message: "Name, email & password are required" });
    }

    const normalizedEmail = email.toLowerCase();

    let user = await User.findOne({ email: normalizedEmail });

    if (user && user.passwordHash && user.isVerified) {
      return res
        .status(400)
        .json({ message: "User already exists, please login" });
    }

    // 6-digit OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpExpiresAt = new Date(
      Date.now() +
      (Number(process.env.OTP_EXPIRE_MINUTES) || 10) * 60 * 1000
    );
    if (!user) {
      const passwordHash = await bcrypt.hash(password, 10);

      user = new User({
        name,
        email: normalizedEmail,
        passwordHash,
        otpCode: otp,
        otpExpiresAt,
        isVerified: false,
      });

      // 👑 set admin if email is in ADMIN_EMAILS
      assignAdminIfEligible(user);
      await user.save();
    } else {
      // Existing (maybe Google user) completing registration or resending OTP
      user.name = name;
      user.passwordHash = await bcrypt.hash(password, 10);
      user.otpCode = otp;
      user.otpExpiresAt = otpExpiresAt;
      user.isVerified = false;

      // 👑 ensure role updated too if needed
      assignAdminIfEligible(user);
      await user.save();
    }


    // Send OTP via email
    await sendEmailOtp(normalizedEmail, otp);

    return res.json({
      message: "OTP sent to your email address",
      email: user.email,
      // debugOtp: otp, // for local debugging only
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Registration failed" });
  }
});

// POST /auth/verify-otp
router.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const normalizedEmail = email.toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    if (!user.otpCode || !user.otpExpiresAt) {
      return res.status(400).json({ message: "No OTP requested" });
    }

    if (user.otpCode !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (user.otpExpiresAt < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    // Mark as verified
    assignAdminIfEligible(user);
    user.isVerified = true;
    user.otpCode = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    // Auto-login (set JWT cookie)
    const token = jwt.sign(
      { id: user._id.toString(), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // change to true in production with HTTPS
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      message: "Email verified & logged in",
      user,
    });
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ message: "Failed to verify OTP" });
  }
});
// POST /auth/logout
router.all("/logout", (req, res) => {
  res.clearCookie("token");

  if (req.logout) {
    req.logout(() => { });
  }

  return res.json({ message: "Logged out" });
});

// POST /auth/forgot-password
// POST /auth/forgot-password
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const normalizedEmail = email.toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    // don't reveal if user exists
    if (!user || !user.passwordHash) {
      return res
        .status(400)
        .json({ message: "If that email exists, an OTP has been sent" });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpExpiresAt = new Date(
      Date.now() + (Number(process.env.OTP_EXPIRE_MINUTES) || 10) * 60 * 1000
    );

    user.resetOtpCode = otp;
    user.resetOtpExpiresAt = otpExpiresAt;
    await user.save();

    await sendEmailOtp(normalizedEmail, otp);

    return res.json({
      message: "Password reset OTP sent to your email",
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Failed to start password reset" });
  }
});

// POST /auth/verify-reset-otp
router.post("/verify-reset-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const normalizedEmail = email.toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(400).json({ message: "Invalid OTP or email" });
    }

    if (!user.resetOtpCode || !user.resetOtpExpiresAt) {
      return res.status(400).json({ message: "No reset OTP requested" });
    }

    if (user.resetOtpCode !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (user.resetOtpExpiresAt < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    // ✅ OTP is valid – create short-lived reset token (NOT login token)
    const resetToken = jwt.sign(
      { id: user._id.toString(), purpose: "password-reset" },
      process.env.JWT_SECRET,
      { expiresIn: "15m" } // 15 minutes
    );

    return res.json({
      message: "OTP verified. You can now reset your password.",
      resetToken,
    });
  } catch (err) {
    console.error("Verify reset OTP error:", err);
    res.status(500).json({ message: "Failed to verify reset OTP" });
  }
});
// POST /auth/reset-password
router.post("/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ message: "Token and new password are required" });
    }

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    if (payload.purpose !== "password-reset") {
      return res.status(400).json({ message: "Invalid reset token" });
    }

    const user = await User.findById(payload.id);
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    user.passwordHash = await bcrypt.hash(password, 10);
    user.resetOtpCode = undefined;
    user.resetOtpExpiresAt = undefined;
    await user.save();

    return res.json({ message: "Password updated successfully. You can login now." });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// ========= ADMIN ROUTES =========

// GET all users (admin only)
router.get(
  "/api/admin/users",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const users = await User.find().select(
        "-passwordHash -otpCode -otpExpiresAt -__v"
      );
      res.json({ users });
    } catch (err) {
      console.error("Admin users list error:", err);
      res.status(500).json({ message: "Failed to load users" });
    }
  }
);

// PATCH: ban / unban user (admin only)
// PATCH: ban / unban user (admin only)
// PATCH: ban / unban user (admin only)
router.patch(
  "/api/admin/users/:id/ban",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { isBanned } = req.body;

      console.log("BAN ROUTE HIT:", { id, body: req.body });

      const target = await User.findById(id);
      if (!target) {
        return res.status(404).json({ message: "User not found" });
      }

      // ❌ never ban admins
      if (target.role === "admin") {
        return res
          .status(403)
          .json({ message: "Admin accounts cannot be banned." });
      }

      target.isBanned = !!isBanned;
      await target.save();

      console.log("BAN ROUTE SUCCESS:", {
        id: target._id.toString(),
        isBanned: target.isBanned,
      });

      return res.status(200).json({
        message: target.isBanned
          ? "User has been banned."
          : "User has been unbanned.",
        user: {
          _id: target._id,
          name: target.name,
          email: target.email,
          role: target.role,
          isBanned: target.isBanned,
        },
      });
    } catch (err) {
      console.error("Admin ban user error:", err);
      return res.status(500).json({
        message: "Failed to update user status",
        error: err.message,
      });
    }
  }
);


// DELETE a user (admin only) – hard delete
router.delete(
  "/api/admin/users/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;

      const target = await User.findById(id);
      if (!target) {
        return res.status(404).json({ message: "User not found" });
      }

      if (target.role === "admin") {
        return res
          .status(403)
          .json({ message: "Admin accounts cannot be removed." });
      }

      if (id === req.jwtUser.id) {
        return res
          .status(400)
          .json({ message: "You cannot delete your own account." });
      }

      await User.findByIdAndDelete(id);

      return res.json({ message: "User removed successfully." });
    } catch (err) {
      console.error("Admin delete user error:", err);
      res.status(500).json({ message: "Failed to remove user" });
    }
  }
);




// API: current logged-in user (JWT-based)
router.get("/api/me", requireAuth, async (req, res) => {
  const user = await User.findById(req.jwtUser.id).select("-__v");
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json(user);
});

// Example admin-only route
router.get(
  "/api/admin/secret",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    res.json({ message: "Welcome, admin! 🎩", user: req.jwtUser });
  }
);

export default router;
