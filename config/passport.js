// config/passport.js
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import User from "../models/User.js";

export default function setupPassport() {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:5000/auth/google/callback",
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          const avatar = profile.photos?.[0]?.value;
          const name = profile.displayName;

          let user = await User.findOne({ googleId: profile.id });

          if (!user) {
            const count = await User.countDocuments();
            const adminEmails = (process.env.ADMIN_EMAILS || "")
              .split(",")
              .map((e) => e.trim().toLowerCase())
              .filter(Boolean);

            const isAdminByEmail = email && adminEmails.includes(email.toLowerCase());
            const isFirstUser = count === 0;

            const role = isAdminByEmail || isFirstUser ? "admin" : "user";

            user = await User.create({
              googleId: profile.id,
              email,
              name,
              avatar,
              role,
            });

            console.log("👤 New user created:", user.email, "role:", user.role);
          }

          return done(null, user);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  // Store only user ID in session
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
}
