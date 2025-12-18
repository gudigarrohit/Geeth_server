// middleware/auth.js
import jwt from "jsonwebtoken";

export function requireAuth(req, res, next) {
  let token = null;

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    token = authHeader.slice(7);
  } else if (req.cookies?.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.jwtUser = payload; // { id, role }
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

export function requireRole(role) {
  return (req, res, next) => {
    if (!req.jwtUser || req.jwtUser.role !== role) {
      return res.status(403).json({ message: "Forbidden: insufficient role" });
    }
    next();
  };
}
