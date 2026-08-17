const jwt = require('jsonwebtoken');

// Checkpoint 1: Verify the user is logged in via their JWT cookie token
const protectRoute = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: 'Access Denied. Please log in first.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; // Attach user metadata (id and role) to the request stream
    next(); // Pass control over to the next route file
  } catch (err) {
    res.status(400).json({ error: 'Invalid or expired session token.' });
  }
};

// Checkpoint 2: Block unauthorized roles from restricted endpoints
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access Forbidden. Unauthorized role.' });
    }
    next();
  };
};

module.exports = { protectRoute, authorizeRoles };
