const jwt = require("jsonwebtoken");
const User = require("../models/user");

async function requireAuth(req, res, next) {
  try {
    // Read token from the "Authorization" cookie
    const token = req.cookies.token;

    // Verify and decode the token
    const decoded = jwt.verify(token, process.env.SECRET);

    // check expiration
    if(Date.now() > decoded.expiresIn) return res.sendStatus(401);

    // Find the user using the decoded userId
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    // Attach the user to the request object
    req.user = user;

    // Continue to the next middleware
    console.log("In middleware");
    next();
  } catch (error) {
    // Handle token verification errors
    return res.status(401).json({ error: "Invalid token" });
  }
}

module.exports = requireAuth;