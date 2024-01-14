const User = require("../models/user");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

async function signup(req, res) {
  try {
    const { email, password } = req.body;

    // Check if the email already exists in the database
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    await User.create({ email, password: hashedPassword });

    res.sendStatus(200);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
}

async function login(req, res) {
  try { 
    const { email, password } = req.body;

    // Find the user with the provided email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare the password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create a JWT token
    const expiresIn = Date.now() + 1000 * 60 * 60 * 24; 
    const token = jwt.sign({ userId: user._id, expiresIn }, process.env.SECRET);

    // Set the token as a cookie
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000, // 1 hour in milliseconds
    });

    res.sendStatus(200);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
}

function logout(req, res) {
  // Clear the token cookie
  res.clearCookie('Authorization');
  res.sendStatus(200);
}

function checkAuth(req, res) {
  try {
    res.sendStatus(200);
  } catch (error) {
    res.sendStatus(400)
  }
 
}

module.exports = {
  signup,
  login,
  logout,
  checkAuth,
};