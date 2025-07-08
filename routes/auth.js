const express = require('express');
const router = express.Router();
const pool = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // <-- Add this
const rateLimit = require('express-rate-limit');

const JWT_SECRET = process.env.JWT_SECRET;

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 30* 60 * 1000, // 30 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many attempts, please try again later'
});

// Input validation middleware
const validateSignup = (req, res, next) => {
  const { fname, lname, username, email, pnumber, password1 } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRegex = /^\+?[1-9]\d{1,14}$/;

  if (!fname || !lname || !username || !email || !pnumber || !password1) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  if (!phoneRegex.test(pnumber)) {
    return res.status(400).json({ error: 'Invalid phone number format' });
  }

  if (password1.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  next();
};

// Check authentication
// router.get('/check-auth', (req, res) => {
//   if (req.isAuthenticated()) {
//     const { password, ...safeUser } = req.user;
//     res.json({ isAuthenticated: true, user: safeUser });
//   } else {
//     res.json({ isAuthenticated: false });
//   }
// });

// ✅ Fixed route path (added '/')
router.post('/signup', authLimiter, validateSignup, async (req, res) => {
  const { fname, lname, username, email, pnumber, password1 } = req.body;

  try {
    const [emailCheck] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    const [usernameCheck] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);

    if (emailCheck.length) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    if (usernameCheck.length) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password1, salt);

    const [result] = await pool.query(
      `INSERT INTO users (firstname, lastname, username, email, phone, password) VALUES (?, ?, ?, ?, ?, ?)`,
      [fname, lname, username, email, pnumber, hashedPassword]
    );

    const [newUserRows] = await pool.query(
      'SELECT id, username, firstname, lastname, email, phone FROM users WHERE id = ?',
      [result.insertId]
    );
    const newUser = newUserRows[0];
    if (!newUser) {
      return res.status(500).json({ error: 'User not found after registration' });
    }

    // Create JWT token
    const token = jwt.sign({ id: newUser.id, username: newUser.username }, JWT_SECRET, { expiresIn: '2h' });

    res.json({ success: true, user: newUser, token });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (!users || users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { password: _, ...userData } = user;

    // Create JWT token
    const token = jwt.sign({ id: userData.id, username: userData.username }, JWT_SECRET, { expiresIn: '10h' });

    res.json({ success: true, user: userData, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
router.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ error: 'Logout error' });
    res.json({ message: 'Logged out successfully' });
  });
});

// JWT authentication middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization || req.cookies.token;
  let token;

  // Support both Authorization header and cookie
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({ isAuthenticated: false, error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET || JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ isAuthenticated: false, error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Add check-auth route
router.get('/check-auth', authenticateJWT, (req, res) => {
  if (req.user) {
    res.json({ isAuthenticated: true, user: req.user });
  } else {
    res.json({ isAuthenticated: false });
  }
});


router.post('/checklogin', async (req, res) => {
  const email=req.body.email;

  if (!email) {
    return res.status(400).json({ ok: false, message: 'Email is required' });
  }

  try {
    // param‑placeholder is safe against SQL‑i
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (rows.length) {
      return res.json({ ok: true, isUserFound: true, user: rows[0] });
    }

    return res.json({ ok: true, isUserFound: false });
  } catch (err) {
    console.error('Database error:', err);
    return res
      .status(500)
      .json({ ok: false, message: 'Internal server error' });
  }
});

module.exports = {
  router,
  authenticateJWT
};
