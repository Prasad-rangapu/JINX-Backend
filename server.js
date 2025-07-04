const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const cors = require('cors');
const session = require('express-session');
const createError = require('http-errors');
const postRoutes=require('./routes/posts.routes');
const auth = require('./routes/auth');
const contactRoutes = require('./routes/contact');
// const profileRoutes = require('./routes/profile.routes');

const app = express();

// Middleware
app.use(logger('dev'));
app.use(cors({
  origin: 'https://prasad-rangapu.github.io',
  credentials: true, // if you use cookies/auth
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: '2560',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set to true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.set('trust proxy', 1);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));



// API routes
app.use('/api/auth', auth.router);
app.use('/api/contact', contactRoutes);
// app.use('/api/profile', profileRoutes);
app.use('/api/posts', postRoutes);


// 404 handler
app.use((req, res, next) => next(createError(404)));

// Error handler
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({ error: err.message });
});
const PORT = process.env.PORT || 3000;
// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;
