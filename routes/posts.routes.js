const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticateJWT } = require('./auth');

// Get recent posts
router.get('/recent', async (req, res) => {
  const [rows] = await db.query('SELECT posts.*,users.username FROM posts join users on posts.user_id=users.id ORDER BY posts.created_at DESC LIMIT 10');
  res.json(rows);
});

// Get random posts
router.get('/random', async (req, res) => {
  const [rows] = await db.query('SELECT posts.*,users.username FROM posts join users on posts.user_id=users.id ORDER BY rand() LIMIT 10');
  res.json(rows);
});

// Search posts
router.get('/search', async (req, res) => {
  const q = req.query.q;
  const [rows] = await db.query(
    'SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?',
    [`%${q}%`, `%${q}%`]
  );
  res.json(rows);
});

// Get user posts
router.get('/:id', async (req, res) => {
  const userId = req.params.id;

  const [rows] = await db.query('SELECT * FROM posts WHERE user_id = ?', [userId]);
  res.json(rows);
});

// Create new post
router.post('/', authenticateJWT, async (req, res) => {
  // Now req.user is available
  const { id,title, description } = req.body;
  

  await db.query(
    'INSERT INTO posts (user_id, title, content, likes) VALUES (?, ?, ?, ?)',
    [id, title, description, 0]
  );
  res.status(201).json({ message: 'Post created' });
});

// Update post (like/unlike)
router.post(`/:postId/like`, async (req, res) => {
  const postId = req.params.postId;
  const { userId } = req.body;

  const [rows] = await db.query(
    'select * from likes where post_id=? and user_id=?',
    [postId, userId]
  );
  if (!rows.length) {
    await db.query(
      'INSERT INTO likes (post_id, user_id) VALUES (?, ?)',
      [postId, userId]
    );
    await db.query(
      'UPDATE posts SET likes = likes + 1 WHERE id = ?',
      [postId]
    );
    const [post] = await db.query(
      'select * from posts where id=?',
      [postId]);
    res.status(201).json(post[0]);
  }
  else{
    await db.query(
      'delete from likes where post_id=? and user_id=?',
      [postId, userId]
    );
    await db.query(
      'UPDATE posts SET likes = likes - 1 WHERE id = ?',
      [postId]
    );
    const [post] = await db.query(
      'select * from posts where id=?',
      [postId]);
    res.status(201).json(post[0]);
  } 
});

module.exports = router;
