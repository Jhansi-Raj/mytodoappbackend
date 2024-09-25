// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const port = 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Database setup
const db = new sqlite3.Database('./mydatabase.db');

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users  (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT
    )`);

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      status TEXT,
      userId INTEGER,
      FOREIGN KEY (userId) REFERENCES users (id)
    )`);
});

// JWT secret key
const JWT_SECRET = 'your_super_secret_key_1234567890123456';

// Middleware for authenticating JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// User Signup
app.post('/api/auth/signup', (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`, [name, email, hashedPassword], function(err) {
    if (err) {
      return res.status(400).json({ message: 'User already exists' });
    }
    res.status(201).json({ message: 'User created' });
  });
});

// User Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Get user profile
app.get('/api/profile', authenticateJWT, (req, res) => {
  db.get(`SELECT id, name, email FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) {
      return res.sendStatus(404);
    }
    res.json(user);
  });
});

// Update user profile
app.put('/api/profile/update', authenticateJWT, (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = password ? bcrypt.hashSync(password, 10) : null;

  db.run(`UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?`, [name, email, hashedPassword, req.user.id], function(err) {
    if (err) {
      return res.sendStatus(400);
    }
    res.json({ message: 'Profile updated' });
  });
});

// Create Task
app.post('/api/tasks/create', authenticateJWT, (req, res) => {
  const { title, status = 'pending' } = req.body;
  
  db.run(`INSERT INTO tasks (title, status, userId) VALUES (?, ?, ?)`, [title, status, req.user.id], function(err) {
    if (err) {
      return res.sendStatus(400);
    }
    res.status(201).json({ message: 'Task created', id: this.lastID });
  });
});

// Update Tasks
// Update Task Status
app.put('/api/tasks/update/:id', authenticateJWT, (req, res) => {
    const { status } = req.body;
    const taskId = req.params.id;
  
    db.run(`UPDATE tasks SET status = ? WHERE id = ? AND userId = ?`, [status, taskId, req.user.id], function(err) {
      if (err) {
        console.error('Error updating task status:', err);
        return res.sendStatus(400);
      }
      if (this.changes === 0) {
        return res.sendStatus(404); // No task found for this user
      }
      res.json({ message: 'Task status updated' });
    });
  });
  

// Get Tasks
app.get('/api/tasks', authenticateJWT, (req, res) => {
  db.all(`SELECT * FROM tasks WHERE userId = ?`, [req.user.id], (err, tasks) => {
    if (err) {
      return res.sendStatus(400);
    }
    res.json(tasks);
  });
});

// Delete Task
app.delete('/api/tasks/delete/:id', authenticateJWT, (req, res) => {
  db.run(`DELETE FROM tasks WHERE id = ? AND userId = ?`, [req.params.id, req.user.id], function(err) {
    if (err || this.changes === 0) {
      return res.sendStatus(404);
    }
    res.json({ message: 'Task deleted' });
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
