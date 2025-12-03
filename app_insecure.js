const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = 3000;

// views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// insecure session config 
app.use(session({
  secret: 'Eugene',  // hard coded secret
  resave: true,
  saveUninitialized: true,
  cookie: {
    // no httponly, no secure and no samesite flags
  }
}));

// inject user into templates
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user;
  next();
});

app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.redirect('/dashboard');
});

// register with plaintext pass
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', (req, res) => {
  const { username, email, password, role } = req.body;

  const finalRole = role || 'user'; 

  db.run(
    `INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`,
    [username, email, password, finalRole], // password stored in plaintext
    function (err) {
      if (err) {
        console.error('Registration error:', err);
        return res.render('register', { error: 'Registration failed (possibly duplicate username/email).' });
      }
      res.redirect('/login');
    }
  );
});

// login with sqli vulnerability
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // user input sent directly into sql query
  const sql = `
    SELECT * FROM users
    WHERE username = '${username}' AND password = '${password}'
  `;

  db.get(sql, [], (err, user) => {
    if (err) {
      console.error('Login error:', err);
      return res.render('login', { error: 'Internal error' });
    }

    if (!user) {
      // generic error but still insecure due to sqli
      return res.render('login', { error: 'Invalid username or password' });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role
    };

    res.redirect('/dashboard');
  });
});

// dashboard with stored xss vulnerability
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  db.all(`
    SELECT posts.*, users.username
    FROM posts
    JOIN users ON posts.user_id = users.id
    ORDER BY posts.created_at DESC
  `, [], (err, posts) => {
    if (err) {
      console.error('Dashboard error:', err);
      return res.send('Error loading posts');
    }
    res.render('dashboard', { posts });
  });
});

// create post function that stores content unsanitised
app.get('/posts/create', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('create', { error: null });
});

app.post('/posts/create', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { content } = req.body;

  db.run(`
    INSERT INTO posts (user_id, content) VALUES (?, ?)
  `, [req.session.user.id, content], function (err) {
    if (err) {
      console.error('Create post error:', err);
      return res.render('create', { error: 'Failed to create post' });
    }
    res.redirect('/dashboard');
  });
});

// edit post (this is still vulnerable to stored xss on display)
app.get('/posts/edit/:id', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  db.get(`SELECT * FROM posts WHERE id = ?`, [req.params.id], (err, post) => {
    if (err || !post) return res.send('Post not found');

    if (post.user_id !== req.session.user.id) {
      return res.send('Not authorised');
    }

    res.render('create', { error: null, post });
  });
});

app.post('/posts/edit/:id', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const { content } = req.body;
  const id = req.params.id;

  db.get(`SELECT * FROM posts WHERE id = ?`, [id], (err, post) => {
    if (err || !post) return res.send('Post not found');

    if (post.user_id !== req.session.user.id) {
      return res.send('Not authorised');
    }

    db.run(`
      UPDATE posts SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    `, [content, id], (err2) => {
      if (err2) {
        console.error('Update error:', err2);
        return res.render('create', { error: 'Failed to update post', post });
      }
      res.redirect('/dashboard');
    });
  });
});

// delete post
app.post('/posts/delete/:id', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const id = req.params.id;
  const isAdmin = req.session.user.role === 'admin';

  if (isAdmin) {
    db.run(`DELETE FROM posts WHERE id = ?`, [id], () => res.redirect('/dashboard'));
  } else {
    db.run(`DELETE FROM posts WHERE id = ? AND user_id = ?`, [id, req.session.user.id], () => {
      res.redirect('/dashboard');
    });
  }
});

// reflected xss endpoint
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // reflect q in the EJS template
  res.render('search', { q });
});

// dom based XSS page
app.get('/domxss', (req, res) => {
  res.render('domxss');
});

// logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.listen(PORT, () => {
  console.log(`Insecure app listening at http://localhost:${PORT}`);
});
