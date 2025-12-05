const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const helmet = require('helmet');
const csurf = require('csurf');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
const PORT = 3001;

// views 
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// middleware (with helmet)
app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// scure session config
app.use(session({
  secret: 'change_this_to_a_long_random_string',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 20 * 60 * 1000 // 20 mins
  }
}));

// csrf protection (with csurf)
app.use(csurf());

// global variables
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.csrfToken = req.csrfToken();
  next();
});

// logging helper
function logAction(userId, action, details, ip) {
  db.run(
    `INSERT INTO logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)`,
    [userId || null, action, details || '', ip || ''],
    (err) => {
      if (err) console.error('Log error:', err);
    }
  );
}

// auth
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    logAction(req.session.user ? req.session.user.id : null, 'UNAUTHORISED_ADMIN_ACCESS', 'Attempted admin action', req.ip);
    return res.status(403).send('Forbidden');
  }
  next();
}

// home
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.redirect('/dashboard');
});

// register with hashed password, no role selection
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.render('register', { error: 'All fields are required.' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')`,
      [username, email, hash],
      function (err) {
        if (err) {
          console.error('Registration error:', err);
          return res.render('register', { error: 'Registration failed (possibly duplicate username/email).' });
        }
        logAction(this.lastID, 'REGISTER', 'New user registered', req.ip);
        res.redirect('/login');
      }
    );
  } catch (err) {
    console.error('Hash error:', err);
    res.render('register', { error: 'Internal error during registration.' });
  }
});

// login with parameterised query + bcrypt compare
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (!username || !password) {
    return res.render('login', { error: 'Username and password required.' });
  }

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err) {
        console.error('Login error:', err);
        return res.render('login', { error: 'Internal error.' });
      }

      if (!user) {
        logAction(null, 'LOGIN_FAILED', `Username not found: ${username}`, ip);
        return res.render('login', { error: 'Invalid username or password.' });
      }

      try {
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          logAction(user.id, 'LOGIN_FAILED', 'Wrong password', ip);
          return res.render('login', { error: 'Invalid username or password.' });
        }

        // regen session to prevent fixation
        req.session.regenerate((err2) => {
          if (err2) {
            console.error('Session regen error:', err2);
            return res.render('login', { error: 'Internal error.' });
          }

          req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role
          };
          logAction(user.id, 'LOGIN_SUCCESS', 'User logged in', ip);
          res.redirect('/dashboard');
        });
      } catch (e) {
        console.error('Bcrypt error:', e);
        res.render('login', { error: 'Internal error.' });
      }
    }
  );
});

// dashboard that still shows posts, but templates will escape
app.get('/dashboard', requireAuth, (req, res) => {

if (!req.query.welcome) {
    const defaultWelcome = `A day without ${req.session.user.username}, is a bad day!`;
    const encoded = encodeURIComponent(defaultWelcome);
    return res.redirect('/dashboard?welcome=' + encoded);
  }

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

// create post with basic validation / content stored but safely encoded on output
app.get('/posts/create', requireAuth, (req, res) => {
  res.render('create', { error: null, post: null });
});

app.post('/posts/create', requireAuth, (req, res) => {
  const { content } = req.body;
  const userId = req.session.user.id;

  if (!content || content.length === 0) {
    return res.render('create', { error: 'Content cannot be empty.', post: null });
  }

  db.run(
    `INSERT INTO posts (user_id, content) VALUES (?, ?)`,
    [userId, content],
    function (err) {
      if (err) {
        console.error('Create post error:', err);
        return res.render('create', { error: 'Failed to create post.', post: null });
      }
      logAction(userId, 'CREATE_POST', `Post id ${this.lastID}`, req.ip);
      res.redirect('/dashboard');
    }
  );
});

// edit posts with validation and logging
app.get('/posts/edit/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const userId = req.session.user.id;

  db.get(`SELECT * FROM posts WHERE id = ?`, [id], (err, post) => {
    if (err || !post) return res.send('Post not found');

    if (post.user_id !== userId) {
      logAction(userId, 'UNAUTHORISED_EDIT_ATTEMPT', `Post id ${id}`, req.ip);
      return res.status(403).send('Not authorised');
    }

    res.render('create', { error: null, post });
  });
});

app.post('/posts/edit/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const { content } = req.body;
  const userId = req.session.user.id;

  if (!content) {
    return res.render('create', { error: 'Content cannot be empty.', post: { id, content } });
  }

  db.get(`SELECT * FROM posts WHERE id = ?`, [id], (err, post) => {
    if (err || !post) return res.send('Post not found');

    if (post.user_id !== userId) {
      logAction(userId, 'UNAUTHORISED_EDIT_ATTEMPT', `Post id ${id}`, req.ip);
      return res.status(403).send('Not authorised');
    }

    db.run(
      `UPDATE posts SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [content, id],
      (err2) => {
        if (err2) {
          console.error('Update error:', err2);
          return res.render('create', { error: 'Failed to update post.', post });
        }
        logAction(userId, 'EDIT_POST', `Post id ${id}`, req.ip);
        res.redirect('/dashboard');
      }
    );
  });
});

// delete post with admin check
app.post('/posts/delete/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const userId = req.session.user.id;
  const isAdmin = req.session.user.role === 'admin';

  if (isAdmin) {
    db.run(`DELETE FROM posts WHERE id = ?`, [id], (err) => {
      if (!err) logAction(userId, 'ADMIN_DELETE_POST', `Post id ${id}`, req.ip);
      res.redirect('/dashboard');
    });
  } else {
    db.run(`DELETE FROM posts WHERE id = ? AND user_id = ?`, [id, userId], (err) => {
      if (!err) logAction(userId, 'DELETE_POST', `Post id ${id}`, req.ip);
      res.redirect('/dashboard');
    });
  }
});

// search / reflected input is html escaped in template
app.get('/search', requireAuth, (req, res) => {
  const q = req.query.q || '';
  res.render('search', { q });
});

// dom xss / use textContent not innerHTML
app.get('/domxss', requireAuth, (req, res) => {
  res.render('domxss');
});

// logout with logging
app.get('/logout', (req, res) => {
  const uid = req.session.user ? req.session.user.id : null;
  req.session.destroy(() => {
    if (uid) logAction(uid, 'LOGOUT', 'User logged out', '');
    res.redirect('/login');
  });
});

// CSRF error handler for nicer message
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.warn('CSRF token error', err);
    return res.status(403).send('Form tampered with.');
  }
  next(err);
});

app.listen(PORT, () => {
  console.log(`Secure app listening at http://localhost:${PORT}`);
});
