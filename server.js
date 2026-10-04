require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = `http://localhost:${PORT}/auth/google/callback`;

app.use(express.json());
app.use(cookieParser());
// Serve the frontend (index.html, login.html, signup.html, etc.) from /public
app.use(express.static(path.join(__dirname, 'public')));

// ---------- "Database" setup ----------
// Plain JSON files instead of a native database module. This means
// `npm install` never has anything to compile — it works the same on
// Windows, Mac, and Linux with zero extra setup. Good for learning and
// small projects; swap for Postgres/MySQL later if you need something
// that scales to many simultaneous writes.
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const RESETS_FILE = path.join(DATA_DIR, 'password_resets.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(RESETS_FILE)) fs.writeFileSync(RESETS_FILE, '[]');

function readJSON(file) {
  const raw = fs.readFileSync(file, 'utf-8').trim();
  return raw ? JSON.parse(raw) : [];
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
function getUsers() { return readJSON(USERS_FILE); }
function saveUsers(users) { writeJSON(USERS_FILE, users); }
function getResets() { return readJSON(RESETS_FILE); }
function saveResets(resets) { writeJSON(RESETS_FILE, resets); }
function nextId(items) { return items.length ? Math.max(...items.map(i => i.id)) + 1 : 1; }
function findUserByEmail(email) {
  return getUsers().find(u => u.email.toLowerCase() === email.toLowerCase());
}

// ---------- Helpers ----------
function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function setAuthCookie(res, token) {
  // httpOnly means client-side JS can never read this cookie — safer than
  // storing the token in localStorage, since it can't be stolen by
  // malicious script on the page.
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired — please log in again' });
  }
}

// ---------- Routes: account ----------

// Create an account
app.post('/api/signup', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are all required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const users = getUsers();
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: 'An account with that email already exists' });
  }

  const user = {
    id: nextId(users),
    name,
    email,
    password_hash: bcrypt.hashSync(password, 10),
    provider: 'local',
    created_at: new Date().toISOString()
  };
  users.push(user);
  saveUsers(users);

  setAuthCookie(res, createToken(user));
  res.status(201).json({ user: { id: user.id, name: user.name, email: user.email } });
});

// Log in to an existing account
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = findUserByEmail(email);
  if (!user) {
    return res.status(401).json({ error: 'Incorrect email or password' });
  }
  if (user.provider === 'google') {
    return res.status(401).json({ error: "This account uses Google sign-in — use the Google button instead." });
  }
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Incorrect email or password' });
  }

  setAuthCookie(res, createToken(user));
  res.json({ user: { id: user.id, name: user.name, email: user.email } });
});

// Log out
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// Check who's currently logged in (used by the frontend on page load)
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, name: req.user.name, email: req.user.email } });
});

// ---------- Routes: password reset ----------

app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const user = findUserByEmail(email);

  // Always respond the same way whether or not the email exists —
  // this stops people from using this form to check who has an account.
  const genericResponse = {
    message: 'If an account exists for that email, a reset link has been sent.'
  };

  if (!user) return res.json(genericResponse);

  const resets = getResets();
  const token = crypto.randomBytes(32).toString('hex');
  resets.push({
    id: nextId(resets),
    user_id: user.id,
    token,
    expires_at: Date.now() + 60 * 60 * 1000, // 1 hour
    used: false
  });
  saveResets(resets);

  // No email service is wired up yet, so for now the reset link is printed
  // to the server's terminal. In production, send this link by email instead.
  const resetLink = `http://localhost:${PORT}/reset-password.html?token=${token}`;
  console.log(`\nPassword reset requested for ${email}`);
  console.log(`Reset link: ${resetLink}\n`);

  res.json(genericResponse);
});

app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ error: 'Missing token or new password' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const resets = getResets();
  const reset = resets.find(r => r.token === token);
  if (!reset || reset.used || reset.expires_at < Date.now()) {
    return res.status(400).json({ error: 'This reset link is invalid or has expired' });
  }

  const users = getUsers();
  const user = users.find(u => u.id === reset.user_id);
  if (!user) {
    return res.status(400).json({ error: 'This reset link is invalid or has expired' });
  }

  user.password_hash = bcrypt.hashSync(password, 10);
  saveUsers(users);

  reset.used = true;
  saveResets(resets);

  res.json({ message: 'Password updated — you can now log in with your new password.' });
});

// ---------- Routes: Google sign-in ----------
// Requires a free Google Cloud project — see README.md for setup steps.
// Until GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are set in .env, this
// route sends people back to the login page with a clear explanation
// instead of a broken redirect.

app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.redirect('/login.html?error=google_not_configured');
  }
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    prompt: 'select_account'
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/login.html?error=google_failed');

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('Google did not return an access token');

    const profileRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileRes.json(); // { email, name, sub, ... }

    let user = findUserByEmail(profile.email);
    if (!user) {
      const users = getUsers();
      user = {
        id: nextId(users),
        name: profile.name || profile.email,
        email: profile.email,
        password_hash: null,
        provider: 'google',
        google_id: profile.sub,
        created_at: new Date().toISOString()
      };
      users.push(user);
      saveUsers(users);
    }

    setAuthCookie(res, createToken(user));
    res.redirect('/index.html');
  } catch (err) {
    console.error('Google sign-in failed:', err.message);
    res.redirect('/login.html?error=google_failed');
  }
});

app.listen(PORT, () => {
  console.log(`KindredMade server running at http://localhost:${PORT}`);
});
