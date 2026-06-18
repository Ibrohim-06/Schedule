const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(express.json());
app.use(cors());

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme_secret_key';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

let db;
MongoClient.connect(MONGO_URI)
  .then(client => {
    db = client.db('command_center');
    console.log('Connected to MongoDB');
  })
  .catch(err => console.error('MongoDB connection error:', err));

// ── Auth middleware ──────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Auth routes ──────────────────────────────────────

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: 'All fields required' });
    const existing = await db.collection('users').findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 10);
    const result = await db.collection('users').insertOne({ email, password: hash, name, provider: 'email', createdAt: new Date() });
    const token = jwt.sign({ userId: result.insertedId, email, name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { email, name } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.collection('users').findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ userId: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { email: user.email, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Google Login
app.post('/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;
    let user = await db.collection('users').findOne({ email });
    if (!user) {
      const result = await db.collection('users').insertOne({ email, name, googleId, provider: 'google', createdAt: new Date() });
      user = { _id: result.insertedId, email, name };
    }
    const token = jwt.sign({ userId: user._id, email, name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { email, name } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Habits ───────────────────────────────────────────
app.get('/habits', authMiddleware, async (req, res) => {
  const habits = await db.collection('habits').find({ userId: req.user.userId.toString() }).toArray();
  res.json(habits);
});

app.post('/habits', authMiddleware, async (req, res) => {
  const { name } = req.body;
  const result = await db.collection('habits').insertOne({ userId: req.user.userId.toString(), name, streak: 0, createdAt: new Date() });
  res.json({ _id: result.insertedId, name, streak: 0 });
});

app.put('/habits/:id', authMiddleware, async (req, res) => {
  const { streak } = req.body;
  await db.collection('habits').updateOne({ _id: new ObjectId(req.params.id), userId: req.user.userId.toString() }, { $set: { streak } });
  res.json({ success: true });
});

app.delete('/habits/:id', authMiddleware, async (req, res) => {
  await db.collection('habits').deleteOne({ _id: new ObjectId(req.params.id), userId: req.user.userId.toString() });
  res.json({ success: true });
});

// ── Habit completions (per day) ──────────────────────
app.get('/habit-done/:date', authMiddleware, async (req, res) => {
  const doc = await db.collection('habit_done').findOne({ userId: req.user.userId.toString(), date: req.params.date });
  res.json(doc?.done || {});
});

app.post('/habit-done/:date', authMiddleware, async (req, res) => {
  const { done } = req.body;
  await db.collection('habit_done').updateOne(
    { userId: req.user.userId.toString(), date: req.params.date },
    { $set: { done } },
    { upsert: true }
  );
  res.json({ success: true });
});

// ── Expenses ─────────────────────────────────────────
app.get('/expenses/:date', authMiddleware, async (req, res) => {
  const doc = await db.collection('expenses').findOne({ userId: req.user.userId.toString(), date: req.params.date });
  res.json(doc?.items || []);
});

app.post('/expenses/:date', authMiddleware, async (req, res) => {
  const { items } = req.body;
  await db.collection('expenses').updateOne(
    { userId: req.user.userId.toString(), date: req.params.date },
    { $set: { items } },
    { upsert: true }
  );
  res.json({ success: true });
});

// ── Budget ───────────────────────────────────────────
app.get('/budget', authMiddleware, async (req, res) => {
  const doc = await db.collection('budgets').findOne({ userId: req.user.userId.toString() });
  res.json({ budget: doc?.budget || 50 });
});

app.post('/budget', authMiddleware, async (req, res) => {
  const { budget } = req.body;
  await db.collection('budgets').updateOne(
    { userId: req.user.userId.toString() },
    { $set: { budget } },
    { upsert: true }
  );
  res.json({ success: true });
});

// ── Time blocks ──────────────────────────────────────
app.get('/timeblocks', authMiddleware, async (req, res) => {
  const doc = await db.collection('timeblocks').findOne({ userId: req.user.userId.toString() });
  res.json(doc?.blocks || []);
});

app.post('/timeblocks', authMiddleware, async (req, res) => {
  const { blocks } = req.body;
  await db.collection('timeblocks').updateOne(
    { userId: req.user.userId.toString() },
    { $set: { blocks } },
    { upsert: true }
  );
  res.json({ success: true });
});

// ── Time block completions (per day) ─────────────────
app.get('/time-done/:date', authMiddleware, async (req, res) => {
  const doc = await db.collection('time_done').findOne({ userId: req.user.userId.toString(), date: req.params.date });
  res.json(doc?.done || {});
});

app.post('/time-done/:date', authMiddleware, async (req, res) => {
  const { done } = req.body;
  await db.collection('time_done').updateOne(
    { userId: req.user.userId.toString(), date: req.params.date },
    { $set: { done } },
    { upsert: true }
  );
  res.json({ success: true });
});

// ── News read (per day) ──────────────────────────────
app.get('/news-read/:date', authMiddleware, async (req, res) => {
  const doc = await db.collection('news_read').findOne({ userId: req.user.userId.toString(), date: req.params.date });
  res.json(doc?.read || {});
});

app.post('/news-read/:date', authMiddleware, async (req, res) => {
  const { read } = req.body;
  await db.collection('news_read').updateOne(
    { userId: req.user.userId.toString(), date: req.params.date },
    { $set: { read } },
    { upsert: true }
  );
  res.json({ success: true });
});

// ── Streak ───────────────────────────────────────────
app.get('/streak', authMiddleware, async (req, res) => {
  const doc = await db.collection('streaks').findOne({ userId: req.user.userId.toString() });
  res.json(doc?.streak || { count: 0, lastDate: '' });
});

app.post('/streak', authMiddleware, async (req, res) => {
  const { streak } = req.body;
  await db.collection('streaks').updateOne(
    { userId: req.user.userId.toString() },
    { $set: { streak } },
    { upsert: true }
  );
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
