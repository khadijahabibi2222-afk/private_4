require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ─── MongoDB Schema ───────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  passwordHash: { type: String, required: true },
  data: {
    type: mongoose.Schema.Types.Mixed,
    default: {
      income: [],
      expenses: [],
      goals: [],
      debts: [],
      openingBalance: { afn: 0, title: 'موجودی اولیه', cur: 'AFN', raw: 0 }
    }
  },
  config: {
    type: mongoose.Schema.Types.Mixed,
    default: { primaryCurrency: 'USD', rate: 88, rateLabel: 'بازار' }
  }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// ─── JWT Helper ───────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-secret-key-2024';
const JWT_EXPIRES = '30d';

function signToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'توکن معتبر نیست' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'توکن منقضی یا نامعتبر است' });
  }
}

// ─── Seed Default Users ───────────────────────────────────────────────────────
async function seedUsers() {
  const count = await User.countDocuments();
  if (count === 0) {
    const defaultPassword = await bcrypt.hash('1234', 10);
    await User.insertMany([
      { username: 'admin', passwordHash: defaultPassword },
      { username: 'کاربر', passwordHash: defaultPassword }
    ]);
    console.log('✓ Default users created: admin/1234 and کاربر/1234');
  }
}

// ─── DB Readiness Check ───────────────────────────────────────────────────────
app.use('/api', (req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'در حال اتصال به پایگاه داده... لطفاً دوباره تلاش کنید' });
  }
  next();
});

// ─── Routes: Auth ─────────────────────────────────────────────────────────────
// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'نام کاربری و رمز الزامی است' });

    const user = await User.findOne({ username: username.trim() });
    if (!user) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

    res.json({ token: signToken(user.username), username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// POST /api/auth/change  — change username and/or password
app.post('/api/auth/change', requireAuth, async (req, res) => {
  try {
    const { newUsername, newPassword } = req.body;
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });

    if (newUsername && newUsername.trim() !== user.username) {
      const exists = await User.findOne({ username: newUsername.trim() });
      if (exists) return res.status(409).json({ error: 'این نام کاربری قبلاً وجود دارد' });
      user.username = newUsername.trim();
    }
    if (newPassword) {
      user.passwordHash = await bcrypt.hash(newPassword, 10);
    }
    if (!newUsername && !newPassword)
      return res.status(400).json({ error: 'هیچ تغییری ارسال نشده' });

    await user.save();
    res.json({ token: signToken(user.username), username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// ─── Routes: Finance Data ─────────────────────────────────────────────────────
// GET /api/data
app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username }).lean();
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
    res.json(user.data || {});
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// PUT /api/data
app.put('/api/data', requireAuth, async (req, res) => {
  try {
    await User.updateOne(
      { username: req.user.username },
      { $set: { data: req.body } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// GET /api/config
app.get('/api/config', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username }).lean();
    if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
    res.json(user.config || { primaryCurrency: 'USD', rate: 88, rateLabel: 'بازار' });
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// PUT /api/config
app.put('/api/config', requireAuth, async (req, res) => {
  try {
    await User.updateOne(
      { username: req.user.username },
      { $set: { config: req.body } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'خطای سرور' });
  }
});

// ─── SPA Fallback ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error('✗ MONGO_URI environment variable is not set. Please add it in your Render dashboard.');
  process.exit(1);
}

// Start the HTTP server immediately so Render can detect the open port
app.listen(PORT, () => console.log(`✓ Server running on port ${PORT}`));

// Connect to MongoDB after server is already listening
mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('✓ MongoDB connected');
    await seedUsers();
  })
  .catch(err => {
    console.error('✗ MongoDB connection failed:', err.message);
    // Do NOT call process.exit(1) here — keep server alive so Render doesn't crash-loop
    // Mongoose will automatically retry the connection
  });

// Handle MongoDB disconnection gracefully
mongoose.connection.on('disconnected', () => {
  console.warn('⚠ MongoDB disconnected. Attempting to reconnect...');
});
mongoose.connection.on('reconnected', () => {
  console.log('✓ MongoDB reconnected');
});
