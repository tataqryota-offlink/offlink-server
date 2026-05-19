// ============================================================
// OFFLINK SERVER — Backend API
// ============================================================

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const { Pool } = require('pg');
const rateLimit    = require('express-rate-limit');

const app  = express();
const port = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet());
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────

// Global — semua endpoint max 100 request/menit per IP
const globalLimiter = rateLimit({
  windowMs : 60 * 1000,
  max      : 100,
  message  : { error: 'Terlalu banyak request. Coba lagi dalam 1 menit.' },
});
app.use(globalLimiter);

// TX check — max 30 request/menit per IP
const txLimiter = rateLimit({
  windowMs : 60 * 1000,
  max      : 30,
  message  : { error: 'Terlalu banyak percobaan scan. Coba lagi dalam 1 menit.' },
});

// Device register — max 5 request/jam per IP (anti spam registrasi)
const registerLimiter = rateLimit({
  windowMs : 60 * 60 * 1000,
  max      : 5,
  message  : { error: 'Terlalu banyak pendaftaran perangkat. Coba lagi dalam 1 jam.' },
});

// ✅ FIX 1: nonceLimiter DITAMBAHKAN — sebelumnya tidak ada, menyebabkan server crash
const nonceLimiter = rateLimit({
  windowMs : 60 * 1000,
  max      : 50,
  message  : { error: 'Terlalu banyak request nonce. Coba lagi dalam 1 menit.' },
});

// ─────────────────────────────────────────────
// DATABASE
// ─────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ─────────────────────────────────────────────
// INIT DATABASE — buat tabel kalau belum ada
// ─────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocked_devices (
      device_id TEXT PRIMARY KEY,
      blocked_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS devices (
      id           SERIAL PRIMARY KEY,
      device_id    TEXT UNIQUE NOT NULL,
      public_key   TEXT NOT NULL,
      created_at   TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id           SERIAL PRIMARY KEY,
      tx_id        TEXT UNIQUE NOT NULL,
      sender_id    TEXT NOT NULL,
      receiver_id  TEXT NOT NULL,
      amount       BIGINT NOT NULL,
      nonce        BIGINT NOT NULL,
      hash         TEXT NOT NULL,
      status       TEXT DEFAULT 'completed',
      created_at   TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS used_tx_ids (
      tx_id        TEXT PRIMARY KEY,
      used_at      TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS nonces (
      device_id    TEXT PRIMARY KEY,
      last_nonce   BIGINT DEFAULT 0,
      updated_at   TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ Database tables ready');
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'OFFLINK Server Running', time: new Date() });
});

// 1. DAFTARKAN PERANGKAT
app.post('/device/register', registerLimiter, async (req, res) => {
  const { deviceId, publicKey } = req.body;
  if (!deviceId || !publicKey)
    return res.status(400).json({ error: 'deviceId dan publicKey wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO devices (device_id, public_key)
       VALUES ($1, $2)
       ON CONFLICT (device_id) DO UPDATE SET public_key = $2`,
      [deviceId, publicKey]
    );
    res.json({ success: true, message: 'Perangkat terdaftar' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 2. CEK DAN SIMPAN NONCE — anti double spend
app.post('/nonce/verify', nonceLimiter, async (req, res) => {
  const { deviceId, nonce } = req.body;
  if (!deviceId || nonce === undefined)
    return res.status(400).json({ error: 'deviceId dan nonce wajib diisi' });
  try {
    const result = await pool.query(
      'SELECT last_nonce FROM nonces WHERE device_id = $1',
      [deviceId]
    );
    if (result.rows.length > 0) {
      const lastNonce = result.rows[0].last_nonce;
      if (nonce <= lastNonce)
        return res.status(409).json({ error: 'Nonce sudah dipakai — double spend terdeteksi' });
    }
    await pool.query(
      `INSERT INTO nonces (device_id, last_nonce, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (device_id) DO UPDATE SET last_nonce = $2, updated_at = NOW()`,
      [deviceId, nonce]
    );
    res.json({ success: true, message: 'Nonce valid' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 3. CEK DAN TANDAI TX ID — anti double scan
app.post('/tx/check', txLimiter, async (req, res) => {
  const { txId } = req.body;
  if (!txId)
    return res.status(400).json({ error: 'txId wajib diisi' });
  try {
    const result = await pool.query(
      'SELECT tx_id FROM used_tx_ids WHERE tx_id = $1',
      [txId]
    );
    if (result.rows.length > 0)
      return res.status(409).json({ error: 'Transaksi sudah pernah digunakan' });
    await pool.query(
      'INSERT INTO used_tx_ids (tx_id) VALUES ($1)',
      [txId]
    );
    res.json({ success: true, message: 'TX ID valid' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 4. SIMPAN TRANSAKSI — sync ledger
app.post('/tx/sync', async (req, res) => {
  const { txId, senderId, receiverId, amount, nonce, hash } = req.body;
  if (!txId || !senderId || !receiverId || !amount || !nonce || !hash)
    return res.status(400).json({ error: 'Semua field wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO transactions (tx_id, sender_id, receiver_id, amount, nonce, hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (tx_id) DO NOTHING`,
      [txId, senderId, receiverId, amount, nonce, hash]
    );
    res.json({ success: true, message: 'Transaksi tersimpan' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 5. AMBIL HISTORI TRANSAKSI
app.get('/tx/history/:deviceId', async (req, res) => {
  const { deviceId } = req.params;
  try {
    const result = await pool.query(
      `SELECT * FROM transactions
       WHERE sender_id = $1 OR receiver_id = $1
       ORDER BY created_at DESC LIMIT 50`,
      [deviceId]
    );
    res.json({ success: true, transactions: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 6. SERVER TIME — TrustClock
app.get('/time', (req, res) => {
  res.json({ serverTime: Math.floor(Date.now() / 1000) });
});

// ─────────────────────────────────────────────
// ADMIN — Static files
// ─────────────────────────────────────────────
const path = require('path');
app.use('/admin', express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// ADMIN AUTH
// ─────────────────────────────────────────────
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'offlink2024';

app.post('/admin/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    res.json({ success: true, token: Buffer.from(`${username}:${password}`).toString('base64') });
  } else {
    res.status(401).json({ success: false, message: 'Username atau password salah' });
  }
});

// Middleware cek token admin
function adminAuth(req, res, next) {
  const auth = req.headers['x-admin-token'];
  const expected = Buffer.from(`${ADMIN_USER}:${ADMIN_PASS}`).toString('base64');
  if (auth === expected) return next();
  res.status(403).json({ error: 'Unauthorized' });
}

// ─────────────────────────────────────────────
// ADMIN API — Statistik
// ─────────────────────────────────────────────
app.get('/admin/api/stats', adminAuth, async (req, res) => {
  try {
    const [users, txTotal, txToday] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM devices'),
      pool.query('SELECT COUNT(*), COALESCE(SUM(amount),0) as total FROM transactions'),
      pool.query("SELECT COUNT(*) FROM transactions WHERE created_at >= NOW() - INTERVAL '24 hours'"),
    ]);
    res.json({
      totalUsers  : parseInt(users.rows[0].count),
      totalTx     : parseInt(txTotal.rows[0].count),
      totalVolume : parseInt(txTotal.rows[0].total),
      txToday     : parseInt(txToday.rows[0].count),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// ADMIN API — Users
// ─────────────────────────────────────────────
app.get('/admin/api/users', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT d.device_id, d.created_at,
        (SELECT COUNT(*) FROM transactions WHERE sender_id=d.device_id OR receiver_id=d.device_id) as tx_count,
        (SELECT COALESCE(SUM(amount),0) FROM transactions WHERE receiver_id=d.device_id) -
        (SELECT COALESCE(SUM(amount),0) FROM transactions WHERE sender_id=d.device_id) as saldo_approx,
        EXISTS(SELECT 1 FROM blocked_devices WHERE device_id=d.device_id) as blocked
      FROM devices d ORDER BY d.created_at DESC
    `);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/api/users/block', adminAuth, async (req, res) => {
  try {
    const { device_id } = req.body;
    await pool.query(
      'INSERT INTO blocked_devices(device_id) VALUES($1) ON CONFLICT DO NOTHING',
      [device_id]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ✅ FIX 2: Route unblock DIPERBAIKI — sebelumnya berisi kode query transaksi (copy-paste error)
app.post('/admin/api/users/unblock', adminAuth, async (req, res) => {
  try {
    const { device_id } = req.body;
    await pool.query(
      'DELETE FROM blocked_devices WHERE device_id=$1',
      [device_id]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ✅ FIX 3: Route /admin/api/transactions DITAMBAHKAN — sebelumnya tidak ada sama sekali
// ─────────────────────────────────────────────
// ADMIN API — Transaksi
// ─────────────────────────────────────────────
app.get('/admin/api/transactions', adminAuth, async (req, res) => {
  try {
    const { limit = 100, offset = 0, search = '' } = req.query;
    const result = await pool.query(`
      SELECT * FROM transactions
      WHERE sender_id ILIKE $3 OR receiver_id ILIKE $3 OR tx_id ILIKE $3
      ORDER BY created_at DESC LIMIT $1 OFFSET $2
    `, [limit, offset, `%${search}%`]);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// ADMIN API — Chart data (7 hari terakhir)
// ─────────────────────────────────────────────
app.get('/admin/api/chart', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DATE(created_at) as date, COUNT(*) as count, SUM(amount) as volume
      FROM transactions
      WHERE created_at >= NOW() - INTERVAL '7 days'
      GROUP BY DATE(created_at) ORDER BY date ASC
    `);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────
initDB().then(() => {
  app.listen(port, () => {
    console.log(`🚀 OFFLINK Server berjalan di port ${port}`);
  });
});