// ============================================================
// OFFLINK SERVER — Backend API
// ============================================================

require('dotenv').config();
const express  = require('express');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const helmet   = require('helmet');
const { Pool } = require('pg');
const rateLimit    = require('express-rate-limit');

const app  = express();
const port = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);    
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
// ADMIN AUTH MIDDLEWARE
// ─────────────────────────────────────────────
function adminAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Token tidak ada' });
  const token = auth.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Bukan admin' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token tidak valid' });
  }
}      

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
  
    CREATE TABLE IF NOT EXISTS device_status (
      device_id    TEXT PRIMARY KEY,
      status       TEXT DEFAULT 'active',
      reason       TEXT DEFAULT '',
      updated_at   TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS disputes (
      id            SERIAL PRIMARY KEY,
      reporter_id   TEXT NOT NULL,
      tx_id         TEXT NOT NULL,
      issue_type    TEXT NOT NULL,
      description   TEXT DEFAULT '',
      status        TEXT DEFAULT 'pending',
      admin_note    TEXT DEFAULT '',
      created_at    TIMESTAMP DEFAULT NOW(),
      resolved_at   TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS top_up_fees (
      id              SERIAL PRIMARY KEY,
      device_id       TEXT NOT NULL,
      top_up_amount   BIGINT NOT NULL,
      fee_amount      BIGINT NOT NULL,
      created_at      TIMESTAMP DEFAULT NOW()
    );
 `);
 console.log('✅ Database tables ready');
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

// Serve admin dashboard
const path = require('path');
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

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
// ADMIN ROUTES
// ─────────────────────────────────────────────

// LOGIN ADMIN
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '8h' });
    return res.json({ success: true, token });
  }
  return res.status(401).json({ error: 'Username atau password salah' });  
});
  
// STATISTIK RINGKASAN
app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const txCount    = await pool.query('SELECT COUNT(*) FROM transactions');
    const devCount   = await pool.query('SELECT COUNT(*) FROM devices');
    const lockedCount= await pool.query("SELECT COUNT(*) FROM device_status WHERE status='locked'");
    const pendingDis = await pool.query("SELECT COUNT(*) FROM disputes WHERE status='pending'");
    const totalFee   = await pool.query('SELECT COALESCE(SUM(fee_amount),0) as total FROM top_up_fees');
    const todayFee   = await pool.query(
      "SELECT COALESCE(SUM(fee_amount),0) as total FROM top_up_fees WHERE created_at >= NOW() - INTERVAL '1 day'"
    );
    res.json({
      totalTransactions : parseInt(txCount.rows[0].count),
      totalDevices      : parseInt(devCount.rows[0].count),
      lockedDevices     : parseInt(lockedCount.rows[0].count),
      pendingDisputes   : parseInt(pendingDis.rows[0].count),
      totalFee          : parseInt(totalFee.rows[0].total),
      todayFee          : parseInt(todayFee.rows[0].total),  
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
  
// SEMUA TRANSAKSI
app.get('/admin/transactions', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100'
    );
    res.json({ success: true, transactions: result.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// SEMUA PERANGKAT
app.get('/admin/devices', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT d.device_id, d.public_key, d.created_at,
             COALESCE(ds.status, 'active') as status,
             COALESCE(ds.reason, '') as reason,
             (SELECT COUNT(*) FROM transactions WHERE sender_id = d.device_id OR receiver_id = d.device_id) as tx_count
      FROM devices d
      LEFT JOIN device_status ds ON d.device_id = ds.device_id
      ORDER BY d.created_at DESC
    `);
    res.json({ success: true, devices: result.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// KUNCI PERANGKAT
app.post('/admin/device/lock', adminAuth, async (req, res) => {
  const { deviceId, reason } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO device_status (device_id, status, reason, updated_at)
       VALUES ($1, 'locked', $2, NOW())
       ON CONFLICT (device_id) DO UPDATE SET status='locked', reason=$2, updated_at=NOW()`,
      [deviceId, reason || 'Dikunci oleh admin']
    );
    res.json({ success: true, message: 'Perangkat dikunci' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// BUKA KUNCI PERANGKAT
app.post('/admin/device/unlock', adminAuth, async (req, res) => {
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO device_status (device_id, status, reason, updated_at)
       VALUES ($1, 'active', '', NOW())
       ON CONFLICT (device_id) DO UPDATE SET status='active', reason='', updated_at=NOW()`,
      [deviceId]
    );
    res.json({ success: true, message: 'Perangkat dibuka' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// SEMUA LAPORAN DISPUTE
app.get('/admin/disputes', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM disputes ORDER BY created_at DESC'
    );
    res.json({ success: true, disputes: result.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// SELESAIKAN DISPUTE
app.put('/admin/dispute/:id/resolve', adminAuth, async (req, res) => {
  const { id } = req.params;
  const { status, adminNote } = req.body;
  // status: resolved_refund, resolved_hangus, rejected
  if (!status) return res.status(400).json({ error: 'status wajib diisi' });
  try {
    await pool.query(
      `UPDATE disputes SET status=$1, admin_note=$2, resolved_at=NOW() WHERE id=$3`,
      [status, adminNote || '', id]
    );
    res.json({ success: true, message: 'Dispute diselesaikan' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// SEMUA DATA FEE
app.get('/admin/fees', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM top_up_fees ORDER BY created_at DESC LIMIT 100'
    );
    const total = await pool.query('SELECT COALESCE(SUM(fee_amount),0) as total FROM top_up_fees');
    res.json({ success: true, fees: result.rows, totalFee: parseInt(total.rows[0].total) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// ROUTES DIPANGGIL DARI APP FLUTTER
// ─────────────────────────────────────────────

// CEK STATUS PERANGKAT (dipanggil app saat online)
app.get('/device/status/:deviceId', async (req, res) => {
  const { deviceId } = req.params;
  try {
    const result = await pool.query(
      'SELECT status, reason FROM device_status WHERE device_id = $1',
      [deviceId]
    );
    if (result.rows.length === 0) return res.json({ status: 'active', reason: '' });
    res.json({ status: result.rows[0].status, reason: result.rows[0].reason });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// BUAT LAPORAN DISPUTE (dipanggil app)
app.post('/dispute/create', async (req, res) => {
  const { reporterId, txId, issueType, description } = req.body;
  if (!reporterId || !txId || !issueType)
    return res.status(400).json({ error: 'reporterId, txId, issueType wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO disputes (reporter_id, tx_id, issue_type, description)
       VALUES ($1, $2, $3, $4)`,
      [reporterId, txId, issueType, description || '']
    );
    res.json({ success: true, message: 'Laporan terkirim' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// CATAT FEE TOP UP (dipanggil server Midtrans webhook nanti)
app.post('/topup/fee', async (req, res) => {
  const { deviceId, topUpAmount, feeAmount } = req.body;
  if (!deviceId || !topUpAmount || !feeAmount)
    return res.status(400).json({ error: 'Semua field wajib diisi' });
  try {
    await pool.query(
      'INSERT INTO top_up_fees (device_id, top_up_amount, fee_amount) VALUES ($1, $2, $3)',
      [deviceId, topUpAmount, feeAmount]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
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