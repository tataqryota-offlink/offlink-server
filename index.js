// ============================================================
// OFFLINK SERVER — Backend API
// ============================================================

require('dotenv').config();
const express  = require('express');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const helmet   = require('helmet');
const path     = require('path');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const ed = require('@noble/ed25519');

const app  = express();
const port = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    },
  },
}));
app.use(cors({
  origin: function (origin, callback) {
    const allowed = [
      process.env.CORS_ORIGIN || 'https://offlink-server-production.up.railway.app',
    ];
    // Izinkan request tanpa origin (mobile app, Postman)
    if (!origin || allowed.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('CORS tidak diizinkan'));
    }
  },
  methods: ['GET', 'POST', 'PUT'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));          
app.use(express.json());

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs : 60 * 1000,
  max      : 100,
  message  : { error: 'Terlalu banyak request. Coba lagi dalam 1 menit.' },
});
app.use(globalLimiter);

const txLimiter = rateLimit({
  windowMs : 60 * 1000,
  max      : 30,
  message  : { error: 'Terlalu banyak percobaan scan. Coba lagi dalam 1 menit.' },
});

const registerLimiter = rateLimit({
  windowMs : 60 * 60 * 1000,
  max      : 5,
  message  : { error: 'Terlalu banyak pendaftaran perangkat. Coba lagi dalam 1 jam.' },
});

const nonceLimiter = rateLimit({
  windowMs : 60 * 1000,
  max      : 50,
  message  : { error: 'Terlalu banyak request nonce. Coba lagi dalam 1 menit.' },
});

// ─────────────────────────────────────────────
// ADMIN AUTH MIDDLEWARE
// ─────────────────────────────────────────────
function verifyAdmin(req, res, next) {
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
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
});

// ─────────────────────────────────────────────
// INIT DATABASE
// ─────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      id           SERIAL PRIMARY KEY,
      device_id    TEXT UNIQUE NOT NULL,
      public_key   TEXT NOT NULL,
      balance      BIGINT DEFAULT 0,
      held_balance BIGINT DEFAULT 0,
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

    CREATE TABLE IF NOT EXISTS blocked_devices (
      device_id  TEXT PRIMARY KEY,
      blocked_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      id              SERIAL PRIMARY KEY,
      device_id       TEXT UNIQUE NOT NULL REFERENCES devices(device_id),
      full_name       TEXT,
      phone           TEXT,
      nik_hash        TEXT,
      kyc_status      TEXT DEFAULT 'unverified',
      kyc_verified_at TIMESTAMP,
      created_at      TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id         SERIAL PRIMARY KEY,
      admin_user TEXT NOT NULL,
      action     TEXT NOT NULL,
      target     TEXT,
      detail     JSONB,
      ip_address TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS aml_alerts (
      id         SERIAL PRIMARY KEY,
      device_id  TEXT NOT NULL,
      alert_type TEXT NOT NULL,
      detail     JSONB,
      risk_level TEXT DEFAULT 'medium',
      status     TEXT DEFAULT 'open',
      handled_by TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      handled_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS system_config (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_by TEXT,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ Database tables ready');
}

// ─────────────────────────────────────────────
// ROUTES — PUBLIC
// ─────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'OFFLINK Server Running', time: new Date() });
});

// Serve admin dashboard
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Server time — TrustClock
app.get('/time', (req, res) => {
  res.json({ serverTime: Math.floor(Date.now() / 1000) });
});

// 1. Daftarkan perangkat
app.post('/device/register', registerLimiter, async (req, res) => {
  const { deviceId, publicKey } = req.body;
  if (!deviceId || !publicKey)
    return res.status(400).json({ error: 'deviceId dan publicKey wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO devices (device_id, public_key)
       VALUES ($1, $2)
       ON CONFLICT (device_id) DO NOTHING`,
      [deviceId, publicKey]
    );
    res.json({ success: true, message: 'Perangkat terdaftar' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 2. Cek dan simpan nonce
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

// 3. Cek dan tandai TX ID
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

// ─────────────────────────────────────────────
// 3b. Update saldo device
// ─────────────────────────────────────────────
app.post('/device/balance', async (req, res) => {
  const { deviceId, balance, heldBalance } = req.body;
  if (!deviceId || balance === undefined)
    return res.status(400).json({ error: 'deviceId dan balance wajib diisi' });
  if (typeof balance !== 'number' || balance < 0)
    return res.status(400).json({ error: 'Balance tidak valid' });
  try {
    await pool.query(
      `UPDATE devices SET balance = $1, held_balance = $2 WHERE device_id = $3`,
      [balance, heldBalance ?? 0, deviceId]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// 3c. Ambil saldo device
// ─────────────────────────────────────────────
app.get('/device/balance/:deviceId', async (req, res) => {
  const { deviceId } = req.params;
  try {
    const result = await pool.query(
      'SELECT balance, held_balance FROM devices WHERE device_id = $1',
      [deviceId]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Device tidak ditemukan' });
    res.json({
      balance: result.rows[0].balance,
      heldBalance: result.rows[0].held_balance
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 4. Simpan transaksi
app.post('/tx/sync', txLimiter, async (req, res) => {
  const { txId, senderId, receiverId, amount, nonce, hash } = req.body;
  if (!txId || !senderId || !receiverId || !amount || !nonce || !hash)
    return res.status(400).json({ error: 'Semua field wajib diisi' });

  // Validasi input
  if (typeof amount !== 'number' || amount <= 0)
    return res.status(400).json({ error: 'Amount tidak valid' });
  if (typeof nonce !== 'number' || nonce <= 0)
    return res.status(400).json({ error: 'Nonce tidak valid' });
  if (txId.length > 100)
    return res.status(400).json({ error: 'txId tidak valid' });
  if (senderId.length > 200 || receiverId.length > 200)
    return res.status(400).json({ error: 'ID perangkat tidak valid' });

  try {
    // Cek pengirim terdaftar dan ambil saldo
    const deviceResult = await pool.query(
      'SELECT public_key, balance FROM devices WHERE device_id = $1',
      [senderId]
    );
    if (deviceResult.rows.length === 0)
      return res.status(403).json({ error: 'Perangkat pengirim tidak terdaftar' });

    // Cek saldo mencukupi
    if (deviceResult.rows[0].balance < amount)
      return res.status(400).json({ error: 'Saldo tidak mencukupi' });

    // Cek device tidak diblokir
    const statusResult = await pool.query(
      'SELECT status FROM device_status WHERE device_id = $1',
      [senderId]
    );
    if (statusResult.rows.length > 0 && statusResult.rows[0].status === 'blocked')
      return res.status(403).json({ error: 'Perangkat diblokir oleh administrator' });

    // Cek txId belum pernah dipakai
    const usedResult = await pool.query(
      'SELECT tx_id FROM used_tx_ids WHERE tx_id = $1',
      [txId]
    );
    if (usedResult.rows.length > 0)
      return res.status(409).json({ error: 'Transaksi sudah pernah diproses' });

    // Kurangi saldo pengirim, tambah saldo penerima
    await pool.query(
      'UPDATE devices SET balance = balance - $1, held_balance = held_balance + $1 WHERE device_id = $2',
      [amount, senderId]
    );
    await pool.query(
      'UPDATE devices SET balance = balance + $1 WHERE device_id = $2',
      [amount, receiverId]
    );

    // Simpan transaksi
    await pool.query(
      `INSERT INTO transactions (tx_id, sender_id, receiver_id, amount, nonce, hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (tx_id) DO NOTHING`,
      [txId, senderId, receiverId, amount, nonce, hash]
    );
    // Tandai txId sudah dipakai
    await pool.query(
      'INSERT INTO used_tx_ids (tx_id) VALUES ($1) ON CONFLICT DO NOTHING',
      [txId]
    );
    res.json({ success: true, message: 'Transaksi tersimpan' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 5. Ambil histori transaksi
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

// 6. Cek status perangkat (dipanggil app Flutter)
app.get('/device/status/:deviceId', async (req, res) => {
  const { deviceId } = req.params;
  try {
    const result = await pool.query(
      'SELECT status, reason FROM device_status WHERE device_id = $1',
      [deviceId]
    );
    if (result.rows.length === 0) return res.json({ status: 'active', reason: '' });
    res.json({ status: result.rows[0].status, reason: result.rows[0].reason });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 7. Buat laporan dispute (dipanggil app Flutter)
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
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 8. Catat fee top up (dipanggil webhook Midtrans nanti)
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
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// ROUTES — ADMIN
// ─────────────────────────────────────────────

// Login admin
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username dan password wajib diisi' });

  const validUsername = username === process.env.ADMIN_USERNAME;
  const validPassword = await bcrypt.compare(
    password,
    process.env.ADMIN_PASSWORD_HASH
  );

  if (validUsername && validPassword) {
    const token = jwt.sign(
      { role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    return res.json({ success: true, token });
  }
  return res.status(401).json({ error: 'Username atau password salah' });
});

// Statistik ringkasan
app.get('/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const txCount     = await pool.query('SELECT COUNT(*) FROM transactions');
    const devCount    = await pool.query('SELECT COUNT(*) FROM devices');
    const lockedCount = await pool.query("SELECT COUNT(*) FROM device_status WHERE status='locked'");
    const pendingDis  = await pool.query("SELECT COUNT(*) FROM disputes WHERE status='pending'");
    const totalFee    = await pool.query('SELECT COALESCE(SUM(fee_amount),0) as total FROM top_up_fees');
    const todayFee    = await pool.query(
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

// Semua transaksi
app.get('/admin/transactions', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100'
    );
    res.json({ success: true, transactions: result.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Semua perangkat
app.get('/admin/devices', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT d.device_id, d.public_key, d.created_at,
             COALESCE(ds.status, 'active') as status,
             COALESCE(ds.reason, '') as reason,
             (SELECT COUNT(*) FROM transactions
              WHERE sender_id = d.device_id OR receiver_id = d.device_id) as tx_count
      FROM devices d
      LEFT JOIN device_status ds ON d.device_id = ds.device_id
      ORDER BY d.created_at DESC
    `);
    res.json({ success: true, devices: result.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Kunci perangkat
app.post('/admin/device/lock', verifyAdmin, async (req, res) => {
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

// Buka kunci perangkat
app.post('/admin/device/unlock', verifyAdmin, async (req, res) => {
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

// Semua laporan dispute
app.get('/admin/disputes', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM disputes ORDER BY created_at DESC'
    );
    res.json({ success: true, disputes: result.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Selesaikan dispute
app.put('/admin/dispute/:id/resolve', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { status, adminNote } = req.body;
  if (!status) return res.status(400).json({ error: 'status wajib diisi' });
  try {
    await pool.query(
      `UPDATE disputes SET status=$1, admin_note=$2, resolved_at=NOW() WHERE id=$3`,
      [status, adminNote || '', id]
    );
    res.json({ success: true, message: 'Dispute diselesaikan' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Semua data fee
app.get('/admin/fees', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM top_up_fees ORDER BY created_at DESC LIMIT 100'
    );
    const total = await pool.query(
      'SELECT COALESCE(SUM(fee_amount),0) as total FROM top_up_fees'
    );
    res.json({ success: true, fees: result.rows, totalFee: parseInt(total.rows[0].total) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Blokir user
app.post('/admin/users/block', verifyAdmin, async (req, res) => {
  const { device_id } = req.body;
  if (!device_id) return res.status(400).json({ error: 'device_id wajib diisi' });
  try {
    await pool.query(
      'INSERT INTO blocked_devices(device_id) VALUES($1) ON CONFLICT DO NOTHING',
      [device_id]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Buka blokir user
app.post('/admin/users/unblock', verifyAdmin, async (req, res) => {
  const { device_id } = req.body;
  if (!device_id) return res.status(400).json({ error: 'device_id wajib diisi' });
  try {
    await pool.query(
      'DELETE FROM blocked_devices WHERE device_id=$1',
      [device_id]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// ADMIN — KYC & PENGGUNA
// ─────────────────────────────────────────────
app.get('/admin/api/users/detail/:deviceId', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT d.device_id, d.public_key, d.balance, d.held_balance, d.created_at,
              u.full_name, u.phone, u.nik_hash, u.kyc_status, u.kyc_verified_at
       FROM devices d LEFT JOIN users u ON d.device_id = u.device_id
       WHERE d.device_id = $1`,
      [req.params.deviceId]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Device tidak ditemukan' });
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/api/users/kyc/approve', verifyAdmin, async (req, res) => {
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO users (device_id, kyc_status, kyc_verified_at)
       VALUES ($1, 'verified', NOW())
       ON CONFLICT (device_id) DO UPDATE SET kyc_status = 'verified', kyc_verified_at = NOW()`,
      [deviceId]
    );
    await pool.query(
      `INSERT INTO audit_logs (admin_user, action, target, ip_address)
       VALUES ($1, 'KYC_APPROVE', $2, $3)`,
      ['admin', deviceId, req.ip]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/api/users/kyc/reject', verifyAdmin, async (req, res) => {
  const { deviceId, reason } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO users (device_id, kyc_status)
       VALUES ($1, 'rejected')
       ON CONFLICT (device_id) DO UPDATE SET kyc_status = 'rejected'`,
      [deviceId]
    );
    await pool.query(
      `INSERT INTO audit_logs (admin_user, action, target, detail, ip_address)
       VALUES ($1, 'KYC_REJECT', $2, $3, $4)`,
      ['admin', deviceId, JSON.stringify({ reason }), req.ip]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// ADMIN — AML & ANOMALI
// ─────────────────────────────────────────────
app.get('/admin/api/aml/alerts', verifyAdmin, async (req, res) => {
  try {
    const { status, risk_level } = req.query;
    let query = 'SELECT * FROM aml_alerts WHERE 1=1';
    const params = [];
    if (status) { params.push(status); query += ` AND status = $${params.length}`; }
    if (risk_level) { params.push(risk_level); query += ` AND risk_level = $${params.length}`; }
    query += ' ORDER BY created_at DESC LIMIT 100';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/api/aml/stats', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status = 'open') AS open_alerts,
        COUNT(*) FILTER (WHERE risk_level = 'high') AS high_risk,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day') AS today
      FROM aml_alerts
    `);
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/api/aml/handle', verifyAdmin, async (req, res) => {
  const { alertId, action } = req.body;
  if (!alertId || !action) return res.status(400).json({ error: 'alertId dan action wajib diisi' });
  try {
    await pool.query(
      `UPDATE aml_alerts SET status = $1, handled_by = 'admin', handled_at = NOW() WHERE id = $2`,
      [action, alertId]
    );
    await pool.query(
      `INSERT INTO audit_logs (admin_user, action, target, ip_address)
       VALUES ('admin', $1, $2, $3)`,
      [`AML_${action.toUpperCase()}`, String(alertId), req.ip]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// ADMIN — AUDIT LOG
// ─────────────────────────────────────────────
app.get('/admin/api/audit-logs', verifyAdmin, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    const result = await pool.query(
      'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset]
    );
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// ADMIN — SYSTEM HEALTH
// ─────────────────────────────────────────────
app.get('/admin/api/health', verifyAdmin, async (req, res) => {
  try {
    const dbStart = Date.now();
    await pool.query('SELECT 1');
    const dbLatency = Date.now() - dbStart;
    res.json({
      server: 'online',
      database: 'connected',
      db_latency_ms: dbLatency,
      uptime_seconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.json({ server: 'online', database: 'error', error: e.message });
  }
});

// ─────────────────────────────────────────────
// ADMIN — REKONSILIASI
// ─────────────────────────────────────────────
app.get('/admin/api/reconciliation/summary', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*) AS total_tx,
        COALESCE(SUM(amount), 0) AS total_volume,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day') AS today_tx,
        COALESCE(SUM(amount) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day'), 0) AS today_volume
      FROM transactions
    `);
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// ADMIN — KONFIGURASI SISTEM
// ─────────────────────────────────────────────
app.get('/admin/api/config', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM system_config ORDER BY key');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/api/config', verifyAdmin, async (req, res) => {
  const { key, value } = req.body;
  if (!key || !value) return res.status(400).json({ error: 'key dan value wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO system_config (key, value, updated_by, updated_at)
       VALUES ($1, $2, 'admin', NOW())
       ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = 'admin', updated_at = NOW()`,
      [key, value]
    );
    await pool.query(
      `INSERT INTO audit_logs (admin_user, action, target, detail, ip_address)
       VALUES ('admin', 'CONFIG_UPDATE', $1, $2, $3)`,
      [key, JSON.stringify({ value }), req.ip]
    );
    res.json({ success: true });
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