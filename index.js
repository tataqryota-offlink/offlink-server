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
const cookieParser = require('cookie-parser');
const ed25519 = require('@noble/ed25519');
const crypto = require('crypto');
ed25519.etc.sha512Sync = (...msgs) => {
  const h = crypto.createHash('sha512');
  msgs.forEach(m => h.update(m));
  return Uint8Array.from(h.digest());
};

const app  = express();
app.set('trust proxy', 1);
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
app.use(cookieParser());

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
  // Coba dari cookie dulu, fallback ke Authorization header
  const token = req.cookies?.admin_token || 
    (req.headers['authorization'] || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token tidak ada' });
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

    CREATE TABLE IF NOT EXISTS held_balances (
      tx_id       TEXT PRIMARY KEY,
      device_id   TEXT NOT NULL,
      amount      BIGINT NOT NULL,
      status      TEXT DEFAULT 'held',
      reason      TEXT DEFAULT '',
      created_at  TIMESTAMP DEFAULT NOW(),
      resolved_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS tx_events (
      id          SERIAL PRIMARY KEY,
      tx_id       TEXT NOT NULL,
      device_id   TEXT NOT NULL,
      event_type  TEXT NOT NULL,
      detail      JSONB,
      created_at  TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dispute_messages (
      id           SERIAL PRIMARY KEY,
      dispute_id   INT NOT NULL,
      sender_type  TEXT NOT NULL,
      sender_id    TEXT NOT NULL,
      message      TEXT NOT NULL,
      created_at   TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
      ALTER TABLE disputes
        ADD COLUMN IF NOT EXISTS ticket_number TEXT,
        ADD COLUMN IF NOT EXISTS deadline_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS last_reply_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS reply_status TEXT DEFAULT 'waiting';

      ALTER TABLE transactions
        ADD COLUMN IF NOT EXISTS flow_status TEXT DEFAULT 'synced',
        ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT '';
    `);
    
    await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_transactions_sender    ON transactions(sender_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_receiver  ON transactions(receiver_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_created   ON transactions(created_at);
    CREATE INDEX IF NOT EXISTS idx_held_balances_device   ON held_balances(device_id);
    CREATE INDEX IF NOT EXISTS idx_held_balances_status   ON held_balances(status);
    CREATE INDEX IF NOT EXISTS idx_tx_events_tx_id        ON tx_events(tx_id);
    CREATE INDEX IF NOT EXISTS idx_tx_events_device       ON tx_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_disputes_reporter      ON disputes(reporter_id);
    CREATE INDEX IF NOT EXISTS idx_disputes_status        ON disputes(status);
    CREATE INDEX IF NOT EXISTS idx_dispute_messages_dispute ON dispute_messages(dispute_id);
    CREATE INDEX IF NOT EXISTS idx_aml_alerts_device      ON aml_alerts(device_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created     ON audit_logs(created_at);
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
  // Validasi device secret
  const secret = req.headers['x-device-secret'];
  if (secret !== process.env.DEVICE_SECRET)
    return res.status(401).json({ error: 'Akses tidak diizinkan' });

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

    // Verifikasi signature - skip sementara untuk testing
    // TODO: aktifkan kembali setelah format signature dikonfirmasi

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
    // Cek AML otomatis
    checkAml(txId, senderId, receiverId, amount);

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

// Logout admin
app.post('/admin/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ success: true });
});

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
    res.cookie('admin_token', token, {
      httpOnly : true,
      secure   : true,
      sameSite : 'strict',
      maxAge   : 8 * 60 * 60 * 1000
    });
    return res.json({ success: true });
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
app.get('/admin/api/users/list', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT d.device_id, d.balance, d.held_balance, d.created_at,
              u.full_name, u.phone, u.kyc_status, u.kyc_verified_at
       FROM devices d
       LEFT JOIN users u ON d.device_id = u.device_id
       ORDER BY d.created_at DESC`
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

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
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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

// Update data user dari app
app.post('/device/userdata', async (req, res) => {
  const { deviceId, fullName, phone } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO users (device_id, full_name, phone, kyc_status)
       VALUES ($1, $2, $3, 'unverified')
       ON CONFLICT (device_id) DO UPDATE
       SET full_name = $2, phone = $3`,
      [deviceId, fullName || null, phone || null]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Cek status device
app.get('/device/status/:deviceId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT status FROM device_status WHERE device_id = $1',
      [req.params.deviceId]
    );
    if (result.rows.length === 0)
      return res.json({ status: 'active' });
    res.json({ status: result.rows[0].status });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// ADMIN — EXPORT DATA
// ─────────────────────────────────────────────
app.get('/admin/export/transactions/csv', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT tx_id, sender_id, receiver_id, amount, status, created_at FROM transactions ORDER BY created_at DESC'
    );
    const rows = result.rows;
    const header = 'TX ID,Pengirim,Penerima,Nominal (Rp),Status,Waktu\n';
    const csv = rows.map(r =>
      `"${r.tx_id}","${r.sender_id}","${r.receiver_id}",${r.amount},"${r.status}","${new Date(r.created_at).toLocaleString('id-ID')}"`
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="offlink-transaksi.csv"');
    res.send(header + csv);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/export/users/csv', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT d.device_id, u.full_name, u.phone, u.kyc_status, d.balance, d.created_at
       FROM devices d LEFT JOIN users u ON d.device_id = u.device_id
       ORDER BY d.created_at DESC`
    );
    const rows = result.rows;
    const header = 'Device ID,Nama,No HP,KYC Status,Saldo (Rp),Terdaftar\n';
    const csv = rows.map(r =>
      `"${r.device_id}","${r.full_name || ''}","${r.phone || ''}","${r.kyc_status || 'unverified'}",${r.balance},"${new Date(r.created_at).toLocaleString('id-ID')}"`
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="offlink-pengguna.csv"');
    res.send(header + csv);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// ADMIN — EXPORT PDF
// ─────────────────────────────────────────────
const PDFDocument = require('pdfkit');

app.get('/admin/export/report/pdf', verifyAdmin, async (req, res) => {
  try {
    const [txResult, userResult, amlResult, recon] = await Promise.all([
      pool.query('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 50'),
      pool.query(`SELECT d.device_id, u.full_name, u.phone, u.kyc_status, d.balance
                  FROM devices d LEFT JOIN users u ON d.device_id = u.device_id
                  ORDER BY d.created_at DESC`),
      pool.query("SELECT COUNT(*) FROM aml_alerts WHERE status='open'"),
      pool.query(`SELECT COUNT(*) as total_tx, COALESCE(SUM(amount),0) as total_volume
                  FROM transactions`)
    ]);

    const doc = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="offlink-laporan.pdf"');
    doc.pipe(res);

    // Header
    doc.fontSize(20).font('Helvetica-Bold').text('OFFLINK', { align: 'center' });
    doc.fontSize(12).font('Helvetica').text('Laporan Sistem Pembayaran Offline', { align: 'center' });
    doc.fontSize(10).text(`Dicetak: ${new Date().toLocaleString('id-ID')}`, { align: 'center' });
    doc.moveDown(2);

    // Ringkasan
    doc.fontSize(14).font('Helvetica-Bold').text('RINGKASAN SISTEM');
    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
    doc.moveDown(0.5);
    doc.fontSize(10).font('Helvetica');
    doc.text(`Total Transaksi    : ${recon.rows[0].total_tx}`);
    doc.text(`Total Volume       : Rp ${Number(recon.rows[0].total_volume).toLocaleString('id-ID')}`);
    doc.text(`Total Pengguna     : ${userResult.rows.length}`);
    doc.text(`Pengguna Verified  : ${userResult.rows.filter(u => u.kyc_status === 'verified').length}`);
    doc.text(`Alert AML Terbuka  : ${amlResult.rows[0].count}`);
    doc.moveDown(2);

    // Daftar Pengguna
    doc.fontSize(14).font('Helvetica-Bold').text('DAFTAR PENGGUNA');
    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
    doc.moveDown(0.5);
    doc.fontSize(9).font('Helvetica');
    userResult.rows.forEach((u, i) => {
      doc.text(
        `${i+1}. ${u.full_name || 'Belum diisi'} | ${u.phone || '-'} | KYC: ${u.kyc_status || 'unverified'} | Saldo: Rp ${Number(u.balance || 0).toLocaleString('id-ID')}`,
        { lineGap: 2 }
      );
    });
    doc.moveDown(2);

    // 50 Transaksi Terakhir
    doc.fontSize(14).font('Helvetica-Bold').text('50 TRANSAKSI TERAKHIR');
    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
    doc.moveDown(0.5);
    doc.fontSize(9).font('Helvetica');
    txResult.rows.forEach((t, i) => {
      doc.text(
        `${i+1}. ${t.tx_id.substring(0,20)}... | Rp ${Number(t.amount).toLocaleString('id-ID')} | ${t.status} | ${new Date(t.created_at).toLocaleString('id-ID')}`,
        { lineGap: 2 }
      );
    });

    doc.end();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// AML OTOMATIS
// ─────────────────────────────────────────────
async function checkAml(txId, senderId, receiverId, amount) {
  try {
    // Aturan 1: Transaksi besar > Rp 500.000 (per transaksi, tanpa batas waktu)
    if (amount >= 500000) {
      await pool.query(
        `INSERT INTO aml_alerts (device_id, alert_type, detail, risk_level, status)
         VALUES ($1, 'LARGE_TRANSACTION', $2, 'high', 'open')`,
        [senderId, JSON.stringify({ tx_id: txId, amount, threshold: 500000 })]
      );
    }

    // Aturan 2: Pengirim kirim ke 5+ device berbeda dalam 1 jam
    const freqSend = await pool.query(
      `SELECT COUNT(DISTINCT receiver_id) as cnt FROM transactions
       WHERE sender_id = $1 AND created_at > NOW() - INTERVAL '1 hour'`,
      [senderId]
    );
    if (parseInt(freqSend.rows[0].cnt) >= 5) {
      await pool.query(
        `INSERT INTO aml_alerts (device_id, alert_type, detail, risk_level, status)
         VALUES ($1, 'FREQUENT_TRANSFER', $2, 'high', 'open')`,
        [senderId, JSON.stringify({ type: 'pengirim', distinct_receivers: freqSend.rows[0].cnt, window: '1 jam' })]
      );
    }

    // Aturan 3: Penerima terima dari 5+ device berbeda dalam 1 jam
    const freqRecv = await pool.query(
      `SELECT COUNT(DISTINCT sender_id) as cnt FROM transactions
       WHERE receiver_id = $1 AND created_at > NOW() - INTERVAL '1 hour'`,
      [receiverId]
    );
    if (parseInt(freqRecv.rows[0].cnt) >= 5) {
      await pool.query(
        `INSERT INTO aml_alerts (device_id, alert_type, detail, risk_level, status)
         VALUES ($1, 'FREQUENT_TRANSFER', $2, 'high', 'open')`,
        [receiverId, JSON.stringify({ type: 'penerima', distinct_senders: freqRecv.rows[0].cnt, window: '1 jam' })]
      );
    }

    // Aturan 4: Pengirim kirim 5+ kali ke orang yang sama dalam 1 jam
    const freqSame = await pool.query(
      `SELECT COUNT(*) as cnt FROM transactions
       WHERE sender_id = $1 AND receiver_id = $2
       AND created_at > NOW() - INTERVAL '1 hour'`,
      [senderId, receiverId]
    );
    if (parseInt(freqSame.rows[0].cnt) >= 5) {
      await pool.query(
        `INSERT INTO aml_alerts (device_id, alert_type, detail, risk_level, status)
         VALUES ($1, 'FREQUENT_TRANSFER', $2, 'medium', 'open')`,
        [senderId, JSON.stringify({ type: 'pengirim_ke_penerima_sama', count: freqSame.rows[0].cnt, window: '1 jam' })]
      );
    }
  } catch (e) {
    console.error('AML check error:', e.message);
  }
}

// ─────────────────────────────────────────────
// ADMIN — HISTORY TRANSAKSI DETAIL
// ─────────────────────────────────────────────
app.get('/admin/api/transactions/detail', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id, t.tx_id, t.sender_id, t.receiver_id, t.amount, 
              t.status, t.flow_status, t.notes, t.created_at,
              us.full_name AS sender_name, us.phone AS sender_phone,
              ur.full_name AS receiver_name, ur.phone AS receiver_phone
       FROM transactions t
       LEFT JOIN users us ON t.sender_id = us.device_id
       LEFT JOIN users ur ON t.receiver_id = ur.device_id
       ORDER BY t.created_at DESC
       LIMIT 100`
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/api/transactions/detail/:deviceId', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id, t.tx_id, t.sender_id, t.receiver_id, t.amount,
              t.status, t.flow_status, t.notes, t.created_at,
              us.full_name AS sender_name, us.phone AS sender_phone,
              ur.full_name AS receiver_name, ur.phone AS receiver_phone
       FROM transactions t
       LEFT JOIN users us ON t.sender_id = us.device_id
       LEFT JOIN users ur ON t.receiver_id = ur.device_id
       WHERE t.sender_id = $1 OR t.receiver_id = $1
       ORDER BY t.created_at DESC
       LIMIT 100`,
      [req.params.deviceId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// HELD BALANCES & TX EVENTS
// ─────────────────────────────────────────────

// Catat dana tertahan per transaksi
app.post('/tx/held', async (req, res) => {
  const { txId, deviceId, amount, issuedAt, expiredAt } = req.body;
  if (!txId || !deviceId || !amount)
    return res.status(400).json({ error: 'txId, deviceId, amount wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO held_balances (tx_id, device_id, amount, status)
       VALUES ($1, $2, $3, 'held')
       ON CONFLICT (tx_id) DO NOTHING`,
      [txId, deviceId, amount]
    );
    // Catat event QR diterbitkan
    await pool.query(
      `INSERT INTO tx_events (tx_id, device_id, event_type, detail)
       VALUES ($1, $2, 'QR_ISSUED', $3)`,
      [txId, deviceId, JSON.stringify({ amount, issuedAt, expiredAt })]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Ambil daftar dana tertahan per device
app.get('/tx/held/:deviceId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT h.tx_id, h.amount, h.status, h.reason, h.created_at, h.resolved_at,
              t.receiver_id, u.full_name AS receiver_name
       FROM held_balances h
       LEFT JOIN transactions t ON h.tx_id = t.tx_id
       LEFT JOIN users u ON t.receiver_id = u.device_id
       WHERE h.device_id = $1
       ORDER BY h.created_at DESC`,
      [req.params.deviceId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Catat event per langkah transaksi
app.post('/tx/event', async (req, res) => {
  const { txId, deviceId, eventType, detail } = req.body;
  if (!txId || !deviceId || !eventType)
    return res.status(400).json({ error: 'txId, deviceId, eventType wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO tx_events (tx_id, device_id, event_type, detail)
       VALUES ($1, $2, $3, $4)`,
      [txId, deviceId, eventType, JSON.stringify(detail || {})]
    );
    // Update status held_balance jika event CONFIRMED
    if (eventType === 'TX_CONFIRMED') {
      await pool.query(
        `UPDATE held_balances SET status = 'released', resolved_at = NOW()
         WHERE tx_id = $1`,
        [txId]
      );
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Ambil semua event per transaksi
app.get('/tx/events/:txId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT event_type, detail, created_at
       FROM tx_events WHERE tx_id = $1
       ORDER BY created_at ASC`,
      [req.params.txId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// PENGADUAN DIPERKUAT
// ─────────────────────────────────────────────

// Buat pengaduan dengan bukti histori
app.post('/dispute/report', async (req, res) => {
  const { reporterId, txId, issueType, description,
          txEventsSnapshot, chainHash, issuedAt, expiredAt } = req.body;
  if (!reporterId || !txId || !issueType)
    return res.status(400).json({ error: 'reporterId, txId, issueType wajib diisi' });
  try {
    // Cek batas waktu 2 minggu
    if (issuedAt) {
      const issuedDate = new Date(issuedAt * 1000);
      const deadline   = new Date(issuedDate.getTime() + 14 * 24 * 60 * 60 * 1000);
      if (new Date() > deadline)
        return res.status(400).json({ error: 'Batas waktu pengaduan 2 minggu sudah lewat' });
    }

    // Cek apakah txId sudah sync ke server (penentu hangus/refund)
    const txCheck = await pool.query(
      'SELECT tx_id, receiver_id FROM transactions WHERE tx_id = $1',
      [txId]
    );
    const txFoundOnServer = txCheck.rows.length > 0;

    const deadline = issuedAt
      ? new Date(issuedAt * 1000 + 14 * 24 * 60 * 60 * 1000)
      : new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO disputes
         (reporter_id, tx_id, issue_type, description,
          tx_events_snapshot, chain_hash, issued_at, expired_at, deadline_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT DO NOTHING`,
      [reporterId, txId, issueType, description || '',
       JSON.stringify(txEventsSnapshot || []),
       chainHash || '', issuedAt || null, expiredAt || null, deadline]
    );

    // Catat event pengaduan
    await pool.query(
      `INSERT INTO tx_events (tx_id, device_id, event_type, detail)
       VALUES ($1, $2, 'DISPUTE_FILED', $3)`,
      [txId, reporterId, JSON.stringify({
        issueType,
        txFoundOnServer,
        recommendation: txFoundOnServer ? 'HANGUS' : 'REFUND'
      })]
    );

    const ticket = generateTicketNumber();
    const disputeResult = await pool.query(
      `UPDATE disputes SET ticket_number = $1 WHERE tx_id = $2 AND reporter_id = $3 AND ticket_number IS NULL RETURNING id, ticket_number`,
      [ticket, txId, reporterId]
    );
    const disputeRow = disputeResult.rows[0] || (await pool.query(
      `SELECT id, ticket_number FROM disputes WHERE tx_id = $1 AND reporter_id = $2`,
      [txId, reporterId]
    )).rows[0];

    res.json({
      success        : true,
      disputeId      : disputeRow?.id,
      ticketNumber   : disputeRow?.ticket_number,
      txFoundOnServer,
      recommendation : txFoundOnServer ? 'HANGUS' : 'REFUND',
      message        : txFoundOnServer
        ? 'Dana kemungkinan sudah diterima HP B. Admin akan verifikasi.'
        : 'Dana kemungkinan belum diterima HP B. Admin akan proses refund.'
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// DISPUTE MESSAGES (SISTEM PESAN PENGADUAN)
// ─────────────────────────────────────────────

// Generate nomor tiket otomatis
function generateTicketNumber() {
  const now = new Date();
  const yy = String(now.getFullYear()).slice(2);
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const rand = Math.floor(Math.random() * 9000 + 1000);
  return `ADU-${yy}${mm}${dd}-${rand}`;
}

// Update ticket_number saat pengaduan dibuat (patch endpoint lama)
app.post('/dispute/init-ticket', async (req, res) => {
  const { disputeId } = req.body;
  try {
    const ticket = generateTicketNumber();
    await pool.query(
      `UPDATE disputes SET ticket_number = $1 WHERE id = $2 AND ticket_number IS NULL`,
      [ticket, disputeId]
    );
    const result = await pool.query(
      `SELECT ticket_number FROM disputes WHERE id = $1`, [disputeId]
    );
    res.json({ ticketNumber: result.rows[0]?.ticket_number });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// User kirim pesan
app.post('/dispute/message', async (req, res) => {
  const { disputeId, deviceId, message } = req.body;
  if (!disputeId || !deviceId || !message)
    return res.status(400).json({ error: 'disputeId, deviceId, message wajib diisi' });
  try {
    // Pastikan dispute milik device ini
    const check = await pool.query(
      `SELECT id, ticket_number FROM disputes WHERE id = $1 AND reporter_id = $2`,
      [disputeId, deviceId]
    );
    if (check.rows.length === 0)
      return res.status(403).json({ error: 'Pengaduan tidak ditemukan' });

    await pool.query(
      `INSERT INTO dispute_messages (dispute_id, sender_type, sender_id, message)
       VALUES ($1, 'user', $2, $3)`,
      [disputeId, deviceId, message]
    );
    await pool.query(
      `UPDATE disputes SET last_reply_at = NOW(), reply_status = 'waiting' WHERE id = $1`,
      [disputeId]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// User ambil semua pesan per pengaduan
app.get('/dispute/messages/:disputeId/:deviceId', async (req, res) => {
  try {
    const { disputeId, deviceId } = req.params;
    // Verifikasi kepemilikan
    const check = await pool.query(
      `SELECT id FROM disputes WHERE id = $1 AND reporter_id = $2`,
      [disputeId, deviceId]
    );
    if (check.rows.length === 0)
      return res.status(403).json({ error: 'Akses ditolak' });

    const result = await pool.query(
      `SELECT sender_type, message, created_at
       FROM dispute_messages WHERE dispute_id = $1
       ORDER BY created_at ASC`,
      [disputeId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// User ambil daftar semua pengaduannya
app.get('/dispute/list/:deviceId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT d.id, d.ticket_number, d.tx_id, d.issue_type, d.status,
              d.reply_status, d.created_at, d.last_reply_at,
              h.amount
       FROM disputes d
       LEFT JOIN held_balances h ON d.tx_id = h.tx_id
       WHERE d.reporter_id = $1
       ORDER BY d.created_at DESC`,
      [req.params.deviceId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin kirim pesan balasan
app.post('/admin/api/dispute/reply', verifyAdmin, async (req, res) => {
  const { disputeId, message } = req.body;
  if (!disputeId || !message)
    return res.status(400).json({ error: 'disputeId dan message wajib diisi' });
  try {
    await pool.query(
      `INSERT INTO dispute_messages (dispute_id, sender_type, sender_id, message)
       VALUES ($1, 'admin', 'admin', $2)`,
      [disputeId, message]
    );
    await pool.query(
      `UPDATE disputes SET last_reply_at = NOW(), reply_status = 'replied' WHERE id = $1`,
      [disputeId]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin ambil semua pesan per pengaduan
app.get('/admin/api/dispute/messages/:disputeId', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sender_type, sender_id, message, created_at
       FROM dispute_messages WHERE dispute_id = $1
       ORDER BY created_at ASC`,
      [req.params.disputeId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ADMIN — HELD BALANCES
app.get('/admin/api/held-balances', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT h.tx_id, h.device_id, h.amount, h.status, h.reason,
             h.created_at, h.resolved_at,
             u.full_name, u.phone
      FROM held_balances h
      LEFT JOIN users u ON h.device_id = u.device_id
      ORDER BY h.created_at DESC LIMIT 100
    `);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ADMIN — DISPUTES DETAIL
app.get('/admin/api/disputes/detail', verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT d.*, u.full_name AS reporter_name, u.phone AS reporter_phone
      FROM disputes d
      LEFT JOIN users u ON d.reporter_id = u.device_id
      ORDER BY d.created_at DESC LIMIT 100
    `);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ADMIN — RESOLVE DISPUTE
app.post('/admin/api/disputes/resolve', verifyAdmin, async (req, res) => {
  const { disputeId, decision, adminNote } = req.body;
  if (!disputeId || !decision)
    return res.status(400).json({ error: 'disputeId dan decision wajib diisi' });
  try {
    await pool.query(
      `UPDATE disputes SET status=$1, admin_note=$2, resolved_at=NOW() WHERE id=$3`,
      [decision, adminNote || '', disputeId]
    );
    const d = await pool.query('SELECT tx_id FROM disputes WHERE id=$1', [disputeId]);
    if (d.rows.length > 0) {
      const s = decision === 'resolved_refund' ? 'refunded' : 'hangus';
      await pool.query(
        `UPDATE held_balances SET status=$1, resolved_at=NOW() WHERE tx_id=$2`,
        [s, d.rows[0].tx_id]
      );
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────
initDB().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`🚀 OFFLINK Server berjalan di port ${port}`);
  });
});


