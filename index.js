// ============================================================
// OFFLINK SERVER — Backend API
// ============================================================

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const { Pool } = require('pg');

const app  = express();
const port = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet());
app.use(cors());
app.use(express.json());

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
app.post('/device/register', async (req, res) => {
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
app.post('/nonce/verify', async (req, res) => {
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
app.post('/tx/check', async (req, res) => {
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
  res.json({ serverTime: Date.now() });
});

// ─────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────
initDB().then(() => {
  app.listen(port, () => {
    console.log(`🚀 OFFLINK Server berjalan di port ${port}`);
  });
});