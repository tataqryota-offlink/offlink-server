// ─────────────────────────────────────────────
// OFFLINK SEED DATA — Demo Bank
// Jalankan: node seed.js
// PERINGATAN: Hapus data lama dan isi ulang!
// ─────────────────────────────────────────────
require('dotenv').config();
const { Pool } = require('pg');
const crypto   = require('crypto');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ── Data user realistis ──
const USERS = [
  { id: 'DEV001', name: 'Budi Santoso',      phone: '081234567001', nik: '3201010101800001' },
  { id: 'DEV002', name: 'Siti Rahayu',       phone: '081234567002', nik: '3201010101800002' },
  { id: 'DEV003', name: 'Ahmad Fauzi',       phone: '081234567003', nik: '3201010101800003' },
  { id: 'DEV004', name: 'Dewi Lestari',      phone: '081234567004', nik: '3201010101800004' },
  { id: 'DEV005', name: 'Rizky Pratama',     phone: '081234567005', nik: '3201010101800005' },
  { id: 'DEV006', name: 'Fitri Handayani',   phone: '081234567006', nik: '3201010101800006' },
  { id: 'DEV007', name: 'Doni Kurniawan',    phone: '081234567007', nik: '3201010101800007' },
  { id: 'DEV008', name: 'Rina Wulandari',    phone: '081234567008', nik: '3201010101800008' },
  { id: 'DEV009', name: 'Hendra Gunawan',    phone: '081234567009', nik: '3201010101800009' },
  { id: 'DEV010', name: 'Yuli Astuti',       phone: '081234567010', nik: '3201010101800010' },
  { id: 'DEV011', name: 'Eko Wahyudi',       phone: '081234567011', nik: '3201010101800011' },
  { id: 'DEV012', name: 'Nisa Permatasari',  phone: '081234567012', nik: '3201010101800012' },
  { id: 'DEV013', name: 'Agus Setiawan',     phone: '081234567013', nik: '3201010101800013' },
  { id: 'DEV014', name: 'Melisa Putri',      phone: '081234567014', nik: '3201010101800014' },
  { id: 'DEV015', name: 'Fajar Nugroho',     phone: '081234567015', nik: '3201010101800015' },
  { id: 'DEV016', name: 'Indah Kusuma',      phone: '081234567016', nik: '3201010101800016' },
  { id: 'DEV017', name: 'Bayu Saputra',      phone: '081234567017', nik: '3201010101800017' },
  { id: 'DEV018', name: 'Rini Susanti',      phone: '081234567018', nik: '3201010101800018' },
  { id: 'DEV019', name: 'Wahyu Hidayat',     phone: '081234567019', nik: '3201010101800019' },
  { id: 'DEV020', name: 'Laila Nurjanah',    phone: '081234567020', nik: '3201010101800020' },
];

const KYC_STATUS = ['verified', 'verified', 'verified', 'verified', 'pending', 'verified', 'verified', 'unverified', 'verified', 'verified',
                    'verified', 'verified', 'pending', 'verified', 'verified', 'verified', 'unverified', 'verified', 'verified', 'verified'];

function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function daysAgo(n) { return new Date(Date.now() - n * 86400000); }
function minsAgo(n) { return new Date(Date.now() - n * 60000); }

function hash(str) { return crypto.createHash('sha256').update(str).digest('hex'); }

async function seed() {
  console.log('┌─────────────────────────────────────┐');
  console.log('│     OFFLINK — SEED DATA DEMO        │');
  console.log('└─────────────────────────────────────┘');

  // ── Hapus data lama (urutan penting karena FK) ──
  console.log('\n🗑  Menghapus data lama...');
  await pool.query(`DELETE FROM dispute_messages`);
  await pool.query(`DELETE FROM disputes`);
  await pool.query(`DELETE FROM aml_alerts`);
  await pool.query(`DELETE FROM audit_logs`);
  await pool.query(`DELETE FROM held_balances`);
  await pool.query(`DELETE FROM tx_events`);
  await pool.query(`DELETE FROM top_up_fees`);
  await pool.query(`DELETE FROM transactions`);
  await pool.query(`DELETE FROM used_tx_ids`);
  await pool.query(`DELETE FROM nonces`);
  await pool.query(`DELETE FROM device_status`);
  await pool.query(`DELETE FROM blocked_devices`);
  await pool.query(`DELETE FROM users`);
  await pool.query(`DELETE FROM devices`);
  console.log('✓ Data lama dihapus');

  // ── 1. Devices ──
  console.log('\n📱 Membuat 20 perangkat...');
  for (const u of USERS) {
    const lastSeen = randItem([
      minsAgo(randInt(1, 4)),    // online (< 5 menit)
      minsAgo(randInt(1, 4)),    // online
      daysAgo(randInt(1, 3)),    // offline
      daysAgo(randInt(1, 7)),    // offline
    ]);
    await pool.query(`
      INSERT INTO devices (device_id, public_key, balance, created_at, last_seen_at)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (device_id) DO NOTHING
    `, [
      u.id,
      `PK_${hash(u.id).substring(0, 32)}`,
      randInt(50000, 5000000),
      daysAgo(randInt(30, 90)),
      lastSeen,
    ]);
  }
  console.log('✓ 20 perangkat dibuat');

  // ── 2. Users (KYC) ──
  console.log('\n👤 Membuat data KYC user...');
  for (let i = 0; i < USERS.length; i++) {
    const u = USERS[i];
    const kyc = KYC_STATUS[i];
    await pool.query(`
      INSERT INTO users (device_id, full_name, phone, nik_hash, kyc_status, kyc_verified_at, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (device_id) DO NOTHING
    `, [
      u.id, u.name, u.phone,
      hash(u.nik),
      kyc,
      kyc === 'verified' ? daysAgo(randInt(5, 60)) : null,
      daysAgo(randInt(30, 90)),
    ]);
  }
  console.log('✓ KYC data dibuat');

  // ── 3. Nonces ──
  for (const u of USERS) {
    await pool.query(`
      INSERT INTO nonces (device_id, last_nonce) VALUES ($1, $2)
      ON CONFLICT (device_id) DO NOTHING
    `, [u.id, randInt(10, 50)]);
  }

  // ── 4. Transaksi (100 TX, 80% offline) ──
  console.log('\n💸 Membuat 100 transaksi...');
  const txIds = [];
  for (let i = 0; i < 100; i++) {
    const sender   = randItem(USERS);
    let receiver   = randItem(USERS);
    while (receiver.id === sender.id) receiver = randItem(USERS);

    const txId     = `TX${Date.now()}${i}${randInt(1000,9999)}`;
    const amount   = randInt(10000, 2000000);
    const isOffline = Math.random() < 0.8; // 80% offline
    const createdAt = daysAgo(randInt(0, 30));

    // Kalau offline: last_seen_at device jauh sebelum TX
    // Kalau online: last_seen_at device dekat dengan TX
    const txHash = hash(`${txId}${sender.id}${receiver.id}${amount}`);

    await pool.query(`
      INSERT INTO transactions (tx_id, sender_id, receiver_id, amount, nonce, hash, status, created_at, flow_status, notes)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (tx_id) DO NOTHING
    `, [
      txId, sender.id, receiver.id, amount,
      randInt(1, 50), txHash, 'completed', createdAt, 'synced',
      isOffline ? 'Transaksi dilakukan saat perangkat offline' : '',
    ]);

    await pool.query(`INSERT INTO used_tx_ids (tx_id, used_at) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [txId, createdAt]);
    txIds.push({ txId, senderId: sender.id, receiverId: receiver.id, amount, createdAt });
  }
  console.log('✓ 100 transaksi dibuat (80% offline)');

  // ── 5. TX Events ──
  console.log('\n📋 Membuat tx events...');
  for (const tx of txIds.slice(0, 40)) {
    await pool.query(`
      INSERT INTO tx_events (tx_id, device_id, event_type, detail, created_at)
      VALUES ($1, $2, $3, $4, $5)
    `, [tx.txId, tx.senderId, 'tx_created', JSON.stringify({ amount: tx.amount, offline: true }), tx.createdAt]);
    await pool.query(`
      INSERT INTO tx_events (tx_id, device_id, event_type, detail, created_at)
      VALUES ($1, $2, $3, $4, $5)
    `, [tx.txId, tx.senderId, 'tx_synced', JSON.stringify({ synced_at: new Date() }), new Date()]);
  }
  console.log('✓ TX events dibuat');

  // ── 6. Disputes (10) ──
  console.log('\n⚠️  Membuat 10 dispute...');
  const issueTypes = ['dana_tidak_masuk', 'transaksi_salah', 'double_charge', 'dana_tidak_masuk', 'transaksi_gagal'];
  const disputeStatuses = ['pending', 'pending', 'pending', 'resolved_refund', 'resolved_hangus', 'pending', 'pending', 'resolved_refund', 'pending', 'pending'];
  const disputeTxs = txIds.slice(0, 10);
  const disputeIds = [];

  for (let i = 0; i < 10; i++) {
    const tx = disputeTxs[i];
    const status = disputeStatuses[i];
    const ticketNo = `TKT-${String(i+1).padStart(4,'0')}`;
    const res = await pool.query(`
      INSERT INTO disputes (reporter_id, tx_id, issue_type, description, status, ticket_number, created_at, resolved_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id
    `, [
      tx.senderId, tx.txId, randItem(issueTypes),
      `Laporan pengaduan untuk transaksi ${tx.txId}. Dana sebesar Rp ${tx.amount.toLocaleString('id-ID')} bermasalah.`,
      status, ticketNo, daysAgo(randInt(1, 10)),
      status.startsWith('resolved') ? daysAgo(randInt(0, 2)) : null,
    ]);
    disputeIds.push(res.rows[0].id);
  }
  console.log('✓ 10 dispute dibuat');

  // ── 7. Dispute Messages ──
  for (let i = 0; i < disputeIds.length; i++) {
    await pool.query(`
      INSERT INTO dispute_messages (dispute_id, sender_type, sender_id, message, created_at)
      VALUES ($1, $2, $3, $4, $5)
    `, [disputeIds[i], 'user', disputeTxs[i].senderId, 'Saya melaporkan transaksi ini karena dana tidak masuk ke penerima.', daysAgo(randInt(1, 10))]);
    if (i % 2 === 0) {
      await pool.query(`
        INSERT INTO dispute_messages (dispute_id, sender_type, sender_id, message, created_at)
        VALUES ($1, $2, $3, $4, $5)
      `, [disputeIds[i], 'admin', 'admin', 'Laporan Anda sedang kami proses. Mohon tunggu 1x24 jam.', daysAgo(randInt(0, 1))]);
    }
  }
  console.log('✓ Pesan dispute dibuat');

  // ── 8. AML Alerts ──
  console.log('\n🚨 Membuat AML alerts...');
  const amlTypes = ['high_value_transaction', 'high_frequency', 'suspicious_pattern', 'rapid_succession'];
  const amlRisks = ['high', 'medium', 'high', 'medium', 'low', 'high', 'medium'];
  for (let i = 0; i < 7; i++) {
    const u = USERS[i];
    await pool.query(`
      INSERT INTO aml_alerts (device_id, alert_type, detail, risk_level, status, created_at)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [
      u.id, randItem(amlTypes),
      JSON.stringify({ threshold: 5000000, actual: randInt(5000000, 20000000), note: 'Transaksi melebihi batas threshold AML' }),
      amlRisks[i],
      i < 4 ? 'open' : 'resolved',
      daysAgo(randInt(1, 14)),
    ]);
  }
  console.log('✓ 7 AML alerts dibuat');

  // ── 9. Audit Logs ──
  console.log('\n📝 Membuat audit logs...');
  const actions = [
    { action: 'kyc_approve', target: 'DEV001', detail: { nama: 'Budi Santoso' } },
    { action: 'kyc_approve', target: 'DEV002', detail: { nama: 'Siti Rahayu' } },
    { action: 'kyc_reject',  target: 'DEV008', detail: { reason: 'Foto KTP buram' } },
    { action: 'topup',       target: 'DEV003', detail: { amount: 500000 } },
    { action: 'topup',       target: 'DEV005', detail: { amount: 1000000 } },
    { action: 'device_lock', target: 'DEV017', detail: { reason: 'Aktivitas mencurigakan' } },
    { action: 'aml_handle',  target: 'DEV001', detail: { decision: 'dismiss' } },
    { action: 'dispute_resolve', target: 'TKT-0004', detail: { decision: 'resolved_refund' } },
    { action: 'config_update', target: 'aml_threshold', detail: { old: '5000000', new: '7500000' } },
    { action: 'kyc_approve', target: 'DEV010', detail: { nama: 'Yuli Astuti' } },
  ];
  for (const a of actions) {
    await pool.query(`
      INSERT INTO audit_logs (admin_user, action, target, detail, ip_address, created_at)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, ['admin', a.action, a.target, JSON.stringify(a.detail), '180.244.xxx.xxx', daysAgo(randInt(0, 14))]);
  }
  console.log('✓ 10 audit logs dibuat');

  // ── 10. Held Balances ──
  console.log('\n💰 Membuat held balances...');
  for (let i = 0; i < 5; i++) {
    const tx = txIds[90 + i];
    await pool.query(`
      INSERT INTO held_balances (tx_id, device_id, amount, status, reason, created_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (tx_id) DO NOTHING
    `, [
      tx.txId, tx.senderId, tx.amount,
      i < 3 ? 'held' : 'released',
      'Dana ditahan karena ada dispute aktif',
      tx.createdAt,
    ]);
  }
  console.log('✓ 5 held balances dibuat');

  // ── 11. Top Up Fees ──
  for (let i = 0; i < 8; i++) {
    const u = USERS[i];
    const topupAmount = randInt(100000, 2000000);
    await pool.query(`
      INSERT INTO top_up_fees (device_id, top_up_amount, fee_amount, created_at)
      VALUES ($1, $2, $3, $4)
    `, [u.id, topupAmount, Math.floor(topupAmount * 0.01), daysAgo(randInt(1, 30))]);
  }

  console.log('\n══════════════════════════════════════');
  console.log('✅ Seed data berhasil dibuat!');
  console.log('   20 user | 100 TX | 10 dispute | 7 AML | 10 audit log');
  console.log('══════════════════════════════════════');

  await pool.end();
}

seed().catch(e => {
  console.error('✖ Seed gagal:', e.message);
  process.exit(1);
});