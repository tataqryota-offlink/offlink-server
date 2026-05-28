// ─────────────────────────────────────────────
// OFFLINK DATABASE BACKUP
// Jalankan: node backup.js
// ─────────────────────────────────────────────
require('dotenv').config();
const { Pool } = require('pg');
const fs       = require('fs');
const path     = require('path');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const TABLES = [
  { nama: 'devices',           label: 'Perangkat' },
  { nama: 'transactions',      label: 'Transaksi' },
  { nama: 'nonces',            label: 'Nonce Anti Double Spend' },
  { nama: 'used_tx_ids',       label: 'ID Transaksi Terpakai' },
  { nama: 'held_balances',     label: 'Dana Tertahan' },
  { nama: 'blocked_devices',   label: 'Perangkat Diblokir' },
  { nama: 'tx_events',         label: 'Event Transaksi' },
  { nama: 'device_status',     label: 'Status Perangkat' },
  { nama: 'top_up_fees',       label: 'Fee Top Up' },
  { nama: 'disputes',          label: 'Pengaduan' },
  { nama: 'dispute_messages',  label: 'Pesan Pengaduan' },
  { nama: 'system_config',     label: 'Konfigurasi Sistem' },
  { nama: 'aml_alerts',        label: 'Peringatan AML' },
  { nama: 'audit_logs',        label: 'Log Audit' },
  { nama: 'users',             label: 'Pengguna' },
];

async function backup() {
  const sekarang = new Date();
  const tanggal  = sekarang.toISOString().split('T')[0];
  const jam      = sekarang.toTimeString().split(' ')[0].replace(/:/g, '-');
  const filename = `backup_${tanggal}_${jam}.json`;
  const filepath = path.join(__dirname, 'backups', filename);

  // Buat folder backups kalau belum ada
  if (!fs.existsSync(path.join(__dirname, 'backups'))) {
    fs.mkdirSync(path.join(__dirname, 'backups'));
  }

  const hasil = {
    info: {
      waktu_backup : sekarang.toLocaleString('id-ID'),
      tanggal      : tanggal,
      sistem       : 'OFFLINK Server',
    },
    data: {}
  };

  console.log('╔════════════════════════════════════╗');
  console.log('║     OFFLINK — BACKUP DATABASE      ║');
  console.log('╚════════════════════════════════════╝');
  console.log(`📅 Tanggal  : ${sekarang.toLocaleString('id-ID')}`);
  console.log(`💾 File     : ${filename}`);
  console.log('────────────────────────────────────');

  let totalBaris = 0;
  let berhasil   = 0;
  let gagal      = 0;

  for (const tabel of TABLES) {
    try {
      const res = await pool.query(`SELECT * FROM ${tabel.nama}`);
      hasil.data[tabel.nama] = res.rows;
      totalBaris += res.rows.length;
      berhasil++;
      console.log(`✅ ${tabel.label.padEnd(28)} : ${res.rows.length} baris`);
    } catch (e) {
      hasil.data[tabel.nama] = [];
      gagal++;
      console.log(`⚠️  ${tabel.label.padEnd(28)} : Gagal (${e.message})`);
    }
  }

  fs.writeFileSync(filepath, JSON.stringify(hasil, null, 2));

  console.log('────────────────────────────────────');
  console.log(`📊 Total data  : ${totalBaris} baris`);
  console.log(`✅ Berhasil    : ${berhasil} tabel`);
  if (gagal > 0)
  console.log(`⚠️  Gagal       : ${gagal} tabel`);
  console.log(`💾 Disimpan ke : backups/${filename}`);
  console.log('════════════════════════════════════');

  await pool.end();
}

backup().catch(e => {
  console.error('❌ Backup gagal:', e.message);
  process.exit(1);
});