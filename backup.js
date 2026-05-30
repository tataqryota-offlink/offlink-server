// ─────────────────────────────────────────────
// OFFLINK DATABASE BACKUP + UPLOAD GOOGLE DRIVE
// Jalankan: node backup.js
// ─────────────────────────────────────────────
require('dotenv').config();
const { Pool }   = require('pg');
const fs         = require('fs');
const path       = require('path');
const { google } = require('googleapis');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const GDRIVE_FOLDER_ID = '1nhc03mBk9P6TMpU9nyYKzYIMepJD-vBw';
const TOKEN_FILE       = path.join(__dirname, 'gdrive-token.json');
const CLIENT_FILE      = path.join(__dirname, 'oauth-client.json');

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

function getDriveClient() {
  const keys   = JSON.parse(fs.readFileSync(CLIENT_FILE));
  const client = keys.installed || keys.web;
  const oauth2 = new google.auth.OAuth2(
    client.client_id,
    client.client_secret,
    'http://localhost:3001/callback'
  );
  const tokens = JSON.parse(fs.readFileSync(TOKEN_FILE));
  oauth2.setCredentials(tokens);
  // Simpan token baru kalau di-refresh otomatis
  oauth2.on('tokens', (t) => {
    const current = JSON.parse(fs.readFileSync(TOKEN_FILE));
    fs.writeFileSync(TOKEN_FILE, JSON.stringify({ ...current, ...t }, null, 2));
  });
  return google.drive({ version: 'v3', auth: oauth2 });
}

async function uploadFile(drive, filepath, filename, mimeType) {
  // Hapus file lama dengan nama sama kalau ada
  const existing = await drive.files.list({
    q: `name='${filename}' and '${GDRIVE_FOLDER_ID}' in parents and trashed=false`,
    fields: 'files(id)',
  });
  for (const f of existing.data.files) {
    await drive.files.delete({ fileId: f.id });
  }
  await drive.files.create({
    requestBody: { name: filename, parents: [GDRIVE_FOLDER_ID] },
    media: { mimeType, body: fs.createReadStream(filepath) },
  });
}

async function backup() {
  const sekarang = new Date();
  const tanggal  = sekarang.toISOString().split('T')[0];
  const jam      = sekarang.toTimeString().split(' ')[0].replace(/:/g, '-');
  const filename = `backup_${tanggal}_${jam}.json`;
  const filepath = path.join(__dirname, 'backups', filename);

  if (!fs.existsSync(path.join(__dirname, 'backups'))) {
    fs.mkdirSync(path.join(__dirname, 'backups'));
  }

  const hasil = {
    info: { waktu_backup: sekarang.toLocaleString('id-ID'), tanggal, sistem: 'OFFLINK Server' },
    data: {}
  };

  console.log('┌─────────────────────────────────────┐');
  console.log('│     OFFLINK — BACKUP DATABASE       │');
  console.log('└─────────────────────────────────────┘');
  console.log(`📅 Tanggal : ${sekarang.toLocaleString('id-ID')}`);
  console.log(`💾 File    : ${filename}`);
  console.log('──────────────────────────────────────');

  let totalBaris = 0, berhasil = 0, gagal = 0;

  for (const tabel of TABLES) {
    try {
      const res = await pool.query(`SELECT * FROM ${tabel.nama}`);
      hasil.data[tabel.nama] = res.rows;
      totalBaris += res.rows.length;
      berhasil++;
      console.log(`✓ ${tabel.label.padEnd(28)} : ${res.rows.length} baris`);
    } catch (e) {
      hasil.data[tabel.nama] = [];
      gagal++;
      console.log(`⚠  ${tabel.label.padEnd(28)} : Gagal (${e.message})`);
    }
  }

  fs.writeFileSync(filepath, JSON.stringify(hasil, null, 2));
  console.log('──────────────────────────────────────');
  console.log(`📊 Total data  : ${totalBaris} baris`);
  console.log(`✓ Berhasil    : ${berhasil} tabel`);
  if (gagal > 0) console.log(`⚠  Gagal       : ${gagal} tabel`);
  console.log(`💾 Disimpan ke : backups/${filename}`);

  // Upload ke Google Drive
  console.log('──────────────────────────────────────');
  console.log('☁ Mengupload ke Google Drive...');
  try {
    const drive = getDriveClient();

    // Upload backup DB
    await uploadFile(drive, filepath, filename, 'application/json');
    console.log(`✓ Backup DB diupload: ${filename}`);

    // Upload file kode server
    const kodeFiles = ['index.js', 'admin.html', 'backup.js', 'package.json'];
    for (const f of kodeFiles) {
      const fp = path.join(__dirname, f);
      if (!fs.existsSync(fp)) continue;
      await uploadFile(drive, fp, f, 'text/plain');
      console.log(`✓ Kode diupload: ${f}`);
    }

    // Upload Flutter — pubspec.yaml
    const flutterRoot = 'c:\\offlink';
    const flutterFiles = ['pubspec.yaml', 'pubspec.lock'];
    for (const f of flutterFiles) {
      const fp = path.join(flutterRoot, f);
      if (!fs.existsSync(fp)) continue;
      await uploadFile(drive, fp, `flutter_${f}`, 'text/plain');
      console.log(`✓ Flutter diupload: ${f}`);
    }

    // Upload semua file .dart di lib/
    const libDir = path.join(flutterRoot, 'lib');
    if (fs.existsSync(libDir)) {
      const dartFiles = fs.readdirSync(libDir, { withFileTypes: true })
        .filter(f => f.isFile() && f.name.endsWith('.dart'))
        .map(f => f.name);
      for (const f of dartFiles) {
        const fp = path.join(libDir, f);
        await uploadFile(drive, fp, `flutter_lib_${f}`, 'text/plain');
        console.log(`✓ Flutter lib diupload: ${f}`);
      }
    }

    console.log('✓ Semua file berhasil diupload ke Google Drive');
  } catch (e) {
    console.log(`⚠  Upload Google Drive gagal: ${e.message}`);
    console.log('   (Backup lokal tetap tersimpan)');
  }
  console.log('══════════════════════════════════════');

  await pool.end();
}

backup().catch(e => {
  console.error('✖ Backup gagal:', e.message);
  process.exit(1);
});