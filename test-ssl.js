require('dotenv').config();
const { Pool } = require('pg');
const p = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});
p.query('SELECT 1')
  .then(() => { console.log('SSL OK'); p.end(); })
  .catch(e => { console.log('SSL GAGAL:', e.message); p.end(); });