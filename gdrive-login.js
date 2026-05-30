const { google } = require('googleapis');
const fs = require('fs');
const http = require('http');
const url = require('url');

const keys = JSON.parse(fs.readFileSync('oauth-client.json'));
const client = keys.installed || keys.web;

const oauth2 = new google.auth.OAuth2(
  client.client_id,
  client.client_secret,
  'http://localhost:3001/callback'
);

const authUrl = oauth2.generateAuthUrl({
  access_type: 'offline',
  scope: ['https://www.googleapis.com/auth/drive.file'],
});

console.log('\nBuka URL ini di browser:\n');
console.log(authUrl);
console.log('\nMenunggu login...');

const server = http.createServer(async (req, res) => {
  const code = url.parse(req.url, true).query.code;
  if (!code) { res.end('Tidak ada code'); return; }
  try {
    const { tokens } = await oauth2.getToken(code);
    fs.writeFileSync('gdrive-token.json', JSON.stringify(tokens, null, 2));
    res.end('Login berhasil! Tutup tab ini dan kembali ke terminal.');
    console.log('\nToken tersimpan di gdrive-token.json');
    server.close();
  } catch(e) {
    res.end('Error: ' + e.message);
    console.error('Error:', e.message);
  }
}).listen(3001);
