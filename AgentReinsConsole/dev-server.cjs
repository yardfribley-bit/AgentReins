// Local preview only. No enterprise data storage or upload listener.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const files = { '/': ['index.html', 'text/html'], '/audit.css': ['audit.css', 'text/css'], '/audit.js': ['audit.js', 'text/javascript'] };
http.createServer((req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
  if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname === '/api/audit/cases') {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'audit_service_not_configured' }));
  }
  const file = files[url.pathname];
  if (!file) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'Content-Type': file[1] + '; charset=utf-8' });
  fs.createReadStream(path.join(__dirname, 'public', file[0])).pipe(res);
}).listen(8899, '127.0.0.1', () => console.log('Enterprise console preview: http://127.0.0.1:8899/'));
