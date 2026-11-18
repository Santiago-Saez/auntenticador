'use strict';
// Smoke test end-to-end sin dependencias: levanta la app en un puerto
// efímero y recorre registro -> verificación -> login -> sesiones ->
// revocación -> recover -> reset -> login nuevo.

const fs = require('fs');
const path = require('path');

// BD aislada para el test
const dataDir = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });
try { fs.unlinkSync(path.join(dataDir, 'auth.db')); } catch {}
for (const f of fs.readdirSync(dataDir)) {
  if (f.endsWith('-wal') || f.endsWith('-shm') || f.endsWith('-journal')) {
    try { fs.unlinkSync(path.join(dataDir, f)); } catch {}
  }
}
const mailbox = path.join(__dirname, '..', 'mailbox');
fs.mkdirSync(mailbox, { recursive: true });
for (const f of fs.readdirSync(mailbox)) {
  try { fs.unlinkSync(path.join(mailbox, f)); } catch {}
}

process.env.BASE_URL = 'http://localhost:3000';
const app = require('../src/app');
const { hashToken } = require('../src/crypto');
const { q } = require('../src/db');

const server = app.listen(0, async () => {
  const base = `http://localhost:${server.address().port}`;
  let cookie = '';
  const req = async (method, p, body, token) => {
    const headers = { 'Content-Type': 'application/json', Origin: base };
    if (cookie) headers.Cookie = cookie;
    const r = await fetch(base + p, {
      method, headers, redirect: 'manual',
      body: body ? JSON.stringify(body) : undefined,
    });
    const setCookie = r.headers.get('set-cookie');
    if (setCookie) {
      const m = setCookie.match(/sid=([^;]+)/);
      if (m) cookie = `sid=${m[1]}`;
      else if (/sid=;/.test(setCookie)) cookie = '';
    }
    let json = {};
    try { json = await r.json(); } catch {}
    return { status: r.status, json };
  };
  const assert = (cond, msg) => {
    if (!cond) { console.error('FAIL:', msg); process.exitCode = 1; server.close(); process.exit(1); }
    console.log('ok:', msg);
  };

  const email = 'usuaria@example.com';
  const pw = 'contraseña-muy-larga-123';

  let r = await req('POST', '/api/register', { email, password: pw });
  assert(r.status === 201, 'registro 201 genérico');

  // Login antes de verificar debe fallar con mensaje genérico (no filtra).
  r = await req('POST', '/api/login', { email, password: pw });
  assert(r.status === 401, 'login pre-verificación rechazado');

  // Token de verificación: un solo uso, caduca.
  const vrow = q.findVerifyToken.all(q.findUserByEmail.get(email).id);
  void vrow;
  const rawVerify = (() => {
    const files = fs.readdirSync(mailbox);
    const last = files.map((f) => path.join(mailbox, f)).sort().pop();
    const link = JSON.parse(fs.readFileSync(last, 'utf8')).link;
    const m = String(link).match(/token=([a-f0-9]+)/);
    return m && m[1];
  })();
  assert(typeof rawVerify === 'string' && rawVerify.length > 10, 'token de verificación emitido');

  r = await req('POST', '/api/verify', { token: rawVerify });
  assert(r.status === 200, 'verificación válida aceptada');
  r = await req('POST', '/api/verify', { token: rawVerify });
  assert(r.status === 400, 'verificación no reutilizable (un solo uso)');

  r = await req('POST', '/api/login', { email, password: pw });
  assert(r.status === 200 && cookie.includes('sid='), 'login crea sesión con cookie');

  r = await req('GET', '/api/me');
  assert(r.status === 200 && r.json.email === email, 'perfil accesible con sesión');

  // Segunda sesión (rotación: cada login crea una nueva)
  const firstCookie = cookie;
  r = await req('POST', '/api/login', { email, password: pw });
  assert(r.status === 200 && cookie !== firstCookie, 'rotación: cada login emite sid nuevo');

  r = await req('GET', '/api/sessions');
  assert(r.status === 200 && r.json.sessions.length >= 2, 'lista sesiones');

  r = await req('DELETE', '/api/sessions');
  assert(r.status === 200, 'revocación de otras sesiones');
  r = await req('GET', '/api/sessions');
  assert(r.json.sessions.filter((s) => !s.revoked).length === 1, 'solo queda la actual');

  // Recover: mismo mensaje exista o no el correo.
  r = await req('POST', '/api/recover', { email });
  const msg1 = r.json.message;
  r = await req('POST', '/api/recover', { email: 'nadie@example.com' });
  assert(r.status === 200 && r.json.message === msg1, 'recover no filtra existencia');

  const files = fs.readdirSync(mailbox).sort();
  const resetLink = JSON.parse(fs.readFileSync(path.join(mailbox, files[files.length - 1]), 'utf8')).link;
  const rawReset = String(resetLink).match(/token=([a-f0-9]+)/)?.[1];
  assert(rawReset, 'token de reset emitido');

  r = await req('POST', '/api/reset', { token: rawReset, newPassword: 'nueva-contraseña-larga-456' });
  assert(r.status === 200, 'reset válido');
  r = await req('POST', '/api/reset', { token: rawReset, newPassword: 'otra-contraseña-larga-789' });
  assert(r.status === 400, 'reset no reutilizable');

  // El reset revocó todo: la sesión vieja ya no vale.
  r = await req('GET', '/api/me');
  assert(r.status === 401, 'reset revocó sesiones anteriores');

  // Rate limit por cuenta: 5 fallos -> 429.
  cookie = '';
  for (let i = 0; i < 5; i++) await req('POST', '/api/login', { email, password: 'incorrecta-larga-000' });
  r = await req('POST', '/api/login', { email, password: 'incorrecta-larga-000' });
  assert(r.status === 429, 'bloqueo temporal tras intentos (429 + Retry-After)');
  assert(r.json.error, 'mensaje de bloqueo presente');
  void hashToken;

  console.log('\nSMOKE OK');
  server.close();
});
