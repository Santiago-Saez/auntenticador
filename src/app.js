'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const config = require('./config');
const { q } = require('./db');
const { randomToken, hashToken } = require('./crypto');
const { hashPassword, verifyPassword } = require('./passwords');
const { sendVerificationEmail, sendPasswordResetEmail } = require('./mailer');
const rl = require('./rateLimit');
const { normalizeEmail, isValidEmail, passwordError, clientIp } = require('./validate');
const { createSession, setSessionCookie, clearSessionCookie, authFromRequest, revokeSessionById } = require('./session');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());

// Cabeceras de seguridad básicas sin dependencias.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (config.isProd) res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
});

// Defensa CSRF para cookie-auth: exige que Origin corresponda al mismo
// host que recibe la petición (comparación de origen, no valor fijo, para
// que funcione en cualquier puerto/entorno). SameSite=Lax ya bloquea el
// envío cross-site de la cookie; esto cubre el resto.
function csrfCheck(req, res, next) {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const origin = req.headers.origin;
    if (origin) {
      try {
        const oHost = new URL(origin).host;
        const hHost = String(req.headers.host || '').split(',')[0].trim();
        if (!hHost || oHost !== hHost) return res.status(403).json({ error: 'Origen no permitido.' });
      } catch {
        return res.status(403).json({ error: 'Origen no permitido.' });
      }
    }
  }
  next();
}
app.use(csrfCheck);

function rateLimited(res, retryAfterMs) {
  res.setHeader('Retry-After', Math.ceil(retryAfterMs / 1000));
  return res.status(429).json({ error: 'Demasiados intentos. Inténtalo más tarde.' });
}

// Adjunta { session, user } o null a cada request.
app.use((req, _res, next) => {
  req.auth = authFromRequest(req);
  next();
});

function requireAuth(req, res, next) {
  if (!req.auth) return res.status(401).json({ error: 'No autenticado.' });
  next();
}

const GENERIC_REGISTER_MSG = 'Si el correo es válido, recibirás instrucciones para verificar tu cuenta.';
const GENERIC_RECOVER_MSG = 'Si el correo existe, recibirás instrucciones para recuperar tu contraseña.';
const GENERIC_LOGIN_MSG = 'Credenciales inválidas.';

// Pequeña espera uniforme para no filtrar por timing si el correo existe.
function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------- Registro ----------
app.post('/api/register', async (req, res) => {
  const ip = clientIp(req);
  const key = `register:ip:${ip}`;
  const c = rl.check(key, config.LIMITS.registerByIp);
  if (!c.allowed) return rateLimited(res, c.retryAfterMs);

  const email = normalizeEmail(req.body.email);
  const { password } = req.body;

  if (!isValidEmail(email)) return res.status(400).json({ error: 'Correo inválido.' });
  const pwErr = passwordError(password);
  if (pwErr) return res.status(400).json({ error: pwErr });

  try {
    const existing = q.findUserByEmail.get(email);
    if (existing) {
      // No filtrar si el correo existe: misma respuesta 201 y reenviamos
      // verificación solo si sigue sin verificar (sin revelar el estado).
      if (!existing.email_verified_at) {
        const raw = randomToken();
        q.invalidateUserVerifyTokens.run(Date.now(), existing.id);
        q.createVerifyToken.run(existing.id, hashToken(raw), Date.now() + config.VERIFY_TTL_MS, Date.now());
        sendVerificationEmail(email, `${config.BASE_URL}/verify.html?token=${raw}`);
      }
      return res.status(201).json({ message: GENERIC_REGISTER_MSG });
    }

    const hash = await hashPassword(password);
    const info = q.createUser.run(email, hash, Date.now());
    const raw = randomToken();
    q.createVerifyToken.run(info.lastInsertRowid, hashToken(raw), Date.now() + config.VERIFY_TTL_MS, Date.now());
    sendVerificationEmail(email, `${config.BASE_URL}/verify.html?token=${raw}`);
    return res.status(201).json({ message: GENERIC_REGISTER_MSG });
  } catch (e) {
    // Carrera de registro duplicado: responder igual (no filtrar).
    if (String(e.message).includes('UNIQUE')) return res.status(201).json({ message: GENERIC_REGISTER_MSG });
    throw e;
  }
});

// ---------- Verificación (un solo uso, con caducidad) ----------
async function consumeVerificationToken(raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 256) return { ok: false };
  const row = q.findVerifyToken.get(hashToken(raw));
  if (!row) return { ok: false };
  if (row.used_at) return { ok: false }; // un solo uso
  if (row.expires_at < Date.now()) return { ok: false, expired: true };
  q.markVerifyTokenUsed.run(Date.now(), row.id);
  q.setVerified.run(Date.now(), row.user_id);
  q.invalidateUserVerifyTokens.run(Date.now(), row.user_id);
  return { ok: true };
}

app.post('/api/verify', async (req, res) => {
  const ip = clientIp(req);
  const key = `verify:ip:${ip}`;
  const c = rl.check(key, config.LIMITS.verifyByIp);
  if (!c.allowed) return rateLimited(res, c.retryAfterMs);

  const r = await consumeVerificationToken(req.body.token || req.query.token);
  if (!r.ok) {
    rl.fail(key, config.LIMITS.verifyByIp);
    return res.status(400).json({ error: 'Token inválido o caducado.' });
  }
  return res.json({ message: 'Correo verificado. Ya puedes iniciar sesión.' });
});

// Reenvío genérico (no revela si existe ni si ya está verificado).
app.post('/api/resend-verification', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (isValidEmail(email)) {
    const user = q.findUserByEmail.get(email);
    if (user && !user.email_verified_at) {
      const raw = randomToken();
      q.invalidateUserVerifyTokens.run(Date.now(), user.id);
      q.createVerifyToken.run(user.id, hashToken(raw), Date.now() + config.VERIFY_TTL_MS, Date.now());
      sendVerificationEmail(email, `${config.BASE_URL}/verify.html?token=${raw}`);
    }
  }
  await delay(300);
  return res.json({ message: GENERIC_REGISTER_MSG });
});

// ---------- Login con rotación ----------
app.post('/api/login', async (req, res) => {
  const ip = clientIp(req);
  const email = normalizeEmail(req.body.email);
  const { password } = req.body;

  if (!isValidEmail(email) || typeof password !== 'string') {
    return res.status(401).json({ error: GENERIC_LOGIN_MSG });
  }

  const ipKey = `login:ip:${ip}`;
  const accKey = `login:acc:${email}`;
  const both = rl.checkBoth(ipKey, accKey,
    { ip: config.LIMITS.loginByIp, account: config.LIMITS.loginByAccount });
  if (!both.allowed) return rateLimited(res, both.retryAfterMs);

  const user = q.findUserByEmail.get(email);
  // Usuario inexistente o sin verificar: hash dummy + mensaje genérico
  // para no filtrar existencia ni estado (oráculo de enumeración).
  if (!user) {
    await hashPassword('dummy-fallback-to-equalize-timing-0123456789');
    rl.failBoth(ipKey, accKey,
      { ip: config.LIMITS.loginByIp, account: config.LIMITS.loginByAccount });
    return res.status(401).json({ error: GENERIC_LOGIN_MSG });
  }

  let okPw = false;
  try {
    okPw = await verifyPassword(user.password_hash, password);
  } catch {
    okPw = false;
  }
  if (!okPw || !user.email_verified_at) {
    rl.failBoth(ipKey, accKey,
      { ip: config.LIMITS.loginByIp, account: config.LIMITS.loginByAccount });
    // OJO: mismo mensaje haya o no verificación, para no filtrar.
    return res.status(401).json({ error: GENERIC_LOGIN_MSG });
  }

  // Éxito: perdonar fallos de la cuenta y ROTAR sesión (siempre nueva).
  rl.okBoth(ipKey, accKey);
  const raw = createSession(user.id, ip, req.headers['user-agent']);
  setSessionCookie(res, raw);
  return res.json({ message: 'Sesión iniciada.' });
});

// ---------- Logout ----------
app.post('/api/logout', (req, res) => {
  if (req.auth) revokeSessionById(req.auth.session.id);
  clearSessionCookie(res);
  return res.json({ message: 'Sesión cerrada.' });
});

// ---------- Recuperación sin oráculo ----------
app.post('/api/recover', async (req, res) => {
  const ip = clientIp(req);
  const email = normalizeEmail(req.body.email);
  const ipKey = `recover:ip:${ip}`;
  const accKey = `recover:acc:${email}`;

  const both = rl.checkBoth(ipKey, accKey,
    { ip: config.LIMITS.recoverByIp, account: config.LIMITS.recoverByAccount });
  if (!both.allowed) return rateLimited(res, both.retryAfterMs);

  // Respuesta idéntica exista o no el correo, con retardo similar.
  const t0 = Date.now();
  if (isValidEmail(email)) {
    const user = q.findUserByEmail.get(email);
    if (user) {
      const raw = randomToken();
      q.invalidateUserResetTokens.run(Date.now(), user.id);
      q.createResetToken.run(user.id, hashToken(raw), Date.now() + config.RESET_TTL_MS, Date.now());
      sendPasswordResetEmail(email, `${config.BASE_URL}/reset.html?token=${raw}`);
    }
  }
  const elapsed = Date.now() - t0;
  if (elapsed < 300) await delay(300 - elapsed);

  if (isValidEmail(email)) {
    rl.fail(ipKey, config.LIMITS.recoverByIp);
    rl.fail(accKey, config.LIMITS.recoverByAccount);
  }
  return res.json({ message: GENERIC_RECOVER_MSG });
});

// ---------- Reset (un solo uso, caduca en 1 h, revoca todo) ----------
app.post('/api/reset', async (req, res) => {
  const ip = clientIp(req);
  const key = `reset:ip:${ip}`;
  const c = rl.check(key, config.LIMITS.resetByIp);
  if (!c.allowed) return rateLimited(res, c.retryAfterMs);

  const { token } = req.body;
  const pwErr = passwordError(req.body.newPassword);
  if (pwErr) return res.status(400).json({ error: pwErr });

  if (!token || typeof token !== 'string') {
    rl.fail(key, config.LIMITS.resetByIp);
    return res.status(400).json({ error: 'Token inválido o caducado.' });
  }
  const row = q.findResetToken.get(hashToken(token));
  if (!row || row.used_at || row.expires_at < Date.now()) {
    rl.fail(key, config.LIMITS.resetByIp);
    // Mensaje idéntico para inválido / usado / caducado (no filtrar).
    return res.status(400).json({ error: 'Token inválido o caducado.' });
  }

  const hash = await hashPassword(req.body.newPassword);
  q.updatePassword.run(hash, row.user_id);
  q.markResetTokenUsed.run(Date.now(), row.id);
  q.invalidateUserResetTokens.run(Date.now(), row.user_id);
  // Tras cambiar la contraseña, revocar TODAS las sesiones (el atacante
  // con una sesión robada queda fuera; el usuario hace login de nuevo).
  q.revokeAllSessions.run(Date.now(), row.user_id);

  return res.json({ message: 'Contraseña actualizada. Inicia sesión de nuevo.' });
});

// ---------- Perfil / sesiones ----------
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.auth.user.email, verified: !!req.auth.user.email_verified_at });
});

app.get('/api/sessions', requireAuth, (req, res) => {
  const rows = q.listSessions.all(req.auth.user.id).map((s) => ({
    id: s.id,
    current: s.id === req.auth.session.id,
    createdAt: new Date(s.created_at).toISOString(),
    expiresAt: new Date(s.expires_at).toISOString(),
    revoked: !!s.revoked_at,
    ip: s.ip,
    userAgent: s.user_agent,
  }));
  res.json({ sessions: rows });
});

// Revocar TODAS las sesiones desde el perfil (excepto la actual por
// defecto; con ?all=true también la actual y cierra sesión).
app.delete('/api/sessions', requireAuth, (req, res) => {
  if (req.query.all === 'true') {
    q.revokeAllSessions.run(Date.now(), req.auth.user.id);
    clearSessionCookie(res);
    return res.json({ message: 'Todas las sesiones revocadas.' });
  }
  q.revokeAllExcept.run(Date.now(), req.auth.user.id, req.auth.session.id);
  return res.json({ message: 'Otras sesiones revocadas. Esta sigue activa.' });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const pwErr = passwordError(req.body.newPassword);
  if (pwErr) return res.status(400).json({ error: pwErr });
  const user = q.findUserById.get(req.auth.user.id);
  const okPw = await verifyPassword(user.password_hash, String(req.body.currentPassword || ''));
  if (!okPw) return res.status(401).json({ error: 'La contraseña actual no es correcta.' });
  q.updatePassword.run(await hashPassword(req.body.newPassword), user.id);
  q.revokeAllExcept.run(Date.now(), user.id, req.auth.session.id);
  return res.json({ message: 'Contraseña actualizada. Otras sesiones cerradas.' });
});

// Frontend estático
app.use(express.static(path.join(__dirname, '..', 'public')));

// Manejo de errores: no filtrar detalles internos.
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Error interno.' });
});

module.exports = app;
