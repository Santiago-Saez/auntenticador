'use strict';
// Sesiones opacas servidas en cookie httpOnly + SameSite.
//
// - Token opaco aleatorio (256 bits) en cookie `sid`; en BD solo su hash.
// - Cookie: httpOnly (JS no la lee -> frena robo por XSS), SameSite=Lax
//   (el navegador no la envía en POST cross-site -> mitiga CSRF; además
//   hay chequeo de Origin), Secure en producción (solo HTTPS), Path=/.
// - Rotación en cada login: cada POST /api/login crea una sesión nueva;
//   nunca se reutiliza ni se acepta un id propuesto por el cliente
//   (defensa contra fijación de sesión).
// - Revocación: logout revoca la actual; "cerrar todas" revoca el resto;
//   reset de contraseña revoca TODAS (incluida la actual).

const { SESSION_TTL_MS, COOKIE_NAME, isProd } = require('./config');
const { q } = require('./db');
const { randomToken, hashToken } = require('./crypto');

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd, // en desarrollo va false para http://localhost
    path: '/',
    maxAge: SESSION_TTL_MS,
  };
}

function createSession(userId, ip, userAgent) {
  const raw = randomToken();
  const now = Date.now();
  q.createSession.run(userId, hashToken(raw), now, now + SESSION_TTL_MS, ip || null, (userAgent || '').slice(0, 300));
  return raw;
}

function setSessionCookie(res, raw) {
  res.cookie(COOKIE_NAME, raw, cookieOptions());
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

// Devuelve la fila de sesión + usuario si la cookie es válida, o null.
function authFromRequest(req) {
  const raw = req.cookies && req.cookies[COOKIE_NAME];
  if (!raw || typeof raw !== 'string' || raw.length > 256) return null;
  const row = q.findSession.get(hashToken(raw));
  if (!row) return null;
  if (row.revoked_at) return null;
  if (row.expires_at < Date.now()) return null;
  const user = q.findUserById.get(row.user_id);
  if (!user) return null;
  return { session: row, user };
}

function revokeSessionById(id) {
  q.revokeSession.run(Date.now(), id);
}

module.exports = {
  createSession, setSessionCookie, clearSessionCookie,
  authFromRequest, revokeSessionById,
};
