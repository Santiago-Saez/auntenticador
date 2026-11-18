'use strict';
// Validación y normalización de entradas.

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  // Suficiente para un sistema propio sin dependencias de validación:
  // formato básico + longitud acotada. La verificación real la hace el
  // correo con token (que demuestra control del buzón).
  if (typeof email !== 'string') return false;
  if (email.length < 3 || email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Política: mínimo 12 caracteres, máximo 128.
// Por qué: NIST 800-63B pide mínimo 8 y sin reglas de composición
// absurdas; 12 da ~70+ bits con contraseñas normales y frena el
// cracking. Máximo 128 evita DoS por hashes gigantes (Argon2 es caro)
// sin molestar a usuarios con gestores de contraseñas.
function passwordError(password) {
  if (typeof password !== 'string') return 'Contraseña inválida.';
  if (password.length < 12) return 'La contraseña debe tener al menos 12 caracteres.';
  if (password.length > 128) return 'La contraseña no puede superar 128 caracteres.';
  return null;
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.ip || req.socket.remoteAddress || 'unknown';
}

module.exports = { normalizeEmail, isValidEmail, passwordError, clientIp };
