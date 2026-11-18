'use strict';

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const isProd = process.env.NODE_ENV === 'production';

const COOKIE_NAME = 'sid';
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 7 * 24 * 60 * 60 * 1000);
const VERIFY_TTL_MS = Number(process.env.VERIFY_TTL_MS || 24 * 60 * 60 * 1000);
const RESET_TTL_MS = Number(process.env.RESET_TTL_MS || 60 * 60 * 1000);

// Límites de intentos (ventana deslizante + bloqueo temporal)
const LIMITS = {
  // Login: 5 fallos / 15 min por IP y por cuenta -> bloqueo 15 min
  loginByIp:      { max: 20, windowMs: 15 * 60 * 1000, blockMs: 15 * 60 * 1000 },
  loginByAccount: { max: 5,  windowMs: 15 * 60 * 1000, blockMs: 15 * 60 * 1000 },
  // Registro: 10 / hora por IP -> bloqueo 1 h (anti-enumeración y anti-spam)
  registerByIp:   { max: 10, windowMs: 60 * 60 * 1000, blockMs: 60 * 60 * 1000 },
  // Recuperación: 5 / hora por IP y por cuenta -> bloqueo 1 h
  recoverByIp:      { max: 5, windowMs: 60 * 60 * 1000, blockMs: 60 * 60 * 1000 },
  recoverByAccount: { max: 5, windowMs: 60 * 60 * 1000, blockMs: 60 * 60 * 1000 },
  // Verificación / reset: 10 / hora por IP
  verifyByIp: { max: 10, windowMs: 60 * 60 * 1000, blockMs: 60 * 60 * 1000 },
  resetByIp:  { max: 10, windowMs: 60 * 60 * 1000, blockMs: 60 * 60 * 1000 },
};

module.exports = {
  PORT, BASE_URL, isProd,
  COOKIE_NAME, SESSION_TTL_MS, VERIFY_TTL_MS, RESET_TTL_MS,
  LIMITS,
};
