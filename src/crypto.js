'use strict';
// Utilidades criptográficas: tokens opacos de un solo uso.
// El token "raw" solo viaja por correo / cookie. En BD solo se guarda
// su hash SHA-256, así una filtración de la BD no permite suplantar.

const crypto = require('crypto');

function randomToken(bytes = 32) {
  // 32 bytes = 256 bits de entropía, codificados en hex (64 chars).
  return crypto.randomBytes(bytes).toString('hex');
}

function hashToken(raw) {
  return crypto.createHash('sha256').update(String(raw), 'utf8').digest('hex');
}

function safeEqualHex(a, b) {
  const ba = Buffer.from(String(a), 'hex');
  const bb = Buffer.from(String(b), 'hex');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

module.exports = { randomToken, hashToken, safeEqualHex };
