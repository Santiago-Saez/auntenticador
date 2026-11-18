'use strict';
// Límite de intentos por IP y por cuenta con bloqueo temporal.
// Ventana deslizante en memoria: por cada clave guardamos timestamps de
// fallos y un "bloqueado hasta". Sin dependencias externas.
//
// Por qué doble dimensión (IP + cuenta):
//  - Solo IP: un atacante rota IPs o comparte NAT y evade / causa DoS.
//  - Solo cuenta: un atacante prueba una contraseña en miles de cuentas
//    (password spraying) sin superar el límite de ninguna.
//  Combinar ambas frena fuerza bruta dirigida y spraying a la vez.
// El bloqueo es temporal (no permanente) para no crear un DoS permanente
// contra el usuario legítimo (un atacante podría bloquearle la cuenta).

/** @type {Map<string, {fails: number[], blockedUntil: number}>} */
const buckets = new Map();

function getBucket(key) {
  let b = buckets.get(key);
  if (!b) { b = { fails: [], blockedUntil: 0 }; buckets.set(key, b); }
  return b;
}

function prune(bucket, now, windowMs) {
  bucket.fails = bucket.fails.filter((t) => now - t < windowMs);
}

// Devuelve { allowed, retryAfterMs }. No registra nada.
function check(key, { max, windowMs }) {
  const now = Date.now();
  const b = getBucket(key);
  if (b.blockedUntil > now) return { allowed: false, retryAfterMs: b.blockedUntil - now };
  prune(b, now, windowMs);
  if (b.fails.length >= max) return { allowed: false, retryAfterMs: windowMs };
  return { allowed: true, retryAfterMs: 0 };
}

// Registra un fallo y activa bloqueo si se supera el máximo.
function fail(key, { max, windowMs, blockMs }) {
  const now = Date.now();
  const b = getBucket(key);
  prune(b, now, windowMs);
  b.fails.push(now);
  if (b.fails.length >= max) b.blockedUntil = now + blockMs;
}

// Registra éxito: limpia los fallos de esa clave (p. ej. login correcto
// perdona los fallos previos de la cuenta, pero NO los de la IP).
function ok(key) {
  buckets.delete(key);
}

// Chequeo combinado IP + cuenta. Falla si cualquiera está bloqueada.
function checkBoth(ipKey, accountKey, limits) {
  const a = check(ipKey, limits.ip);
  const b = accountKey ? check(accountKey, limits.account) : { allowed: true, retryAfterMs: 0 };
  if (!a.allowed || !b.allowed) {
    return { allowed: false, retryAfterMs: Math.max(a.retryAfterMs, b.retryAfterMs) };
  }
  return { allowed: true, retryAfterMs: 0 };
}

function failBoth(ipKey, accountKey, limits) {
  fail(ipKey, limits.ip);
  if (accountKey) fail(accountKey, limits.account);
}

function okBoth(ipKey, accountKey) {
  // Solo perdonamos la cuenta; la IP conserva su historial para frenar
  // ataques distribuidos desde la misma origen.
  if (accountKey) ok(accountKey);
}

module.exports = { check, fail, ok, checkBoth, failBoth, okBoth };
