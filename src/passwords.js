'use strict';
// Hash de contraseñas con Argon2id.
//
// Parámetros elegidos (justificación):
//   - type: argon2id  -> variante híbrida: resiste ataques de canal lateral
//     (como argon2d) y ataques con GPU/ASIC por tradeoff memoria-tiempo
//     (como argon2i). Es la recomendada por OWASP para contraseñas.
//   - memoryCost: 19456 KiB (~19 MiB) -> recomendación OWASP 2023 para el
//     "primer nivel" (interactivo): suficiente dureza de memoria para que
//     el cracking masivo en GPU sea caro, sin agotar un servidor modesto
//     con logins concurrentes (19 MiB × N peticiones es asumible; 64 MiB
//     por defecto de la RFC 9106 solo si hay poca concurrencia).
//   - timeCost: 2 iteraciones -> empareja con los 19 MiB según OWASP
//     (m=19MiB,t=2,p=1). Subir t aumenta CPU linealmente y latencia de
//     login; 2 da ~100-300 ms por hash en hardware típico, aceptable.
//   - parallelism: 1 -> evita multiplicar el uso de memoria por hilo
//     (memoria total ≈ m × p) y evita sobrecargar el event-loop en Node;
//     el hashing se ejecuta en el pool de libuv de argon2, no bloquea.
//   - hashLength: 32 bytes -> 256 bits de salida, margen sobrado.
//   - versión 0x13 (19) -> la actual, gestionada por la librería.
//
// Si el servidor crece: subir primero memoryCost (p. ej. 64 MiB) antes
// que timeCost, midiendo p95 de /login bajo carga.

const argon2 = require('argon2');

const OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456, // KiB (~19 MiB)
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
};

async function hashPassword(password) {
  return argon2.hash(password, OPTIONS);
}

async function verifyPassword(hash, password) {
  return argon2.verify(hash, password);
}

module.exports = { OPTIONS, hashPassword, verifyPassword };
