'use strict';
// Mailer de desarrollo: NO envía correo real.
// Guarda cada mensaje en ./mailbox/<timestamp>-<dest>.json e imprime el
// enlace por consola para poder verificar / recuperar sin SMTP.
// Para producción, sustituir sendMail por Nodemailer/SES/Postmark sin
// cambiar el resto del código (los tokens ya son URLs completas).

const fs = require('fs');
const path = require('path');

const MAILBOX = path.join(__dirname, '..', 'mailbox');
fs.mkdirSync(MAILBOX, { recursive: true });

function persist(to, subject, body, link) {
  const file = path.join(MAILBOX, `${Date.now()}-${to.replace(/[^a-z0-9@._-]/gi, '_')}.json`);
  fs.writeFileSync(file, JSON.stringify({ to, subject, body, link, at: new Date().toISOString() }, null, 2));
  console.log(`[mail] ${subject} -> ${to}\n  ${link}`);
}

function sendVerificationEmail(to, link) {
  persist(to, 'Verifica tu cuenta',
    `Haz clic para verificar tu cuenta (caduca en 24 h, un solo uso): ${link}`, link);
}

function sendPasswordResetEmail(to, link) {
  persist(to, 'Recupera tu contraseña',
    `Haz clic para elegir una nueva contraseña (caduca en 1 h, un solo uso): ${link}`, link);
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail };
