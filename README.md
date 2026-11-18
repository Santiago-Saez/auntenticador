# Autenticación completa sin librerías de auth de terceros

Sistema propio en Node + Express + SQLite (`better-sqlite3`) + Argon2.
Sin Passport, Auth.js, Lucia, Firebase Auth ni similares: registro,
verificación por correo, sesiones en cookie, recuperación y rate-limit
están implementados a mano en `src/`.

## Estructura

```
src/
  server.js      arranque
  app.js         rutas API + middlewares (registro, verify, login, recover, reset, sesiones)
  config.js      TTLs, cookie, límites por IP/cuenta
  db.js          esquema SQLite (users, tokens, sessions)
  crypto.js      tokens opacos (randomBytes 256 bits, solo hash SHA-256 en BD)
  passwords.js   Argon2id + parámetros justificados
  session.js     sesiones opacas + cookie httpOnly/SameSite
  rateLimit.js   ventana deslizante por IP y por cuenta + bloqueo temporal
  validate.js    normalización email, política de contraseña, IP cliente
  mailer.js      buzón de desarrollo (./mailbox/ + consola; sustituir por SMTP en prod)
public/          demo mínima (index, verify, reset)
scripts/smoke.js test end-to-end: `npm run smoke`
```

## Uso

```bash
cp .env.example .env   # opcional
npm install
npm run dev            # http://localhost:3000
npm run smoke          # verifica el flujo completo
```

Los enlaces de verificación/recuperación **no se envían de verdad**:
se guardan en `./mailbox/*.json` y salen por consola. Abrir el enlace o
usar el token en `verify.html` / `reset.html`.

## API

| Método | Ruta | Notas |
|---|---|---|
| POST | `/api/register` | Siempre `201` genérico (no filtra existencia) |
| POST | `/api/verify` | `{ token }`, un solo uso, caduca 24 h |
| POST | `/api/resend-verification` | Genérico |
| POST | `/api/login` | `401` genérico; crea sesión nueva (rotación) |
| POST | `/api/logout` | Revoca sesión actual |
| POST | `/api/recover` | Siempre `200` genérico, exista o no el correo |
| POST | `/api/reset` | `{ token, newPassword }`, un solo uso, caduca 1 h, revoca todo |
| GET | `/api/me` | Perfil (auth) |
| GET | `/api/sessions` | Lista sesiones (auth) |
| DELETE | `/api/sessions` | Revoca las demás; con `?all=true` revoca todas |
| POST | `/api/change-password` | Revoca las demás sesiones |

## Decisiones de seguridad y sus porqués

1. **Argon2id con `m=19456 KiB (~19 MiB), t=2, p=1`** (ver `src/passwords.js`).
   Por qué: es la variante híbrida recomendada por OWASP — resiste ataques
   de canal lateral (como Argon2d) y cracking masivo en GPU/ASIC por ser
   *memory-hard* (como Argon2i). El par 19 MiB × 2 iteraciones es el
   "primer nivel" OWASP 2023: encarece el cracking paralelo sin agotar un
   servidor modesto con logins concurrentes (la memoria total ≈ `m × p`,
   de ahí `p=1`). Cada hash tarda ~100–300 ms: irrelevante para un login
   legítimo, carísimo para probar millones de contraseñas. Si el hardware
   lo permite, subir primero `m` (p. ej. 64 MiB, nivel RFC 9106) antes que
   `t`, midiendo el p95 de `/api/login`.
   Alternativas descartadas: bcrypt (límite 72 bytes, sin dureza de
   memoria), scrypt (bueno pero más difícil de parametrizar bien en Node),
   SHA/md5 con salt (rotos para contraseñas desde hace décadas).

2. **Tokens de verificación/reset opacos, hasheados y de un solo uso.**
   Por qué: se generan con `crypto.randomBytes(32)` (256 bits, impredecibles)
   y en BD solo se guarda su SHA-256. Una filtración de la BD no permite
   suplantar ni reenviar enlaces. Se marcan `used_at` al consumirse y se
   rechazan reutilizaciones (replay), con caducidad corta (24 h verificar,
   1 h reset). Un JWT firma­do "stateless" no permitiría invalidación
   inmediata; el token opaco revocable sí.

3. **Sesión opaca en cookie `httpOnly` + `SameSite=Lax` (+ `Secure` en prod).**
   Por qué: `httpOnly` impide que JavaScript la lea → un XSS no puede
   exfiltrarla con `document.cookie`. `SameSite=Lax` hace que el navegador
   no la envíe en POST cross-site → mitiga CSRF por defecto; además hay
   chequeo de `Origin` contra el `Host` en escrituras. `Secure` (solo en
   producción) impide que viaje por HTTP. No se usa `localStorage` para el
   token precisamente para no exponerlo a XSS.

4. **Rotación en cada login + revocación total desde el perfil.**
   Por qué: cada `POST /api/login` crea un `sid` nuevo y nunca se acepta un
   id propuesto por el cliente → defensa contra *fijación de sesión* (un
   atacante no puede plantar un sid y esperar a que la víctima lo use).
   `DELETE /api/sessions` permite cerrar el resto de dispositivos; tras un
   reset o cambio de contraseña se revocan **todas** (incluida la actual en
   el reset) para expulsar sesiones robadas. El atacante con una cookie
   vieja queda fuera aunque conozca la contraseña anterior.

5. **Recuperación y login sin oráculo de enumeración.**
   Por qué: `/api/recover` responde el mismo `200` exista o no el correo,
   con retardo uniforme (~300 ms) y solo crea/envía token si el usuario
   existe. `/api/login` responde el mismo `401` para "no existe",
   "contraseña mal" y "sin verificar" (incluye un hash dummy para igualar
   tiempos). `/api/register` responde el mismo `201` aunque el correo ya
   exista. Si el sistema distinguiera los casos, un atacante podría
   enumerar qué correos están registrados y luego concentrar phishing o
   credential stuffing en ellos.

6. **Límite de intentos por IP *y* por cuenta, con bloqueo temporal.**
   Por qué doble dimensión: solo por IP lo evade rotando IPs (y castiga a
   usuarios tras un NAT compartido); solo por cuenta no frena el
   *password spraying* (una contraseña contra miles de cuentas). Se
   combinan: login 5 fallos/15 min por cuenta + 20/15 min por IP; registro,
   recover y verify con sus propios cubos. El bloqueo es **temporal**
   (15 min–1 h con `Retry-After`), no permanente: un bloqueo definitivo
   permitiría a un atacante hacer DoS al usuario legítimo bloqueándole la
   cuenta a voluntad. Tras un login correcto se perdonan los fallos de la
   cuenta (pero no los de la IP).

7. **Defensas en profundidad menores, pero que suman.**
   Normalización del email (trim + minúsculas) para que `User@x.com` no sea
   otra cuenta; política de mínimo 12 caracteres (NIST 800-63B) sin reglas
   de composición absurdas; tope de 128 para evitar DoS por CPU en Argon2;
   comparación en tiempo constante donde aplica; `express.json({limit})`
   contra payloads gigantes; cabeceras `X-Content-Type-Options`, `X-Frame-Options`,
   `Referrer-Policy` y HSTS en prod; manejo de errores que nunca filtra
   detalles internos ni el estado de la cuenta.

## Límites conocidos (trabajo futuro)

- Rate-limit en memoria: con varias instancias habría que moverlo a Redis.
- Mailer de desarrollo: en producción usar proveedor SMTP/transactional +
  SPF/DKIM/DMARC.
- Falta 2FA (TOTP/WebAuthn), detección de brechas (k-anonimato HIBP) y
  *email change confirmation*; dejados fuera a propósito para el alcance.
