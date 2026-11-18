'use strict';

const app = require('./app');
const config = require('./config');

app.listen(config.PORT, () => {
  console.log(`Auth listening on ${config.BASE_URL} (${config.isProd ? 'production' : 'development'})`);
  console.log('Buzón de desarrollo: ./mailbox/ (los enlaces de verificación/reset salen por consola)');
});
