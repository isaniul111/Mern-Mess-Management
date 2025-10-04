// hash.js
const bcrypt = require('bcryptjs');

async function createHash(password) {
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);
  console.log('Hashed password:', hash);
}

// Example: password 12345678
createHash('12345678');
