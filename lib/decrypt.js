const base58 = require('bs58');
const crypto = require('crypto');

module.exports = function decrypt(password, str) {
  let iv = Buffer.alloc(16, 0);    
  if (str.length > 66) {
      const parts = str.split(':');
      iv = Buffer.from(parts[0], 'hex');
      str = parts[1];
  }
  const key = crypto.scryptSync(password, iv, 32);
  const aes256 = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const a = aes256.update(Buffer.from(base58.decode(str)));
  const b = aes256.final();
  return Buffer.concat([a, b]).toString('utf8');
};
