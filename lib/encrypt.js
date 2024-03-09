const base58 = require('bs58');
const crypto = require('crypto');

module.exports = function encrypt(password, str) {
  const iv = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, iv, 32);
  const aes256 = crypto.createCipheriv('aes-256-cbc', key, iv);
  const a = aes256.update(str, 'utf8');
  const b = aes256.final();
  return iv.toString('hex') + ':' + base58.encode(Buffer.concat([a, b]));
};
