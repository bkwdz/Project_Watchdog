const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12;

class CredentialVaultError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CredentialVaultError';
  }
}

function readKey() {
  const raw = String(process.env.CREDENTIAL_ENCRYPTION_KEY_BASE64 || '').trim();

  if (!raw) {
    throw new CredentialVaultError('CREDENTIAL_ENCRYPTION_KEY_BASE64 is required for credential encryption');
  }

  let decoded;

  try {
    decoded = Buffer.from(raw, 'base64');
  } catch (error) {
    throw new CredentialVaultError('CREDENTIAL_ENCRYPTION_KEY_BASE64 must be valid base64');
  }

  if (decoded.length !== 32) {
    throw new CredentialVaultError('CREDENTIAL_ENCRYPTION_KEY_BASE64 must decode to exactly 32 bytes');
  }

  return decoded;
}

function encryptSecret(plainText) {
  const input = String(plainText || '');

  if (!input) {
    throw new CredentialVaultError('Credential secret is required');
  }

  const key = readKey();
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(input, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext,
    iv,
    tag,
  };
}

function decryptSecret({ ciphertext, iv, tag }) {
  if (!ciphertext || !iv || !tag) {
    throw new CredentialVaultError('Encrypted credential payload is incomplete');
  }

  const key = readKey();

  try {
    const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv));
    decipher.setAuthTag(Buffer.from(tag));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(ciphertext)),
      decipher.final(),
    ]);
    return plain.toString('utf8');
  } catch (error) {
    throw new CredentialVaultError('Unable to decrypt credential secret');
  }
}

module.exports = {
  CredentialVaultError,
  encryptSecret,
  decryptSecret,
};
