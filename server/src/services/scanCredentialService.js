const { query, withTransaction } = require('../db');
const { encryptSecret, decryptSecret } = require('./credentialVault');

function normalizeCredentialType(type) {
  const normalized = String(type || '').trim().toLowerCase();
  return normalized === 'ssh' || normalized === 'smb' ? normalized : null;
}

function normalizeOptionalText(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function sanitizeCredentialRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    credential_type: row.credential_type,
    display_name: row.display_name,
    username: row.username,
    external_credential_id: row.external_credential_id,
    source: row.source,
    created_by: row.created_by,
    created_at: row.created_at,
    last_used_at: row.last_used_at,
  };
}

async function createCredentialRecord({
  credentialType,
  displayName = null,
  username,
  password,
  source = 'greenbone',
  createdBy = null,
  externalCredentialId = null,
}) {
  const normalizedType = normalizeCredentialType(credentialType);
  const normalizedUsername = normalizeOptionalText(username);
  const normalizedPassword = normalizeOptionalText(password);

  if (!normalizedType) {
    throw new Error('credential type must be ssh or smb');
  }

  if (!normalizedUsername || !normalizedPassword) {
    throw new Error('credential username and password are required');
  }

  const encrypted = encryptSecret(normalizedPassword);

  const insertResult = await query(
    `
      INSERT INTO scan_credentials (
        credential_type,
        display_name,
        username,
        secret_ciphertext,
        secret_iv,
        secret_tag,
        external_credential_id,
        source,
        created_by
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING
        id,
        credential_type,
        display_name,
        username,
        external_credential_id,
        source,
        created_by,
        created_at,
        last_used_at
    `,
    [
      normalizedType,
      normalizeOptionalText(displayName),
      normalizedUsername,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.tag,
      normalizeOptionalText(externalCredentialId),
      normalizeOptionalText(source) || 'greenbone',
      Number.isInteger(createdBy) ? createdBy : null,
    ],
  );

  return sanitizeCredentialRow(insertResult.rows[0]);
}

async function listCredentialSummaries(credentialType) {
  const normalizedType = normalizeCredentialType(credentialType);

  if (!normalizedType) {
    throw new Error('type must be ssh or smb');
  }

  const result = await query(
    `
      SELECT
        id,
        credential_type,
        display_name,
        username,
        external_credential_id,
        source,
        created_by,
        created_at,
        last_used_at
      FROM scan_credentials
      WHERE credential_type = $1
      ORDER BY last_used_at DESC NULLS LAST, created_at DESC, id DESC
    `,
    [normalizedType],
  );

  return result.rows.map(sanitizeCredentialRow);
}

async function getCredentialRecord(credentialId, { expectedType = null, lock = false, client = null } = {}) {
  const parsedId = Number(credentialId);

  if (!Number.isInteger(parsedId) || parsedId < 1) {
    throw new Error('invalid credential id');
  }

  const normalizedType = expectedType ? normalizeCredentialType(expectedType) : null;
  const values = [parsedId];
  const typeClause = normalizedType ? 'AND credential_type = $2' : '';

  if (normalizedType) {
    values.push(normalizedType);
  }

  const sql = `
    SELECT
      id,
      credential_type,
      display_name,
      username,
      secret_ciphertext,
      secret_iv,
      secret_tag,
      external_credential_id,
      source,
      created_by,
      created_at,
      last_used_at
    FROM scan_credentials
    WHERE id = $1
      ${typeClause}
    LIMIT 1
    ${lock ? 'FOR UPDATE' : ''}
  `;

  const db = client || { query };
  const result = await db.query(sql, values);
  return result.rows[0] || null;
}

async function markCredentialUsed(credentialId, { client = null } = {}) {
  const parsedId = Number(credentialId);

  if (!Number.isInteger(parsedId) || parsedId < 1) {
    return;
  }

  const db = client || { query };
  await db.query(
    `
      UPDATE scan_credentials
      SET last_used_at = NOW()
      WHERE id = $1
    `,
    [parsedId],
  );
}

async function updateCredentialExternalId(credentialId, externalCredentialId, { client = null } = {}) {
  const parsedId = Number(credentialId);

  if (!Number.isInteger(parsedId) || parsedId < 1) {
    throw new Error('invalid credential id');
  }

  const db = client || { query };
  await db.query(
    `
      UPDATE scan_credentials
      SET external_credential_id = $2
      WHERE id = $1
    `,
    [parsedId, normalizeOptionalText(externalCredentialId)],
  );
}

async function resolveCredentialWithSecret(credentialId, expectedType) {
  const row = await getCredentialRecord(credentialId, { expectedType });

  if (!row) {
    throw new Error('credential not found');
  }

  const password = decryptSecret({
    ciphertext: row.secret_ciphertext,
    iv: row.secret_iv,
    tag: row.secret_tag,
  });

  return {
    row: sanitizeCredentialRow(row),
    credential_type: row.credential_type,
    username: row.username,
    password,
    external_credential_id: row.external_credential_id,
  };
}

async function createCredentialWithSecret({
  credentialType,
  displayName = null,
  username,
  password,
  source = 'greenbone',
  createdBy = null,
  externalCredentialId = null,
}) {
  return createCredentialRecord({
    credentialType,
    displayName,
    username,
    password,
    source,
    createdBy,
    externalCredentialId,
  });
}

async function withCredentialLock(credentialId, expectedType, work) {
  return withTransaction(async (client) => {
    const row = await getCredentialRecord(credentialId, {
      expectedType,
      lock: true,
      client,
    });

    if (!row) {
      throw new Error('credential not found');
    }

    const password = decryptSecret({
      ciphertext: row.secret_ciphertext,
      iv: row.secret_iv,
      tag: row.secret_tag,
    });

    return work({
      client,
      row,
      password,
      sanitized: sanitizeCredentialRow(row),
    });
  });
}

module.exports = {
  normalizeCredentialType,
  sanitizeCredentialRow,
  createCredentialRecord,
  createCredentialWithSecret,
  listCredentialSummaries,
  getCredentialRecord,
  resolveCredentialWithSecret,
  markCredentialUsed,
  updateCredentialExternalId,
  withCredentialLock,
};
