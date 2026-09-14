'use strict';
const crypto = require('crypto');

/**
 * HIPAA § 164.312(c)(1) Data Integrity Mechanism
 * Provides cryptographic HMAC-SHA256 checksums to corroborate that
 * electronic Protected Health Information (ePHI) has not been altered or destroyed
 * in an unauthorized manner.
 */

const INTEGRITY_SECRET = process.env.INTEGRITY_SECRET || process.env.JWT_SECRET;

if (!INTEGRITY_SECRET) {
  throw new Error('[FATAL] INTEGRITY_SECRET or JWT_SECRET must be defined to initialize HIPAA integrity engine');
}

/**
 * Generates a deterministic canonical HMAC-SHA256 signature of a healthcare record.
 * @param {Object} record - The clinical data object (e.g. prescription, patient diagnosis)
 * @returns {string} Hex-encoded HMAC digest
 */
function generateRecordHMAC(record) {
  if (!record || typeof record !== 'object') {
    throw new Error('Record object must be provided for HMAC calculation');
  }

  // Create deterministic representation excluding dynamic metadata (e.g. updated_at, hmac)
  const canonicalObj = {};
  const sortedKeys = Object.keys(record)
    .filter(key => !['integrity_hash', 'updated_at', 'created_at'].includes(key))
    .sort();

  for (const key of sortedKeys) {
    canonicalObj[key] = record[key];
  }

  const serialized = JSON.stringify(canonicalObj);
  return crypto.createHmac('sha256', INTEGRITY_SECRET).update(serialized).digest('hex');
}

/**
 * Validates the cryptographic integrity of a healthcare record against an expected hash.
 * @param {Object} record - The clinical data record retrieved from database
 * @param {string} expectedHash - The previously stored HMAC digest
 * @returns {boolean} True if data is intact, false if tampered
 */
function verifyRecordHMAC(record, expectedHash) {
  if (!expectedHash) {
    return false;
  }
  const currentHash = generateRecordHMAC(record);
  
  // Use constant-time comparison to prevent timing attacks
  const hashBuffer = Buffer.from(currentHash, 'hex');
  const expectedBuffer = Buffer.from(expectedHash, 'hex');
  
  if (hashBuffer.length !== expectedBuffer.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(hashBuffer, expectedBuffer);
}

module.exports = {
  generateRecordHMAC,
  verifyRecordHMAC
};
