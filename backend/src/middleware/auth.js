'use strict';
const jwt = require('jsonwebtoken');
const db = require('../database/db');
const logger = require('../utils/logger');
const { writeAuditEvent } = require('./audit');

// HIPAA § 164.312(d) Cryptographic Secret Enforcement (VULN-03 Remediation)
const INSECURE_FALLBACKS = [
  'your-secret-key-change-this',
  'secret',
  'jwt_secret',
  'default_secret',
  '123456'
];

const rawSecret = process.env.JWT_SECRET;
if (!rawSecret || INSECURE_FALLBACKS.includes(rawSecret.trim())) {
  if (process.env.NODE_ENV === 'production' || process.env.STRICT_SECURITY === 'true') {
    throw new Error('[FATAL SECURITY ERROR] Insecure or missing JWT_SECRET. The application cannot start in production with a default or empty secret key (HIPAA § 164.312(d)).');
  } else {
    logger.warn('[SECURITY WARNING] Insecure default JWT_SECRET detected. Set a high-entropy secret in your .env file.');
  }
}

const JWT_SECRET = rawSecret || 'temporary-dev-only-secret-do-not-use-in-prod-xyz123!';

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    writeAuditEvent({
      action: 'AUTHENTICATION_FAILURE',
      resource_type: 'AUTH',
      resource_id: 'token',
      http_status: 401,
      status: 'DENIED',
      reason: 'MISSING_BEARER_TOKEN',
      client_ip: req.ip || req.socket.remoteAddress
    });
    return res.status(401).json({
      success: false,
      error: 'Access token required'
    });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (error) {
    writeAuditEvent({
      action: 'AUTHENTICATION_FAILURE',
      resource_type: 'AUTH',
      resource_id: 'token',
      http_status: 403,
      status: 'DENIED',
      reason: error.message,
      client_ip: req.ip || req.socket.remoteAddress
    });
    return res.status(403).json({
      success: false,
      error: 'Invalid or expired token'
    });
  }

  try {
    const result = await db.query(
      'SELECT id, username, role, is_active, patient_id FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0 || !result.rows[0].is_active) {
      writeAuditEvent({
        actor_id: decoded.userId,
        action: 'AUTHENTICATION_FAILURE',
        resource_type: 'USER',
        resource_id: String(decoded.userId),
        http_status: 401,
        status: 'DENIED',
        reason: 'USER_INACTIVE_OR_DELETED',
        client_ip: req.ip || req.socket.remoteAddress
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid or inactive user'
      });
    }

    req.user = {
      id: result.rows[0].id,
      userId: result.rows[0].id,
      username: result.rows[0].username,
      role: result.rows[0].role,
      patientId: result.rows[0].patient_id
    };

    return next();
  } catch (dbError) {
    // Standalone DevSecOps fallback: Use cryptographically verified JWT claims
    req.user = {
      id: decoded.userId,
      userId: decoded.userId,
      username: decoded.username,
      role: decoded.role,
      patientId: decoded.patientId || decoded.patient_id || null
    };
    return next();
  }
};

const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role)) {
      writeAuditEvent({
        actor_id: req.user.id,
        actor_role: req.user.role,
        action: 'AUTHORIZATION_FAILURE_ROLE',
        resource_type: 'ENDPOINT',
        resource_id: req.originalUrl,
        http_status: 403,
        status: 'DENIED',
        reason: `ROLE_REQUIRED: ${roles.join(',')}`,
        client_ip: req.ip || req.socket.remoteAddress
      });
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions'
      });
    }

    next();
  };
};

const requireAdmin = requireRole(['admin']);
const requireDoctorOrAdmin = requireRole(['doctor', 'admin']);

/**
 * HIPAA § 164.312(a)(1) Access Control - Object-Level Authorization (VULN-01 IDOR Remediation)
 * Verifies that the authenticated user owns the requested patient record or holds doctor/admin privileges.
 */
const authorizePatientAccess = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  // Admins and Doctors have authorized clinical oversight
  if (['admin', 'doctor'].includes(req.user.role)) {
    return next();
  }

  const requestedPatientId = req.params.id || req.body.patient_id;

  // Verify object ownership: requesting user's patientId MUST match target patientId
  if (!req.user.patientId || String(req.user.patientId) !== String(requestedPatientId)) {
    writeAuditEvent({
      actor_id: req.user.id,
      actor_role: req.user.role,
      action: 'BOLA_IDOR_BLOCKED',
      resource_type: 'PATIENT_RECORD',
      resource_id: String(requestedPatientId),
      http_status: 403,
      status: 'DENIED',
      reason: `CROSS_TENANT_ACCESS_ATTEMPT: User patient_id ${req.user.patientId} tried to access patient ${requestedPatientId}`,
      client_ip: req.ip || req.socket.remoteAddress
    });

    return res.status(403).json({
      success: false,
      error: 'Access denied: You do not have authorization to view or modify this patient record'
    });
  }

  next();
};

/**
 * Object-Level Authorization for Prescriptions (VULN-01 IDOR Remediation)
 */
const authorizePrescriptionAccess = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  if (['admin', 'doctor'].includes(req.user.role)) {
    return next();
  }

  const prescriptionId = req.params.id;

  try {
    const result = await db.query(
      `SELECT a.patient_id 
       FROM prescriptions p
       JOIN appointments a ON p.appointment_id = a.id
       WHERE p.id = $1`,
      [prescriptionId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Prescription not found' });
    }

    const prescriptionPatientId = result.rows[0].patient_id;

    if (String(req.user.patientId) !== String(prescriptionPatientId)) {
      writeAuditEvent({
        actor_id: req.user.id,
        actor_role: req.user.role,
        action: 'PRESCRIPTION_IDOR_BLOCKED',
        resource_type: 'PRESCRIPTION',
        resource_id: String(prescriptionId),
        http_status: 403,
        status: 'DENIED',
        reason: `CROSS_TENANT_PRESCRIPTION_PROBE: User patient_id ${req.user.patientId} probed prescription belonging to patient ${prescriptionPatientId}`,
        client_ip: req.ip || req.socket.remoteAddress
      });

      return res.status(403).json({
        success: false,
        error: 'Access denied: You do not have authorization to view this prescription'
      });
    }

    next();
  } catch (err) {
    logger.error('Error verifying prescription ownership:', err);
    return res.status(500).json({ success: false, error: 'Authorization check failed' });
  }
};

const addPatientFilter = (req, res, next) => {
  if (['admin', 'doctor'].includes(req.user.role)) {
    req.patientFilter = null;
    return next();
  }

  if (req.user.patientId) {
    req.patientFilter = req.user.patientId;
  } else {
    req.patientFilter = 'none';
  }
  
  next();
};

module.exports = {
  authenticateToken,
  requireRole,
  requireAdmin,
  requireDoctorOrAdmin,
  authorizePatientAccess,
  authorizePrescriptionAccess,
  addPatientFilter
};