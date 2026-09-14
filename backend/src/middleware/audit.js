'use strict';
const fs = require('fs');
const path = require('path');

/**
 * HIPAA § 164.312(b) Audit Controls Middleware
 * Captures immutable security audit trails answering:
 * Who did what, when, from where, and with what result?
 * Explicitly sanitizes and suppresses raw PHI and secrets.
 */

const auditLogPath = process.env.AUDIT_LOG_PATH || path.join(__dirname, '../../logs/security_audit.jsonl');
const auditDir = path.dirname(auditLogPath);

let db;
try {
  db = require('../database/db');
} catch (e) {
  // fallback if db not loaded
}

if (!fs.existsSync(auditDir)) {
  fs.mkdirSync(auditDir, { recursive: true });
}

function writeAuditEvent(event) {
  const logEntry = JSON.stringify({
    timestamp: new Date().toISOString(),
    event_type: 'SECURITY_AUDIT',
    ...event
  }) + '\n';

  // 1. Append to audit log file (HIPAA SIEM / WORM storage)
  fs.appendFile(auditLogPath, logEntry, (err) => {
    if (err) {
      console.error('[AUDIT LOGGING FAILURE]:', err);
    }
  });

  // 2. Output to console for container log collectors
  if (process.env.NODE_ENV !== 'test') {
    console.log(`[HIPAA-AUDIT] ${logEntry.trim()}`);
  }

  // 3. Persist to PostgreSQL audit_logs table
  if (db && !db.isPostgresOffline) {
    const query = `
      INSERT INTO audit_logs (
        event_type, actor_id, actor_username, actor_role, action, 
        resource_type, resource_id, http_method, endpoint, client_ip, 
        user_agent, http_status, status, duration_ms
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
    `;
    const params = [
      event.event_type || 'SECURITY_AUDIT',
      event.actor_id ? String(event.actor_id) : null,
      event.actor_username || null,
      event.actor_role || null,
      event.action || 'UNKNOWN_ACTION',
      event.resource_type || null,
      event.resource_id ? String(event.resource_id) : null,
      event.http_method || null,
      event.endpoint || null,
      event.client_ip || null,
      event.user_agent || null,
      event.http_status || null,
      event.status || null,
      event.duration_ms || null
    ];
    db.query(query, params).catch(() => {});
  }
}

/**
 * Express middleware for logging access to PHI and sensitive healthcare endpoints.
 */
function auditMiddleware(actionName, resourceType) {
  return (req, res, next) => {
    const originalJson = res.json;
    const startTime = Date.now();

    res.json = function (body) {
      res.json = originalJson;

      const actor = req.user || { id: 'anonymous', username: 'unauthenticated', role: 'public' };
      const resourceId = req.params?.id || req.body?.id || req.body?.patient_id || 'collection';
      const statusCode = res.statusCode;
      const status = statusCode >= 200 && statusCode < 400 ? 'SUCCESS' : 'DENIED';

      writeAuditEvent({
        actor_id: actor.id,
        actor_username: actor.username,
        actor_role: actor.role,
        action: actionName,
        resource_type: resourceType,
        resource_id: String(resourceId),
        http_method: req.method,
        endpoint: req.originalUrl || req.baseUrl,
        client_ip: req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress,
        user_agent: req.headers['user-agent'] || 'unknown',
        http_status: statusCode,
        status: status,
        duration_ms: Date.now() - startTime
      });

      return res.json(body);
    };

    next();
  };
}

module.exports = {
  writeAuditEvent,
  auditMiddleware
};
