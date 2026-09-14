'use strict';
const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { requireAdmin } = require('../middleware/auth');

/**
 * HIPAA § 164.312(b) Audit Controls API
 * Restricted strictly to System Administrators.
 */

// GET /api/audit - Fetch recent audit logs with optional filtering
router.get('/', requireAdmin, async (req, res) => {
  try {
    const { status, action, search, limit = 100 } = req.query;
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 500);

    let query = `
      SELECT id, timestamp, event_type, actor_id, actor_username, actor_role, action,
             resource_type, resource_id, http_method, endpoint, client_ip, http_status, status, duration_ms
      FROM audit_logs
      WHERE 1=1
    `;
    const params = [];

    if (status && status !== 'ALL') {
      params.push(status);
      query += ` AND status = $${params.length}`;
    }

    if (action) {
      params.push(`%${action}%`);
      query += ` AND action ILIKE $${params.length}`;
    }

    if (search) {
      params.push(`%${search}%`);
      query += ` AND (
        actor_username ILIKE $${params.length} OR 
        action ILIKE $${params.length} OR 
        resource_id ILIKE $${params.length} OR 
        client_ip ILIKE $${params.length}
      )`;
    }

    query += ` ORDER BY timestamp DESC LIMIT $${params.length + 1}`;
    params.push(safeLimit);

    const result = await db.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve HIPAA audit logs'
    });
  }
});

// GET /api/audit/stats - Summary metrics for Admin Security Dashboard
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    const totalResult = await db.query('SELECT COUNT(*) as total FROM audit_logs');
    const deniedResult = await db.query("SELECT COUNT(*) as denied FROM audit_logs WHERE status = 'DENIED'");
    const aiSecResult = await db.query("SELECT COUNT(*) as ai_violations FROM audit_logs WHERE action ILIKE '%AI_%' AND status = 'DENIED'");
    const phiAccessResult = await db.query("SELECT COUNT(*) as phi_events FROM audit_logs WHERE action ILIKE '%PHI%' OR resource_type ILIKE '%PATIENT%'");

    res.json({
      success: true,
      stats: {
        totalEvents: parseInt(totalResult.rows[0].total, 10),
        deniedEvents: parseInt(deniedResult.rows[0].denied, 10),
        aiViolations: parseInt(aiSecResult.rows[0].ai_violations, 10),
        phiEvents: parseInt(phiAccessResult.rows[0].phi_events, 10)
      }
    });
  } catch (error) {
    console.error('Error fetching audit stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve audit metrics'
    });
  }
});

module.exports = router;
