'use strict';
const express = require('express');
const router = express.Router();
const { processAIChat } = require('../services/ai-assistant');
const { auditMiddleware } = require('../middleware/audit');

/**
 * AI Clinical Triage & Patient Assistant API
 * Protected route: requires valid JWT session.
 * Architecture: User -> AI Gateway -> Tool Request -> Backend Authorization -> Audit Log
 */
router.post('/chat', auditMiddleware('AI_ASSISTANT_INVOCATION', 'AI_SYSTEM'), async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({
        success: false,
        error: 'A prompt or clinical message is required'
      });
    }

    if (message.length > 2000) {
      return res.status(400).json({
        success: false,
        error: 'Message exceeds maximum allowable length of 2000 characters'
      });
    }

    const result = await processAIChat(req.user, message);

    if (!result.success && result.error && result.error.includes('AI Security Guardrails')) {
      return res.status(400).json({
        success: false,
        error: result.error,
        security_violation: true
      });
    }

    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('AI Chat Error:', error);
    res.status(500).json({
      success: false,
      error: 'Clinical AI processing failed'
    });
  }
});

module.exports = router;
