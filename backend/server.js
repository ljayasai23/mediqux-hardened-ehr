'use strict';
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
require('dotenv').config({ quiet: true });

// Enforce environment secrets with secure production defaults
process.env.JWT_SECRET = process.env.JWT_SECRET || 'hipaa-high-entropy-secure-jwt-secret-key-2026';
process.env.INTEGRITY_SECRET = process.env.INTEGRITY_SECRET || 'hipaa-hmac-data-integrity-key-2026';
process.env.DB_USER = process.env.DB_USER || 'mediqux_user';
process.env.DB_PASSWORD = process.env.DB_PASSWORD || 'mediqux_pass';
process.env.DB_NAME = process.env.DB_NAME || 'mediqux_db';

const rateLimit = require('express-rate-limit');
const logger = require('./src/utils/logger');
const { sequelize } = require('./src/models');
const db = require('./src/database/db');
const { generateRecordHMAC } = require('./src/utils/integrity');
const { writeAuditEvent } = require('./src/middleware/audit');

// Standalone In-Memory Clinical Database Seed (Active in Standalone & DevSecOps Mode)
global.STANDALONE_PATIENTS_DB = {
  '101': {
    id: '101',
    first_name: 'Alice',
    last_name: 'Smith',
    date_of_birth: '1985-04-12',
    gender: 'female',
    phone: '+1-555-0101',
    email: 'alice.smith@example.com',
    diagnosis: 'Type 2 Diabetes Mellitus & Hypertension',
    prescriptions: ['Metformin 500mg (Twice daily)', 'Amlodipine 5mg (Once daily)', 'Atorvastatin 20mg (Once daily at night)'],
    allergies: ['Penicillin']
  },
  'c1000000-0000-0000-0000-000000000001': {
    id: 'c1000000-0000-0000-0000-000000000001',
    first_name: 'Alice',
    last_name: 'Smith',
    date_of_birth: '1985-04-12',
    gender: 'female',
    phone: '+1-555-0101',
    email: 'alice.smith@example.com',
    diagnosis: 'Type 2 Diabetes Mellitus & Hypertension',
    prescriptions: ['Metformin 500mg (Twice daily)', 'Amlodipine 5mg (Once daily)', 'Atorvastatin 20mg (Once daily at night)'],
    allergies: ['Penicillin']
  },
  '202': {
    id: '202',
    first_name: 'Bob',
    last_name: 'Jones',
    date_of_birth: '1972-11-23',
    gender: 'male',
    phone: '+1-555-0202',
    email: 'bob.jones@example.com',
    diagnosis: 'Coronary Artery Disease & Hypertension',
    prescriptions: ['Atorvastatin 40mg (Once daily)', 'Amlodipine 5mg (Once daily)'],
    allergies: ['Sulfa drugs']
  },
  'c1000000-0000-0000-0000-000000000002': {
    id: 'c1000000-0000-0000-0000-000000000002',
    first_name: 'Bob',
    last_name: 'Jones',
    date_of_birth: '1972-11-23',
    gender: 'male',
    phone: '+1-555-0202',
    email: 'bob.jones@example.com',
    diagnosis: 'Coronary Artery Disease & Hypertension',
    prescriptions: ['Atorvastatin 40mg (Once daily)', 'Amlodipine 5mg (Once daily)'],
    allergies: ['Sulfa drugs']
  }
};

for (const pid in global.STANDALONE_PATIENTS_DB) {
  global.STANDALONE_PATIENTS_DB[pid].integrity_hash = generateRecordHMAC(global.STANDALONE_PATIENTS_DB[pid]);
}

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again later.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many authentication attempts, please try again later.' }
});

const app = express();
const PORT = process.env.PORT || 3000;

// HIPAA § 164.312(e)(1) Security Headers & CORS Policy Hardening (VULN-05 Remediation)
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

const rawAllowed = process.env.ALLOWED_ORIGINS || 'http://localhost:8080,http://127.0.0.1:8080,http://localhost:3000,http://127.0.0.1:3000';
const allowedOrigins = rawAllowed.split(',').map(o => o.trim());

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin) || /^http:\/\/(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?$/.test(origin)) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true,
  exposedHeaders: ['Content-Disposition', 'Content-Type', 'Content-Length']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve frontend static files
const frontendDir = path.join(__dirname, '../frontend');
app.use(express.static(frontendDir));

// Uploads directory
const fs = require('fs');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Protected uploads
const { authenticateToken } = require('./src/middleware/auth');
app.use('/uploads', authenticateToken, express.static(uploadsDir));

// ============================================================================
// 1. DEMONSTRATION & SECURITY ASSESSMENT ROUTES
// ============================================================================

// Demo JWT Sessions for Manual Testing & Burp Suite
app.get('/api/demo/tokens', (req, res) => {
  res.json({
    message: 'Pre-generated demo JWT sessions for Burp Suite & manual testing',
    tokens: {
      alice_patient_101: jwt.sign({ userId: 10, username: 'alice', role: 'patient', patientId: '101' }, process.env.JWT_SECRET, { expiresIn: '8h' }),
      bob_patient_202: jwt.sign({ userId: 20, username: 'bob', role: 'patient', patientId: '202' }, process.env.JWT_SECRET, { expiresIn: '8h' }),
      dr_house_doctor: jwt.sign({ userId: 2, username: 'dr_house', role: 'doctor', patientId: null }, process.env.JWT_SECRET, { expiresIn: '8h' }),
      admin_user: jwt.sign({ userId: 1, username: 'admin', role: 'admin', patientId: null }, process.env.JWT_SECRET, { expiresIn: '8h' })
    }
  });
});

// VULNERABLE: As-Found BOLA/IDOR Demonstration (VULN-01)
app.get(['/api/vulnerable/patients', '/api/vulnerable/patients/:id'], async (req, res) => {
  const id = req.params.id;
  if (!id) {
    return res.json({
      status: 'VULNERABLE_ENDPOINT (As-Found State)',
      warning: 'Unauthenticated BOLA/IDOR vulnerability active! All patient records leaked.',
      data: Object.values(global.STANDALONE_PATIENTS_DB)
    });
  }

  let patient = global.STANDALONE_PATIENTS_DB[id];
  if (!patient && db && !db.isPostgresOffline) {
    try {
      const r = await db.query('SELECT * FROM patients WHERE id = $1', [id]);
      if (r.rows.length > 0) patient = r.rows[0];
    } catch (e) { }
  }
  if (!patient) {
    patient = global.STANDALONE_PATIENTS_DB['202'];
  }

  res.json({
    status: 'VULNERABLE_ENDPOINT (As-Found State)',
    warning: 'Unauthenticated BOLA/IDOR vulnerability active! PHI leaked.',
    data: patient
  });
});

// VULNERABLE: As-Found JWT Weak Secret Demonstration (VULN-03)
app.get('/api/vulnerable/users', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  let claims = { userId: 1, username: 'admin_attacker', role: 'admin', note: 'Forged administrative identity' };

  if (token) {
    try {
      claims = jwt.verify(token, 'your-secret-key-change-this');
    } catch (err) {
      claims = { userId: 1, username: 'admin_attacker', role: 'admin', note: 'Forged token accepted via fallback weak key' };
    }
  }

  res.json({
    status: 'VULNERABLE_STATE_EXPLOITED',
    warning: 'Server accepted forged JWT signed with default weak secret key!',
    user_claims: claims,
    users: [
      { id: 1, username: 'admin', role: 'admin' },
      { id: 2, username: 'dr_house', role: 'doctor' },
      { id: 10, username: 'alice', role: 'patient' },
      { id: 20, username: 'bob', role: 'patient' }
    ]
  });
});

// VULNERABLE: As-Found CORS Reflection Demonstration (VULN-05)
app.get('/api/vulnerable/cors', (req, res) => {
  const origin = req.headers.origin || '*';
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.json({
    status: 'VULNERABLE_CORS_ACTIVE',
    warning: 'Permissive CORS reflection with credentials enabled!',
    reflected_origin: origin
  });
});

// ============================================================================
// 2. CORE APPLICATION ROUTES
// ============================================================================
const authRoutes = require('./src/routes/auth');
const usersRoutes = require('./src/routes/users');
const patientRoutes = require('./src/routes/patients');
const doctorRoutes = require('./src/routes/doctors');
const institutionRoutes = require('./src/routes/institutions');
const appointmentRoutes = require('./src/routes/appointments');
const conditionRoutes = require('./src/routes/conditions');
const medicationRoutes = require('./src/routes/medications');
const prescriptionRoutes = require('./src/routes/prescriptions');
const testResultRoutes = require('./src/routes/test-results');
const diagnosticStudiesRoutes = require('./src/routes/diagnostic-studies');
const aiRoutes = require('./src/routes/ai');
const auditRoutes = require('./src/routes/audit');

// Public routes
app.use('/api/auth', authLimiter, authRoutes);

// Protected routes (authentication required)
app.use('/api/users', apiLimiter, authenticateToken, usersRoutes);
app.use('/api/patients', apiLimiter, authenticateToken, patientRoutes);
app.use('/api/doctors', apiLimiter, authenticateToken, doctorRoutes);
app.use('/api/institutions', apiLimiter, authenticateToken, institutionRoutes);
app.use('/api/appointments', apiLimiter, authenticateToken, appointmentRoutes);
app.use('/api/conditions', apiLimiter, authenticateToken, conditionRoutes);
app.use('/api/medications', apiLimiter, authenticateToken, medicationRoutes);
app.use('/api/prescriptions', apiLimiter, authenticateToken, prescriptionRoutes);
app.use('/api/test-results', apiLimiter, authenticateToken, testResultRoutes);
app.use('/api/diagnostic-studies', apiLimiter, authenticateToken, diagnosticStudiesRoutes);
app.use('/api/ai', apiLimiter, authenticateToken, aiRoutes);
app.use('/api/audit', apiLimiter, authenticateToken, auditRoutes);

// System database connectivity check
app.get('/api/system/database', apiLimiter, async (req, res) => {
  try {
    await sequelize.authenticate();
    const [results] = await sequelize.query('SELECT NOW() as current_time, version() as postgres_version');
    res.json({
      success: true,
      message: 'Database connection successful (Sequelize)',
      orm: 'Sequelize',
      data: results[0]
    });
  } catch (error) {
    res.json({
      success: false,
      mode: 'STANDALONE_DEVSECOPS_SANDBOX',
      message: 'PostgreSQL offline; standalone in-memory clinical persistence active',
      details: error.message
    });
  }
});

// Enhanced health check
app.get('/api/health', apiLimiter, (req, res) => {
  res.json({
    status: 'Server running',
    timestamp: new Date(),
    nodeVersion: process.version,
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Frontend SPA fallback
app.get('/', (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled application error', { error: err.message, stack: err.stack });
  res.status(500).json({
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});
process.on('SIGINT', () => {
  console.log('\n[!] Server stopped by user (Ctrl+C)');
  process.exit(0);
});

// Server startup with automatic graceful degradation
async function initializeServer() {
  let dbConnected = false;
  try {
    logger.info('Testing PostgreSQL database connection...');
    await sequelize.authenticate();
    logger.info('Database connection established successfully (Sequelize)');
    dbConnected = true;
    const db = require('./src/database/db');
    db.setPostgresOffline(false);
  } catch (error) {
    logger.warn('PostgreSQL database not detected on localhost:5432.');
    logger.info('[STANDALONE ENGINE READY] Running with isolated clinical engine for security testing, red-teaming & CI/CD.');
    const db = require('./src/database/db');
    db.setPostgresOffline(true);
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('='.repeat(72));
    console.log(`[+] MEDICARE HEALTHCARE PLATFORM RUNNING ON http://localhost:${PORT}`);
    console.log(`    - Frontend Web Portal: http://localhost:${PORT}`);
    console.log(`    - Health Check:        http://localhost:${PORT}/api/health`);
    console.log(`    - Demo Security Tokens: http://localhost:${PORT}/api/demo/tokens`);
    console.log(`    - Operating Mode:      ${dbConnected ? 'PostgreSQL Production' : 'Standalone DevSecOps Sandbox'}`);
    console.log('='.repeat(72));
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n[!] ERROR: Port ${PORT} is already in use by another process!`);
      console.error(`    Run: Get-Process node | Stop-Process -Force   (to free the port)\n`);
    } else {
      console.error('Server error:', err);
    }
  });
}

// Initialize
initializeServer();