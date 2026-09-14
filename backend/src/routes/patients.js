const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { addPatientFilter, authorizePatientAccess, requireAdmin, requireDoctorOrAdmin } = require('../middleware/auth');
const { auditMiddleware } = require('../middleware/audit');
const { generateRecordHMAC } = require('../utils/integrity');

// Get all patients (with RBAC filtering and HIPAA Audit Trail)
router.get('/', addPatientFilter, auditMiddleware('LIST_PATIENTS', 'PATIENT_PHI'), async (req, res) => {
  try {
    let query = `
      SELECT 
        id, 
        first_name, 
        last_name, 
        date_of_birth, 
        gender, 
        phone, 
        email,
        address,
        created_at
      FROM patients 
    `;
    let params = [];
    
    // Apply patient filtering based on user role
    if (req.patientFilter && req.patientFilter !== 'none') {
      query += ` WHERE id = $1`;
      params = [req.patientFilter];
    } else if (req.patientFilter === 'none') {
      // User has no patient access
      return res.json({
        success: true,
        data: [],
        count: 0
      });
    }
    
    query += ` ORDER BY last_name, first_name`;
    
    const result = await db.query(query, params);
    
    res.json({
      success: true,
      data: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    if (global.STANDALONE_PATIENTS_DB && db.isPostgresOffline) {
      let list = Object.values(global.STANDALONE_PATIENTS_DB);
      if (req.patientFilter && req.patientFilter !== 'none') {
        list = list.filter(p => String(p.id) === String(req.patientFilter));
      } else if (req.patientFilter === 'none') {
        list = [];
      }
      return res.json({ success: true, data: list, count: list.length });
    }
    console.error('Error fetching patients:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch patients'
    });
  }
});

// Get single patient by ID - Protected with Object-Level Authorization (IDOR Protection)
router.get('/:id', authorizePatientAccess, auditMiddleware('READ_PATIENT_RECORD', 'PATIENT_PHI'), async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.query(`
      SELECT id, first_name, last_name, date_of_birth, gender, phone, email, address,
             emergency_contact_name, emergency_contact_phone, created_at, updated_at
      FROM patients WHERE id = $1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Patient not found'
      });
    }
    
    const patientData = result.rows[0];
    
    // Attach cryptographic integrity verification hash (HIPAA § 164.312(c)(1))
    patientData.integrity_hash = generateRecordHMAC(patientData);

    res.json({
      success: true,
      data: patientData
    });
  } catch (error) {
    if (global.STANDALONE_PATIENTS_DB && global.STANDALONE_PATIENTS_DB[req.params.id]) {
      const patientData = { ...global.STANDALONE_PATIENTS_DB[req.params.id] };
      patientData.integrity_hash = generateRecordHMAC(patientData);
      return res.json({
        success: true,
        data: patientData
      });
    }
    console.error('Error fetching patient:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch patient'
    });
  }
});

// Create new patient - Restricted to Doctors and Admins (HIPAA Least Privilege § 164.312(a)(1))
router.post('/', requireDoctorOrAdmin, auditMiddleware('CREATE_PATIENT_RECORD', 'PATIENT_PHI'), async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      date_of_birth,
      gender,
      phone,
      email,
      address,
      emergency_contact_name,
      emergency_contact_phone
    } = req.body;
    
    // Basic validation
    if (!first_name || !last_name) {
      return res.status(400).json({
        success: false,
        error: 'First name and last name are required'
      });
    }
    
    const result = await db.query(`
      INSERT INTO patients (
        first_name, last_name, date_of_birth, gender,
        phone, email, address, emergency_contact_name, emergency_contact_phone
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `, [
      first_name, last_name, date_of_birth, gender,
      phone, email, address, emergency_contact_name, emergency_contact_phone
    ]);

    const newPatient = result.rows[0];

    // Auto-link the new patient to the user's account if they are non-admin and have no patient linked yet
    if (req.user.role !== 'admin' && !req.user.patientId) {
      await db.query(
        'UPDATE users SET patient_id = $1 WHERE id = $2',
        [newPatient.id, req.user.id]
      );
    }

    res.status(201).json({
      success: true,
      data: newPatient,
      message: 'Patient created successfully'
    });
  } catch (error) {
    console.error('Error creating patient:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create patient'
    });
  }
});

// Update patient - Protected with Object-Level Authorization
router.put('/:id', authorizePatientAccess, auditMiddleware('UPDATE_PATIENT_RECORD', 'PATIENT_PHI'), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      first_name,
      last_name,
      date_of_birth,
      gender,
      phone,
      email,
      address,
      emergency_contact_name,
      emergency_contact_phone
    } = req.body;
    
    const result = await db.query(`
      UPDATE patients SET
        first_name = $1,
        last_name = $2,
        date_of_birth = $3,
        gender = $4,
        phone = $5,
        email = $6,
        address = $7,
        emergency_contact_name = $8,
        emergency_contact_phone = $9,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $10
      RETURNING *
    `, [
      first_name, last_name, date_of_birth, gender,
      phone, email, address, emergency_contact_name, emergency_contact_phone, id
    ]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Patient not found'
      });
    }
    
    res.json({
      success: true,
      data: result.rows[0],
      message: 'Patient updated successfully'
    });
  } catch (error) {
    console.error('Error updating patient:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update patient'
    });
  }
});

// Delete patient - Restricted exclusively to Admins
router.delete('/:id', requireAdmin, auditMiddleware('DELETE_PATIENT_RECORD', 'PATIENT_PHI'), async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await db.query(`
      DELETE FROM patients WHERE id = $1 RETURNING id
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Patient not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Patient deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting patient:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete patient'
    });
  }
});

module.exports = router;