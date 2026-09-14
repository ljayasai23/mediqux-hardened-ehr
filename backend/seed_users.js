'use strict';
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'mediqux_db',
  user: process.env.DB_USER || 'mediqux_user',
  password: process.env.DB_PASSWORD || 'mediqux_pass'
});

async function seedUsers() {
  const client = await pool.connect();
  try {
    console.log('Seeding Mediqux users into PostgreSQL...');

    // Fetch existing patient IDs
    const patientRes = await client.query('SELECT id, first_name, last_name FROM patients ORDER BY created_at ASC');
    const dennyId = patientRes.rows[0]?.id || null;
    const rebeccaId = patientRes.rows[1]?.id || null;

    const users = [
      {
        username: 'admin',
        email: 'admin@mediqux.org',
        password: 'Admin123!',
        first_name: 'System',
        last_name: 'Admin',
        role: 'admin',
        patient_id: null
      },
      {
        username: 'dr_house',
        email: 'house@mediqux.org',
        password: 'Doctor123!',
        first_name: 'Gregory',
        last_name: 'House',
        role: 'doctor',
        patient_id: null
      },
      {
        username: 'alice',
        email: 'alice@example.com',
        password: 'Patient123!',
        first_name: 'Alice',
        last_name: 'Smith',
        role: 'patient',
        patient_id: dennyId
      },
      {
        username: 'bob',
        email: 'bob@example.com',
        password: 'Patient123!',
        first_name: 'Bob',
        last_name: 'Jones',
        role: 'patient',
        patient_id: rebeccaId
      }
    ];

    for (const u of users) {
      const hash = await bcrypt.hash(u.password, 10);
      await client.query(`
        INSERT INTO users (username, email, password_hash, first_name, last_name, role, patient_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (username) DO UPDATE SET
          password_hash = EXCLUDED.password_hash,
          role = EXCLUDED.role,
          patient_id = EXCLUDED.patient_id,
          updated_at = CURRENT_TIMESTAMP
      `, [u.username, u.email, hash, u.first_name, u.last_name, u.role, u.patient_id]);
      console.log(`✓ User seeded: ${u.username} (${u.role})`);
    }

    console.log('User seeding completed successfully!');
  } catch (err) {
    console.error('Error seeding users:', err);
  } finally {
    client.release();
    await pool.end();
  }
}

seedUsers();
