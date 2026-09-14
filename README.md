# 🏥 MediQuX Healthcare Platform — Hardened & Compliance-Ready Edition

[![HIPAA Security Rule](https://img.shields.io/badge/Compliance-HIPAA%20§%20164.312-blue.svg)](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
[![OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010%20Hardened-green.svg)](https://owasp.org/www-project-top-ten/)
[![OWASP LLM Top 10](https://img.shields.io/badge/AI%20Security-OWASP%20LLM01%20%7C%20LLM07%20Guarded-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Security Tests](https://img.shields.io/badge/Tests-9%2F9%20Passing-brightgreen.svg)]()
[![Node.js](https://img.shields.io/badge/Node.js-22%20LTS-darkgreen.svg)](https://nodejs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17-blue.svg)](https://postgresql.org)

> **AI.Prof Security & Compliance Engineer Intern Technical Challenge**  
> **Candidate:** L. Jaya Sai Reddy  
> **Evaluation Focus:** Real-World Security Hardening, AI Clinical Gateway Security, CI/CD DevSecOps & HIPAA Compliance  
> **Compliance Framework:** HIPAA Security Rule (45 CFR Part 164 Subpart C)  

---

## 📖 Executive Summary

**MediQuX** is an enterprise-grade Electronic Health Record (EHR) and clinical triage platform designed for ambulatory clinics and healthcare institutions. 

Starting from an initial open-source baseline, this repository represents the **hardened, compliance-engineered edition** developed to satisfy the end-to-end security engineering lifecycle under PRD specifications:
$$\text{Discover} \longrightarrow \text{Assess} \longrightarrow \text{Validate} \longrightarrow \text{Prioritize} \longrightarrow \text{Remediate} \longrightarrow \text{Automate} \longrightarrow \text{Monitor}$$

### Key Engineering Accomplishments:
1. **Remediated 8 Critical & High-Risk Vulnerabilities** spanning BOLA/IDOR, broken authentication, permissive CORS leakage, weak cryptographic secrets, and missing access controls.
2. **Engineered a HIPAA § 164.312 Compliant Security Framework** with object-level patient ownership verification, HMAC cryptographic record integrity sealing, and tamper-evident audit logging.
3. **Built a Secure AI Clinical Gateway (PRD § 13)** incorporating prompt injection regex filtering (OWASP LLM01) and independent backend tool authorization guards (OWASP LLM07) with zero direct database privileges granted to LLMs.
4. **Implemented DevSecOps Security Automation (PRD § 14)** with GitHub Actions running SAST (Semgrep), SCA dependency scanning (`npm audit`), and an automated Jest security regression suite (9/9 passing tests).
5. **Constructed a Real-Time SIEM Anomaly Detection Daemon (PRD § 16)** capable of detecting credential stuffing, cross-tenant IDOR probes, and AI adversarial prompts with sub-second alert dispatch.

---

## 🏛️ Security Architecture & Trust Boundaries

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                    ZONE 1: EXTERNAL UNTRUSTED CLIENT                         │
│   Patient / Doctor / Admin Browser  ─── (HTTPS / TLS 1.3) ───►  Attacker      │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                    ZONE 2: INGRESS & REVERSE PROXY                           │
│   Strict CORS Whitelist • Rate Limiting • Security Headers (CSP, HSTS)       │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼───────────────────────────────────────┐
│              ZONE 3: APPLICATION & AUTHENTICATION BOUNDARY                   │
│   ┌────────────────────────┐  ┌───────────────────────┐  ┌────────────────┐  │
│   │ JWT Bearer Middleware  │  │ RBAC & Object-Level   │  │ HIPAA Audit    │  │
│   │ (HS256 256-bit Secret) │  │ IDOR Authorization    │  │ Structured Log │  │
│   └───────────┬────────────┘  └───────────┬───────────┘  └───────┬────────┘  │
│               └─────────────────────┬─────┘                      │           │
│                                     │                            │           │
│   ┌─────────────────────────────────▼────────────────────────────▼────────┐  │
│   │              PRD § 13 SECURE AI CLINICAL GATEWAY                      │  │
│   │  • Input Sanitization (Adversarial Prompt Injection Detection)        │  │
│   │  • Zero Model DB Access (Structured Tool Calls Only)                  │  │
│   │  • Backend Authorization Guard (Tenant-Isolated Tool Execution)       │  │
│   └─────────────────────────────────┬─────────────────────────────────────┘  │
└──────────────────────────────────────┼───────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                ZONE 4: SECURE STORAGE & DATABASE TIER                        │
│   PostgreSQL 17 (:5432) • HMAC Record Integrity Validator • Encrypted Backups │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Vulnerability Remediation Register

| Vulnerability ID | Vulnerability Category | Severity | OWASP / CWE | Root Cause & Technical Remediation |
| :--- | :--- | :---: | :---: | :--- |
| **VULN-01** | Broken Object-Level Auth (BOLA/IDOR) | **CRITICAL** | API1:2023 / CWE-639 | Fixed unauthenticated patient record access by implementing `authorizePatientAccess` checking JWT `patient_id` against requested resource. |
| **VULN-02** | Weak Cryptographic Secret Key | **HIGH** | A02:2021 / CWE-326 | Enforced minimum 32-character cryptographically random `JWT_SECRET` with startup failure on weak fallback keys. |
| **VULN-03** | Broken Function Level Auth (RBAC) | **HIGH** | API5:2023 / CWE-285 | Implemented `requireDoctorOrAdmin` and `requireAdmin` guards on doctor directory mutations and prescription updates. |
| **VULN-04** | Missing Data Integrity Verification | **HIGH** | A08:2021 / CWE-353 | Implemented SHA-256 HMAC cryptographic sealing (`generateRecordHMAC`) to detect record tampering under HIPAA § 164.312(c)(1). |
| **VULN-05** | Overly Permissive CORS Policy | **MEDIUM** | A01:2021 / CWE-942 | Replaced wildcard `Access-Control-Allow-Origin: *` with strict whitelist validation and origin regex check. |
| **VULN-06** | AI Direct Prompt Injection (LLM01) | **HIGH** | OWASP LLM01 | Implemented gateway-level adversarial pattern detection rejecting jailbreaks (`"Ignore all previous instructions"`) with HTTP 400. |
| **VULN-07** | AI Tool Manipulation & IDOR (LLM07) | **HIGH** | OWASP LLM07 | Stripped model database access; model outputs structured JSON tool calls intercepted and validated by backend authorization guards. |
| **VULN-08** | Inadequate Security Logging | **MEDIUM** | A09:2021 / CWE-778 | Built centralized structured audit logger emitting JSONL and PostgreSQL records for all PHI access, auth failures, and AI calls. |

---

## 🤖 PRD § 13 Secure AI Clinical Gateway

The AI Clinical Assistant (`/api/ai/chat`) provides symptom triage decision support and personal prescription retrieval governed by four fundamental architectural rules:

1. **The AI model is never treated as an authorization boundary.**
2. **The model has ZERO credentials or network connectivity to the database, filesystem, or administrative APIs.**
3. **The model communicates exclusively through structured JSON tool requests.**
4. **The backend independently authorizes caller identity before executing any tool.**

### Registered Safe AI Tools:
* `triage_symptom_inquiry`: Deterministic symptom evaluation returning clinical urgency and recommended medical specialties.
* `fetch_patient_medications`: Retrieves active prescriptions. Requires verified patient chart ownership; blocks cross-tenant attempts.
* `request_appointment_booking`: Creates appointment requests for verified patients.

---

## 🧪 Automated Security Regression Test Suite

All security remediations are covered by automated regression tests in [`backend/tests/security/security_controls.test.js`](backend/tests/security/security_controls.test.js):

```bash
cd backend
npx jest tests/security/security_controls.test.js --verbose
```

### Test Suite Execution Output:
```text
PASS tests/security/security_controls.test.js
  Security & Compliance Regression Test Suite (HIPAA & OWASP Controls)
    1. BOLA / IDOR Access Control (VULN-01 Regression Guard)
      ✓ should allow patient to access their OWN patient record (66 ms)
      ✓ should BLOCK cross-tenant IDOR when patient attempts to read another record (21 ms)
      ✓ should allow Admin to access any patient record for clinical oversight (15 ms)
    2. HIPAA § 164.312(c)(1) Cryptographic Data Integrity (VULN-04)
      ✓ should generate valid deterministic HMAC for medical records (3 ms)
      ✓ should verify genuine untampered record successfully (1 ms)
      ✓ should DETECT and REJECT record tampering (dosage alteration) (2 ms)
    3. PRD § 13 Secure AI Gateway & Red Teaming Defenses
      ✓ should block direct prompt injection attempts (3 ms)
      ✓ should block AI tool cross-tenant IDOR attack (3 ms)
      ✓ should provide safe clinical symptom triage for legitimate inquiry (2 ms)

Test Suites: 1 passed, 1 total
Tests:       9 passed, 9 total
Time:        10.758 s
```

---

## ⚙️ Quick Start & Local Setup

### 1. Prerequisites
* **Node.js**: v20.x or v22.x LTS
* **PostgreSQL**: v16 or v17 (or Docker)

### 2. Environment Configuration
Copy the configuration template:
```bash
cp backend/.env.example backend/.env
```
Ensure `JWT_SECRET` is set to a secure random string (minimum 32 characters).

### 3. Database Setup (Docker or Local Postgres)
If using Docker for PostgreSQL:
```bash
docker run -d --name mediqux_postgres -p 5432:5432 \
  -e POSTGRES_DB=mediqux_db \
  -e POSTGRES_USER=mediqux_user \
  -e POSTGRES_PASSWORD=mediqux_pass \
  postgres:17-alpine
```

Seed database demo users:
```bash
cd backend
node seed_users.js
```

### 4. Install Dependencies & Start Server
```bash
cd backend
npm install
npm start
```
The server will start on `http://localhost:3000`.

---

## 👥 Demo Personas & Credentials

| Role | Username | Password | Purpose & Scenarios |
| :--- | :--- | :--- | :--- |
| **System Administrator** | `admin` | `Admin123!` | Full platform administration, user management, and security audit log inspection. |
| **Attending Physician** | `ghouse` | `Doctor123!` | Clinical directory viewing, patient consultations, read-only staff view. |
| **Patient** | `alice` | `Patient123!` | Personal health summary, active medications, AI symptom triage. |

---

## 🔄 CI/CD DevSecOps Automation

The `.github/workflows/security.yml` pipeline automates three security gates on every push and pull request:
1. **Static Application Security Testing (SAST):** Semgrep scanning for OWASP Top 10 vulnerabilities, SQL injection, and insecure cryptographic usage.
2. **Software Composition Analysis (SCA):** `npm audit --audit-level=high` detecting vulnerable third-party dependencies.
3. **Automated Security Regression Suite:** Automated execution of Jest security controls verifying BOLA, HMAC, and AI guardrails.

---

## 📜 Compliance Mapping (HIPAA Security Rule)

| HIPAA Specification | Regulatory Requirement | MediQuX Technical Implementation |
| :--- | :--- | :--- |
| **§ 164.312(a)(1)** | Unique User Identification & Access Control | JWT Bearer authentication with role claims and object-level patient ownership checks. |
| **§ 164.312(a)(2)(iii)** | Automatic Logoff | Client-side inactivity token expiration and prominent secure session revocation. |
| **§ 164.312(b)** | Audit Controls | Centralized audit logger recording actor, role, action, resource, HTTP status, and client IP. |
| **§ 164.312(c)(1)** | Mechanism to Authenticate Electronic PHI | SHA-256 HMAC record integrity verification detecting unauthorized clinical alterations. |
| **§ 164.312(d)** | Person or Entity Authentication | Bcrypt password hashing (cost factor 10) with credential-stuffing detection. |
| **§ 164.312(e)(1)** | Transmission Security | TLS 1.3 encryption in transit and strict Cross-Origin Resource Sharing (CORS) whitelisting. |

---

## 👤 Author & Acknowledgments

* **Engineering & Hardening:** L. Jaya Sai Reddy (B.Tech Computer Science & Engineering)
* **Submitted for:** AI.Prof Security & Compliance Engineer Intern Evaluation
* **Base Project:** Mediqux EHR Open-Source Project
