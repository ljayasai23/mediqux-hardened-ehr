class AuthManager {
    constructor() {
        this.baseURL = window.getApiBaseUrl();
        this.token = localStorage.getItem('authToken');
        this.user = JSON.parse(localStorage.getItem('user') || 'null');

        this.validateAndClearTokens();
    }

    async init() {
        if (window.location.pathname.includes('login.html')) {
            await this.initLoginPage();
        } else {
            this.checkAuth();
        }
    }

    validateAndClearTokens() {
        if (this.token) {
            const tokenParts = this.token.split('.');
            if (tokenParts.length !== 3 || this.token.length < 50) {
                localStorage.removeItem('authToken');
                localStorage.removeItem('user');
                this.token = null;
                this.user = null;
            }
        }
    }

    async initLoginPage() {
        await this.checkInitialSetup();
        
        this.setupLoginEventListeners();
    }

    async checkInitialSetup() {
        try {
            const response = await fetch(`${this.baseURL}/auth/initial-config`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            
            if (result.success && !result.data.hasUsers) {
                document.getElementById('setupAlert').classList.remove('d-none');
                this.showSignupForm();
                document.getElementById('signupLink').classList.add('d-none');
            } else {
                this.showLoginForm();
            }
        } catch (error) {
            console.error('Setup check failed:', error);
            this.showError('Failed to check system setup');
        }
    }

    setupLoginEventListeners() {
        document.getElementById('loginForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.getElementById('signupForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleSignup();
        });

        document.getElementById('togglePassword').addEventListener('click', () => {
            const passwordField = document.getElementById('password');
            const icon = document.querySelector('#togglePassword i');
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.replace('bi-eye', 'bi-eye-slash');
            } else {
                passwordField.type = 'password';
                icon.classList.replace('bi-eye-slash', 'bi-eye');
            }
        });

        document.getElementById('showSignup')?.addEventListener('click', () => {
            this.showSignupForm();
        });

        document.getElementById('backToLogin')?.addEventListener('click', () => {
            this.showLoginForm();
        });
    }

    async handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        if (!username || !password) {
            this.showError('Please enter both username and password');
            return;
        }

        this.showLoading(true);

        try {
            const response = await fetch(`${this.baseURL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const result = await response.json();

            if (result.success) {
                localStorage.setItem('authToken', result.data.token);
                localStorage.setItem('user', JSON.stringify(result.data.user));
                
                this.showSuccess('Login successful! Redirecting...');
                
                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 1500);
            } else {
                this.showError(result.error || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showError('Login failed. Please try again.');
        } finally {
            this.showLoading(false);
        }
    }

    async handleSignup() {
        const firstName = document.getElementById('firstName').value;
        const lastName = document.getElementById('lastName').value;
        const username = document.getElementById('signupUsername').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('signupPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (!firstName || !lastName || !username || !email || !password) {
            this.showError('Please fill in all fields');
            return;
        }

        if (password !== confirmPassword) {
            this.showError('Passwords do not match');
            return;
        }

        if (password.length < 6) {
            this.showError('Password must be at least 6 characters long');
            return;
        }

        this.showLoading(true);

        try {
            const response = await fetch(`${this.baseURL}/auth/signup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    firstName,
                    lastName,
                    username,
                    email,
                    password
                })
            });

            const result = await response.json();

            if (result.success) {
                localStorage.setItem('authToken', result.data.token);
                localStorage.setItem('user', JSON.stringify(result.data.user));
                
                this.showSuccess('Account created successfully! Redirecting...');
                
                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 1500);
            } else {
                this.showError(result.error || 'Signup failed');
            }
        } catch (error) {
            console.error('Signup error:', error);
            this.showError('Signup failed. Please try again.');
        } finally {
            this.showLoading(false);
        }
    }

    showSignupForm() {
        document.getElementById('loginForm').classList.add('d-none');
        document.getElementById('signupSection').classList.remove('d-none');
        document.getElementById('signupLink').classList.add('d-none');
        document.documentElement.style.setProperty('--login-visibility', 'visible');
    }

    showLoginForm() {
        document.getElementById('loginForm').classList.remove('d-none');
        document.getElementById('signupSection').classList.add('d-none');
        document.getElementById('signupLink').classList.remove('d-none');
        document.documentElement.style.setProperty('--login-visibility', 'visible');
    }

    checkAuth() {
        if (!this.token || !this.user) {
            this.redirectToLogin();
            return false;
        }
        
        this.updateUserInfo();
        return true;
    }

    updateUserInfo() {
        const userNameElements = document.querySelectorAll('.user-name');
        const userRoleElements = document.querySelectorAll('.user-role');
        
        if (this.user) {
            userNameElements.forEach(el => {
                el.textContent = `${this.user.firstName} ${this.user.lastName}`;
            });
            
            userRoleElements.forEach(el => {
                el.textContent = this.user.role.charAt(0).toUpperCase() + this.user.role.slice(1);
            });
            
            this.updateAdminElements();
        }
    }
    
    updateAdminElements() {
        const adminElements = document.querySelectorAll('.admin-only');
        const userOnlyElements = document.querySelectorAll('.user-only');
        const isAdmin = this.user && this.user.role === 'admin';
        
        adminElements.forEach(el => {
            if (isAdmin) {
                el.style.display = '';
            } else {
                el.style.display = 'none';
            }
        });
        
        userOnlyElements.forEach(el => {
            if (!isAdmin) {
                el.style.display = '';
            } else {
                el.style.display = 'none';
            }
        });
        
        this.updateRoleBasedNavigation();
    }
    
    updateRoleBasedNavigation() {
        if (!this.user) return;
        
        const role = (this.user.role || '').toLowerCase();
        
        // Update user role and display name in navigation
        const userRoleElements = document.querySelectorAll('.user-role');
        userRoleElements.forEach(el => {
            el.textContent = role === 'admin' ? 'System Administrator' : (role === 'doctor' ? 'Attending Physician' : 'Patient Portal');
        });
        
        const userNameElements = document.querySelectorAll('.user-name');
        userNameElements.forEach(el => {
            const displayName = this.user.firstName ? `${this.user.firstName} ${this.user.lastName || ''}`.trim() : (this.user.username || 'User');
            el.textContent = displayName;
        });

        // 1. PATIENT ROLE LEAST-PRIVILEGE UI FILTERING (HIPAA § 164.312(a)(1))
        if (role === 'patient') {
            // Patients must NEVER see internal clinical/administrative management options
            const prohibitedLinks = [
                'patients.html',
                'institutions.html',
                'doctors.html',
                'diagnostic-studies.html',
                'conditions.html',
                'medications.html',
                'users.html',
                'audit-logs.html'
            ];
            
            prohibitedLinks.forEach(page => {
                document.querySelectorAll(`a.nav-link[href="${page}"], a.dropdown-item[href="${page}"]`).forEach(link => {
                    const parentLi = link.closest('.nav-item') || link.closest('li');
                    if (parentLi && !parentLi.classList.contains('dropdown')) {
                        parentLi.style.display = 'none';
                    } else {
                        link.style.display = 'none';
                    }
                });
            });

            // Prevent direct URL navigation: redirect patients away from administrative directory pages
            const currentPath = window.location.pathname.split('/').pop() || 'index.html';
            if (['patients.html', 'institutions.html', 'users.html', 'audit-logs.html'].includes(currentPath)) {
                window.location.replace('index.html');
                return;
            }

            // Hide clinical mutation buttons (patients consume records, they do not create them)
            const addButtons = document.querySelectorAll('[data-bs-toggle="modal"][data-bs-target*="Modal"], .admin-action, .btn-primary:has(.bi-plus), .btn-primary:has(.bi-person-plus)');
            addButtons.forEach(btn => {
                // Keep password change or legitimate patient action buttons, hide clinical creation modals
                if (btn.getAttribute('data-bs-target') !== '#changePasswordModal') {
                    btn.style.display = 'none';
                }
            });
        }

        // 2. DOCTOR ROLE LEAST-PRIVILEGE UI FILTERING
        if (role === 'doctor') {
            // Doctors cannot manage user accounts, audit logs, or hospital facilities
            document.querySelectorAll('a.nav-link[href="users.html"], a.dropdown-item[href="users.html"], a.nav-link[href="institutions.html"], a.dropdown-item[href="audit-logs.html"], a.nav-link[href="audit-logs.html"]').forEach(link => {
                const parentLi = link.closest('.nav-item') || link.closest('li');
                if (parentLi) parentLi.style.display = 'none';
            });

            const currentPath = window.location.pathname.split('/').pop() || 'index.html';
            if (['users.html', 'audit-logs.html'].includes(currentPath)) {
                window.location.replace('index.html');
                return;
            }
        }

        // Clean up orphaned "Settings" dropdown headers for non-admin roles
        if (role !== 'admin') {
            document.querySelectorAll('.dropdown-menu .dropdown-header').forEach(header => {
                if (header.textContent.toLowerCase().includes('settings')) {
                    const li = header.closest('li');
                    if (li) li.style.display = 'none';
                    const prevLi = li?.previousElementSibling;
                    if (prevLi && prevLi.querySelector('.dropdown-divider')) {
                        prevLi.style.display = 'none';
                    }
                }
            });
        }

        // 3. INJECT "AI ASSISTANT" & "SECURITY AUDIT LOGS" NAV ITEMS DYNAMICALLY
        const navbarNav = document.querySelector('.navbar-nav');
        if (navbarNav && !document.querySelector('a.nav-link[href="ai-assistant.html"]')) {
            const aiLink = document.createElement('a');
            aiLink.className = `nav-link ${window.location.pathname.includes('ai-assistant.html') ? 'active' : ''}`;
            aiLink.href = 'ai-assistant.html';
            aiLink.innerHTML = '<i class="bi bi-robot text-primary me-1"></i>AI Assistant';
            
            const recordsDropdown = navbarNav.querySelector('.nav-item.dropdown');
            if (recordsDropdown) {
                recordsDropdown.before(aiLink);
            } else {
                navbarNav.appendChild(aiLink);
            }
        }

        if (role === 'admin' && !document.querySelector('a.dropdown-item[href="audit-logs.html"]')) {
            const userMgmtLink = document.querySelector('a[href="users.html"]');
            if (userMgmtLink) {
                const auditLi = document.createElement('li');
                auditLi.innerHTML = `
                    <a class="dropdown-item admin-only ${window.location.pathname.includes('audit-logs.html') ? 'active' : ''}" href="audit-logs.html">
                        <i class="bi bi-shield-check me-2 text-primary"></i>Security Audit Logs
                    </a>
                `;
                userMgmtLink.closest('li')?.after(auditLi);
            }
        }

        // 4. PROMINENT DIRECT LOGOUT BUTTON IN NAVBAR FOR ALL USERS
        const userDropdownEl = document.getElementById('userDropdown');
        if (userDropdownEl && !document.getElementById('directLogoutBtn')) {
            const userNavItem = userDropdownEl.closest('.nav-item') || userDropdownEl.parentElement;
            const parentNav = userNavItem?.parentElement;
            if (parentNav) {
                const logoutNavItem = document.createElement('div');
                logoutNavItem.className = 'nav-item ms-2 d-flex align-items-center';
                logoutNavItem.innerHTML = `
                    <button id="directLogoutBtn" class="btn btn-outline-danger btn-sm logout-btn py-1 px-2 d-flex align-items-center" title="Logout">
                        <i class="bi bi-box-arrow-right me-1"></i>Logout
                    </button>
                `;
                userNavItem.after(logoutNavItem);
                logoutNavItem.querySelector('#directLogoutBtn').addEventListener('click', (e) => {
                    e.preventDefault();
                    this.logout();
                });
            }
        }


        this.updateActionButtons();
    }
    
    updateActionButtons() {
        if (!this.user) return;
        
        const isAdmin = this.user.role === 'admin';
        const isDoctorOrAdmin = this.user.role === 'admin' || this.user.role === 'doctor';
        
        // Hide "+ Add Patient" button from non-clinical patients
        const addPatientBtn = document.querySelector('[data-bs-target="#patientModal"]');
        if (addPatientBtn) {
            addPatientBtn.style.display = isDoctorOrAdmin ? '' : 'none';
        }
        
        const restrictedButtons = document.querySelectorAll('.admin-action');
        restrictedButtons.forEach(button => {
            button.style.display = isAdmin ? '' : 'none';
        });
    }

    async apiRequest(endpoint, options = {}) {
        const headers = {
            'Authorization': `Bearer ${this.token}`,
            ...options.headers
        };
        
        if (!(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
        }
        
        const config = {
            headers,
            ...options
        };

        try {
            const response = await fetch(`${this.baseURL}${endpoint}`, config);
            
            if (response.status === 401) {
                this.logout();
                return null;
            }
            
            return response;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    logout() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        this.token = null;
        this.user = null;
        this.redirectToLogin();
    }

    redirectToLogin() {
        window.location.href = 'login.html';
    }

    showLoading(show) {
        const spinner = document.getElementById('loadingSpinner');
        if (spinner) {
            if (show) {
                spinner.classList.remove('d-none');
            } else {
                spinner.classList.add('d-none');
            }
        }
    }

    showError(message) {
        this.showAlert(message, 'danger');
    }

    showSuccess(message) {
        this.showAlert(message, 'success');
    }

    showAlert(message, type) {
        const existingAlerts = document.querySelectorAll('.auth-alert');
        existingAlerts.forEach(alert => alert.remove());

        const alert = document.createElement('div');
        alert.className = `alert alert-${type} auth-alert alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        const cardBody = document.querySelector('.card-body');
        if (cardBody) {
            cardBody.insertBefore(alert, cardBody.firstChild);
        }

        setTimeout(() => {
            if (alert.parentNode) {
                alert.remove();
            }
        }, 5000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.authManager = new AuthManager();
    window.authManager.init();
});

document.addEventListener('DOMContentLoaded', () => {
    const logoutButtons = document.querySelectorAll('.logout-btn');
    logoutButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            e.preventDefault();
            if (window.authManager) {
                window.authManager.logout();
            }
        });
    });
});