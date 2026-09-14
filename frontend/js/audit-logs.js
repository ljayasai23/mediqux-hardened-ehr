'use strict';

class AuditLogsManager {
    constructor() {
        this.baseURL = (window.getApiBaseUrl && window.getApiBaseUrl()) || (window.ENV_CONFIG && window.ENV_CONFIG.API_BASE_URL) || '/api';
        this.currentLogs = [];
        this.init();
    }

    async init() {
        // Wait for auth verification
        const user = (window.authManager && window.authManager.user) || JSON.parse(localStorage.getItem('user') || 'null');
        const token = localStorage.getItem('authToken') || (window.authManager && window.authManager.token);

        if (!token || !user || user.role !== 'admin') {
            window.location.replace('index.html');
            return;
        }

        this.setupEventListeners();
        await this.loadStats();
        await this.loadAuditLogs();
    }

    setupEventListeners() {
        document.getElementById('refreshAuditBtn')?.addEventListener('click', () => {
            this.loadStats();
            this.loadAuditLogs();
        });

        document.getElementById('auditStatusFilter')?.addEventListener('change', () => {
            this.loadAuditLogs();
        });

        document.getElementById('auditActionFilter')?.addEventListener('change', () => {
            this.loadAuditLogs();
        });

        document.getElementById('auditLimitSelect')?.addEventListener('change', () => {
            this.loadAuditLogs();
        });

        let searchTimeout;
        document.getElementById('auditSearchInput')?.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                this.loadAuditLogs();
            }, 300);
        });
    }

    getAuthHeaders() {
        const token = localStorage.getItem('authToken');
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        };
    }

    async loadStats() {
        try {
            const response = await fetch(`${this.baseURL}/audit/stats`, {
                headers: this.getAuthHeaders()
            });
            if (!response.ok) return;
            const result = await response.json();
            if (result.success && result.stats) {
                document.getElementById('metricTotalEvents').textContent = result.stats.totalEvents.toLocaleString();
                document.getElementById('metricDeniedEvents').textContent = result.stats.deniedEvents.toLocaleString();
                document.getElementById('metricAiViolations').textContent = result.stats.aiViolations.toLocaleString();
                document.getElementById('metricPhiEvents').textContent = result.stats.phiEvents.toLocaleString();
            }
        } catch (e) {
            console.error('Error loading audit stats:', e);
        }
    }

    async loadAuditLogs() {
        const tbody = document.getElementById('auditTableBody');
        const status = document.getElementById('auditStatusFilter')?.value || 'ALL';
        const action = document.getElementById('auditActionFilter')?.value || '';
        const limit = document.getElementById('auditLimitSelect')?.value || '100';
        const search = document.getElementById('auditSearchInput')?.value || '';

        const params = new URLSearchParams();
        if (status !== 'ALL') params.append('status', status);
        if (action) params.append('action', action);
        if (limit) params.append('limit', limit);
        if (search.trim()) params.append('search', search.trim());

        try {
            const response = await fetch(`${this.baseURL}/audit?${params.toString()}`, {
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">Failed to load audit logs (HTTP ${response.status})</td></tr>`;
                return;
            }

            const result = await response.json();
            this.currentLogs = result.data || [];
            this.renderTable(this.currentLogs);
            document.getElementById('auditRecordCountDisplay').textContent = `Showing ${this.currentLogs.length} records`;
        } catch (error) {
            console.error('Audit query error:', error);
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">Error connecting to audit service</td></tr>`;
        }
    }

    renderTable(logs) {
        const tbody = document.getElementById('auditTableBody');
        if (!logs || logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No audit logs matching query</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map((log, index) => {
            const date = new Date(log.timestamp);
            const formattedTime = date.toISOString().replace('T', ' ').substring(0, 19);
            
            // Actor badge
            let roleBadge = '<span class="badge bg-secondary">Anonymous</span>';
            if (log.actor_role === 'admin') roleBadge = '<span class="badge bg-primary">Admin</span>';
            else if (log.actor_role === 'doctor') roleBadge = '<span class="badge bg-success">Doctor</span>';
            else if (log.actor_role === 'patient') roleBadge = '<span class="badge bg-info text-dark">Patient</span>';

            const actorDisplay = `
                <div><strong>${log.actor_username || 'System / Client'}</strong></div>
                <small class="text-muted">${roleBadge} ID: ${log.actor_id || '-'}</small>
            `;

            // Action formatting
            let actionBadge = `<span class="badge bg-light text-dark border font-monospace-sm">${log.action}</span>`;
            if (log.action.includes('AI_PROMPT_INJECTION')) {
                actionBadge = `<span class="badge bg-danger font-monospace-sm"><i class="bi bi-shield-slash me-1"></i>${log.action}</span>`;
            } else if (log.action.includes('AI_TOOL_IDOR')) {
                actionBadge = `<span class="badge bg-warning text-dark font-monospace-sm"><i class="bi bi-exclamation-diamond me-1"></i>${log.action}</span>`;
            } else if (log.action.includes('AI_')) {
                actionBadge = `<span class="badge bg-info text-dark font-monospace-sm"><i class="bi bi-robot me-1"></i>${log.action}</span>`;
            } else if (log.action.includes('PHI') || log.action.includes('PATIENT')) {
                actionBadge = `<span class="badge bg-primary font-monospace-sm"><i class="bi bi-hospital me-1"></i>${log.action}</span>`;
            }

            // Outcome badge
            const isDenied = log.status === 'DENIED';
            const outcomeBadge = isDenied
                ? '<span class="badge badge-denied"><i class="bi bi-x-circle me-1"></i>DENIED</span>'
                : '<span class="badge badge-success-audit"><i class="bi bi-check-circle me-1"></i>SUCCESS</span>';

            // HTTP Status
            let httpBadge = `<span class="badge bg-secondary">${log.http_status || '-'}</span>`;
            if (log.http_status === 200 || log.http_status === 201) httpBadge = `<span class="badge bg-success">${log.http_status}</span>`;
            else if (log.http_status === 400 || log.http_status === 401 || log.http_status === 403) httpBadge = `<span class="badge bg-danger">${log.http_status}</span>`;
            else if (log.http_status === 429) httpBadge = `<span class="badge bg-warning text-dark">429 LIMIT</span>`;

            return `
                <tr>
                    <td class="font-monospace-sm text-nowrap">${formattedTime}</td>
                    <td>${actorDisplay}</td>
                    <td>${actionBadge}</td>
                    <td><small class="text-muted font-monospace-sm">${log.resource_type || '-'} (${log.resource_id || '-'})</small></td>
                    <td>${httpBadge}</td>
                    <td>${outcomeBadge}</td>
                    <td style="text-align: center;">
                        <button class="btn btn-sm btn-outline-secondary" onclick="window.auditLogsManager.showDetail(${index})">
                            <i class="bi bi-eye"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    showDetail(index) {
        const record = this.currentLogs[index];
        if (!record) return;
        document.getElementById('auditModalJson').textContent = JSON.stringify(record, null, 2);
        const modal = new bootstrap.Modal(document.getElementById('auditDetailModal'));
        modal.show();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.auditLogsManager = new AuditLogsManager();
});
