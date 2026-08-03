import { LightningElement, track, wire } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import runScan from '@salesforce/apex/PermissionRiskAnalyzerController.runScan';
import getLatestScanResults from '@salesforce/apex/PermissionRiskAnalyzerController.getLatestScanResults';

const RISK_LEVEL_ORDER = ['Critical', 'High', 'Medium', 'Low'];

const RISK_BADGE_CLASS = {
    Critical: 'risk-badge risk-critical',
    High: 'risk-badge risk-high',
    Medium: 'risk-badge risk-medium',
    Low: 'risk-badge risk-low'
};

const ALL_OPTION = { label: 'All', value: '' };

const SEVERITY_OPTIONS = [
    ALL_OPTION,
    ...RISK_LEVEL_ORDER.map((level) => ({ label: level, value: level }))
];

export default class PermissionRiskDashboard extends LightningElement {
    @track logs = [];
    @track selectedLogId;
    isLoading = false;
    errorMessage;
    lastScanDate;
    orgHealthScore;

    searchTerm = '';
    roleFilter = '';
    profileFilter = '';
    severityFilter = '';

    severityOptions = SEVERITY_OPTIONS;

    wiredResult;

    @wire(getLatestScanResults)
    wiredLatest(result) {
        this.wiredResult = result;
        if (result.data) {
            this.setLogs(result.data);
        } else if (result.error) {
            this.errorMessage = this.reduceError(result.error);
        }
    }

    get hasLogs() {
        return this.logs && this.logs.length > 0;
    }

    get riskCounts() {
        const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        this.logs.forEach((log) => {
            if (counts[log.RiskLevel__c] !== undefined) {
                counts[log.RiskLevel__c] += 1;
            }
        });
        return RISK_LEVEL_ORDER.map((level) => ({
            level,
            count: counts[level],
            badgeClass: RISK_BADGE_CLASS[level]
        }));
    }

    get overallRiskLevel() {
        if (!this.hasLogs) {
            return null;
        }
        const counts = this.riskCounts;
        const highest = counts.find((c) => c.count > 0);
        return highest ? highest.level : 'Low';
    }

    get overallRiskBadgeClass() {
        return this.overallRiskLevel ? RISK_BADGE_CLASS[this.overallRiskLevel] : '';
    }

    get atRiskUserCount() {
        return this.logs.filter((log) => log.RiskLevel__c !== 'Low').length;
    }

    get lastScanDateDisplay() {
        if (!this.lastScanDate) {
            return '';
        }
        const scanDate = new Date(this.lastScanDate);
        if (Number.isNaN(scanDate.getTime())) {
            return '';
        }

        const now = new Date();
        const diffMs = now - scanDate;
        const diffMin = Math.floor(diffMs / 60000);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);

        if (diffMin < 1) {
            return 'Just now';
        }
        if (diffMin < 60) {
            return `${diffMin} minute${diffMin === 1 ? '' : 's'} ago`;
        }

        const isSameDay = scanDate.toDateString() === now.toDateString();
        if (isSameDay) {
            return 'Today';
        }

        const yesterday = new Date(now);
        yesterday.setDate(yesterday.getDate() - 1);
        if (scanDate.toDateString() === yesterday.toDateString()) {
            return 'Yesterday';
        }

        if (diffDay < 7) {
            return `${diffDay} day${diffDay === 1 ? '' : 's'} ago`;
        }

        const diffWeek = Math.floor(diffDay / 7);
        if (diffWeek < 5) {
            return `${diffWeek} week${diffWeek === 1 ? '' : 's'} ago`;
        }

        const diffMonth = Math.floor(diffDay / 30);
        if (diffMonth < 12) {
            return `${diffMonth} month${diffMonth === 1 ? '' : 's'} ago`;
        }

        const diffYear = Math.floor(diffDay / 365);
        return `${diffYear} year${diffYear === 1 ? '' : 's'} ago`;
    }

    get roleOptions() {
        return this.buildOptionsFrom((log) => log.User__r && log.User__r.UserRole ? log.User__r.UserRole.Name : null);
    }

    get profileOptions() {
        return this.buildOptionsFrom((log) => log.User__r && log.User__r.Profile ? log.User__r.Profile.Name : null);
    }

    buildOptionsFrom(pluckName) {
        const names = new Set();
        this.logs.forEach((log) => {
            const name = pluckName(log);
            if (name) {
                names.add(name);
            }
        });
        return [ALL_OPTION, ...[...names].sort().map((name) => ({ label: name, value: name }))];
    }

    get hasActiveFilters() {
        return Boolean(this.searchTerm || this.roleFilter || this.profileFilter || this.severityFilter);
    }

    get clearFiltersDisabled() {
        return !this.hasActiveFilters;
    }

    get filteredLogs() {
        const term = this.searchTerm.trim().toLowerCase();
        return this.logs.filter((log) => {
            if (this.severityFilter && log.RiskLevel__c !== this.severityFilter) {
                return false;
            }
            const user = log.User__r || {};
            if (this.roleFilter && (!user.UserRole || user.UserRole.Name !== this.roleFilter)) {
                return false;
            }
            if (this.profileFilter && (!user.Profile || user.Profile.Name !== this.profileFilter)) {
                return false;
            }
            if (term) {
                const haystack = [user.Name, user.Username, user.Email]
                    .filter(Boolean)
                    .join(' ')
                    .toLowerCase();
                if (!haystack.includes(term)) {
                    return false;
                }
            }
            return true;
        });
    }

    get filteredResults() {
        return [...this.filteredLogs]
            .sort((a, b) => b.RiskScore__c - a.RiskScore__c)
            .map((log) => ({
                id: log.Id,
                name: log.User__r ? log.User__r.Name : log.User__c,
                username: log.User__r ? log.User__r.Username : '',
                roleName: log.User__r && log.User__r.UserRole ? log.User__r.UserRole.Name : '—',
                riskLevel: log.RiskLevel__c,
                riskScore: log.RiskScore__c,
                badgeClass: RISK_BADGE_CLASS[log.RiskLevel__c] || 'risk-badge',
                dangerousPermissions: log.DangerousPermissions__c
                    ? log.DangerousPermissions__c.split('|').join(', ')
                    : '—'
            }));
    }

    get showEmptyState() {
        return !this.isLoading && !this.hasLogs && !this.errorMessage;
    }

    get showNoMatchesState() {
        return this.hasLogs && this.hasActiveFilters && this.filteredResults.length === 0;
    }

    setLogs(data) {
        this.logs = data;
        if (data.length > 0) {
            this.lastScanDate = data[0].ScanDate__c;
            this.orgHealthScore = data[0].OrgHealthScore__c;
        }
    }

    async handleScanClick() {
        this.isLoading = true;
        this.errorMessage = undefined;
        try {
            // runScan() computes and persists the Permission_Risk_Log__c records,
            // but doesn't hand back their new record Ids. Re-fetch through
            // getLatestScanResults() so the table works with real log Ids
            // (needed by the "View" drill-down) instead of raw user Ids.
            const scanResult = await runScan();
            this.lastScanDate = scanResult.scanDate;
            this.orgHealthScore = scanResult.orgHealthScore;

            const freshLogs = await getLatestScanResults();
            this.setLogs(freshLogs);
            await refreshApex(this.wiredResult);
        } catch (error) {
            this.errorMessage = this.reduceError(error);
        } finally {
            this.isLoading = false;
        }
    }

    handleViewDetail(event) {
        this.selectedLogId = event.currentTarget.dataset.id;
    }

    handleCloseDetail() {
        this.selectedLogId = undefined;
    }

    handleSearchChange(event) {
        this.searchTerm = event.target.value || '';
    }

    handleRoleFilterChange(event) {
        this.roleFilter = event.detail.value;
    }

    handleProfileFilterChange(event) {
        this.profileFilter = event.detail.value;
    }

    handleSeverityFilterChange(event) {
        this.severityFilter = event.detail.value;
    }

    handleClearFilters() {
        this.searchTerm = '';
        this.roleFilter = '';
        this.profileFilter = '';
        this.severityFilter = '';
    }

    handleExportCsv() {
        if (!this.hasLogs) {
            this.showToast('Nothing to export', 'Run a scan first to generate results.', 'warning');
            return;
        }
        if (!this.filteredLogs.length) {
            this.showToast('Nothing to export', 'No scan results match the current filters.', 'warning');
            return;
        }
        try {
            const header = ['User', 'Username', 'Risk Level', 'Risk Score', 'Dangerous Permissions', 'Recommended Actions'];
            const rows = this.filteredLogs.map((log) => [
                log.User__r ? log.User__r.Name : '',
                log.User__r ? log.User__r.Username : '',
                log.RiskLevel__c,
                log.RiskScore__c,
                (log.DangerousPermissions__c || '').split('|').join('; '),
                (log.RecommendedActions__c || '').split('\n').join('; ')
            ]);
            const csvContent = [header, ...rows]
                .map((row) => row.map((cell) => `"${String(cell === undefined || cell === null ? '' : cell).replace(/"/g, '""')}"`).join(','))
                .join('\n');

            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `permission-risk-report-${new Date().toISOString().slice(0, 10)}.csv`;
            // Lightning Experience renders components inside a sandboxed iframe
            // that blocks same-frame anchor-click downloads; target="_blank"
            // makes the browser treat this as a new browsing context instead,
            // which isn't subject to that sandbox restriction.
            link.target = '_blank';
            link.rel = 'noopener';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        } catch (error) {
            this.showToast('Export failed', this.reduceError(error), 'error');
        }
    }

    showToast(title, message, variant) {
        this.dispatchEvent(new ShowToastEvent({ title, message, variant }));
    }

    reduceError(error) {
        if (Array.isArray(error.body)) {
            return error.body.map((e) => e.message).join(', ');
        }
        if (error.body && typeof error.body.message === 'string') {
            return error.body.message;
        }
        return error.message || 'An unknown error occurred';
    }
}
