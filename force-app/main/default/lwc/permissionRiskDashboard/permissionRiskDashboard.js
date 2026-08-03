import { LightningElement, track, wire } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import runScan from '@salesforce/apex/PermissionRiskAnalyzerController.runScan';
import getLatestScanResults from '@salesforce/apex/PermissionRiskAnalyzerController.getLatestScanResults';

const RISK_LEVEL_ORDER = ['Critical', 'High', 'Medium', 'Low'];

const RISK_BADGE_CLASS = {
    Critical: 'risk-badge risk-critical',
    High: 'risk-badge risk-high',
    Medium: 'risk-badge risk-medium',
    Low: 'risk-badge risk-low'
};

export default class PermissionRiskDashboard extends LightningElement {
    @track logs = [];
    @track selectedLogId;
    isLoading = false;
    errorMessage;
    lastScanDate;
    orgHealthScore;

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

    get topRisks() {
        return [...this.logs]
            .sort((a, b) => b.RiskScore__c - a.RiskScore__c)
            .slice(0, 10)
            .map((log) => ({
                id: log.Id,
                name: log.User__r ? log.User__r.Name : log.User__c,
                username: log.User__r ? log.User__r.Username : '',
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

    handleExportCsv() {
        if (!this.hasLogs) {
            return;
        }
        const header = ['User', 'Username', 'Risk Level', 'Risk Score', 'Dangerous Permissions', 'Recommended Actions'];
        const rows = this.logs.map((log) => [
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
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
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
