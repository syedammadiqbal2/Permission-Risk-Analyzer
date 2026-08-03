/**
 * PermissionRiskAnalyzerController
 *
 * Thin @AuraEnabled layer between the Lightning Web Components and
 * PermissionRiskAnalyzerService. Keeps all scoring logic in the service class
 * so it stays independently unit-testable.
 */
public with sharing class PermissionRiskAnalyzerController {

    /** Triggered by the "Scan Org" button. Runs a fresh scan and returns it. */
    @AuraEnabled
    public static PermissionRiskAnalyzerService.ScanResult runScan() {
        try {
            return PermissionRiskAnalyzerService.scanOrg();
        } catch (Exception e) {
            throw new AuraHandledException('Scan failed: ' + e.getMessage());
        }
    }

    /** Loads the most recent scan results for the dashboard without re-scanning. */
    @AuraEnabled(cacheable=true)
    public static List<Permission_Risk_Log__c> getLatestScanResults() {
        List<Permission_Risk_Log__c> latest = [
            SELECT ScanBatchId__c
            FROM Permission_Risk_Log__c
            WITH SECURITY_ENFORCED
            ORDER BY ScanDate__c DESC
            LIMIT 1
        ];

        if (latest.isEmpty()) {
            return new List<Permission_Risk_Log__c>();
        }

        String latestBatchId = latest[0].ScanBatchId__c;

        return [
            SELECT Id, Name, User__c, User__r.Name, User__r.Username,
                   RiskScore__c, RiskLevel__c, DangerousPermissions__c,
                   RecommendedActions__c, ScanDate__c, OrgHealthScore__c
            FROM Permission_Risk_Log__c
            WHERE ScanBatchId__c = :latestBatchId
            WITH SECURITY_ENFORCED
            ORDER BY RiskScore__c DESC
        ];
    }

    /** Powers the drill-down / user detail view. */
    @AuraEnabled(cacheable=true)
    public static Permission_Risk_Log__c getUserDetail(Id logId) {
        List<Permission_Risk_Log__c> records = [
            SELECT Id, Name, User__c, User__r.Name, User__r.Username,
                   User__r.Profile.Name, User__r.UserRole.Name,
                   User__r.LastLoginDate, User__r.IsActive,
                   RiskScore__c, RiskLevel__c, DangerousPermissions__c,
                   RecommendedActions__c, Details__c, ScanDate__c
            FROM Permission_Risk_Log__c
            WHERE Id = :logId
            WITH SECURITY_ENFORCED
            LIMIT 1
        ];
        return records.isEmpty() ? null : records[0];
    }
}
