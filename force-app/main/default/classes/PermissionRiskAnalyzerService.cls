/**
 * PermissionRiskAnalyzerService
 *
 * Core scanning + scoring engine for the Permission Risk Analyzer app.
 *
 * Approach: every user in Salesforce always has at least one PermissionSetAssignment
 * that represents their Profile (PermissionSet.IsOwnedByProfile = true), plus zero or
 * more assigned Permission Sets / Permission Set Groups. Reading PermissionSetAssignment
 * joined to PermissionSet therefore gives us the *effective* system permissions for a
 * user without having to separately reconcile Profile permissions and Permission Set
 * permissions - Salesforce already unions them for us at that layer.
 */
public with sharing class PermissionRiskAnalyzerService {

    // Dangerous system permission API names -> risk weight contributed per user.
    @TestVisible
    private static final Map<String, Integer> DANGEROUS_PERMISSION_WEIGHTS = new Map<String, Integer>{
        'PermissionsModifyAllData' => 100,
        'PermissionsViewAllData' => 50,
        'PermissionsManageUsers' => 80,
        'PermissionsManageProfilesPermissionsets' => 60,
        'PermissionsManageRoles' => 40,
        'PermissionsManageSharing' => 30,
        'PermissionsResetPasswords' => 25,
        'PermissionsAuthorApex' => 20
    };

    // Friendly labels for display / recommended-action text.
    @TestVisible
    private static final Map<String, String> PERMISSION_LABELS = new Map<String, String>{
        'PermissionsModifyAllData' => 'Modify All Data',
        'PermissionsViewAllData' => 'View All Data',
        'PermissionsManageUsers' => 'Manage Users',
        'PermissionsManageProfilesPermissionsets' => 'Manage Profiles and Permission Sets',
        'PermissionsManageRoles' => 'Manage Roles',
        'PermissionsManageSharing' => 'Manage Sharing',
        'PermissionsResetPasswords' => 'Reset Passwords',
        'PermissionsAuthorApex' => 'Author Apex'
    };

    // Standard objects checked for same-role edit-access inconsistencies. A user
    // whose peers (same UserRole) can't edit one of these, but they can, gets
    // flagged - that split is itself a sign of a misconfigured/one-off grant.
    @TestVisible
    private static final List<String> SENSITIVE_OBJECTS = new List<String>{
        'Account', 'Contact', 'Opportunity', 'Lead', 'Case'
    };

    private static final Integer INACTIVITY_DAYS_THRESHOLD = 90;
    private static final Integer COMPOUND_RISK_PERMISSION_COUNT = 3;
    private static final Integer COMPOUND_RISK_BONUS = 50;
    private static final Integer ROLE_MISMATCH_BONUS = 30;
    private static final Integer INACTIVE_WITH_ACCESS_BONUS = 40;
    private static final Integer EXTERNAL_USER_BONUS = 70;
    private static final Integer OBJECT_ACCESS_MISMATCH_BONUS = 35;

    private static final Integer THRESHOLD_CRITICAL = 150;
    private static final Integer THRESHOLD_HIGH = 80;
    private static final Integer THRESHOLD_MEDIUM = 30;

    /**
     * Runs a full org scan: pulls active + inactive users (excluding automated
     * process/integration users where sensible), aggregates their effective
     * permissions, scores each one, persists the results, and returns them.
     */
    public static ScanResult scanOrg() {
        List<User> users = queryUsers();
        Map<Id, AggregatedPermissions> permsByUser = aggregatePermissions(users);

        List<UserRiskResult> userResults = new List<UserRiskResult>();
        for (User u : users) {
            AggregatedPermissions perms = permsByUser.get(u.Id);
            if (perms == null) {
                perms = new AggregatedPermissions();
            }
            userResults.add(calculateUserRisk(u, perms));
        }

        // Peer comparison needs every user's score already computed, so it can
        // only run after the individual-scoring loop above, not inside it.
        applyPeerObjectAccessComparison(userResults);

        userResults.sort();

        Integer orgHealthScore = calculateOrgHealthScore(userResults);
        String scanBatchId = generateBatchId();
        DateTime scanDate = System.now();

        List<Permission_Risk_Log__c> logsToInsert = new List<Permission_Risk_Log__c>();
        for (UserRiskResult r : userResults) {
            logsToInsert.add(toLogRecord(r, scanBatchId, scanDate, orgHealthScore));
        }

        if (!logsToInsert.isEmpty() && Schema.sObjectType.Permission_Risk_Log__c.isCreateable()) {
            insert logsToInsert;
        }

        ScanResult result = new ScanResult();
        result.scanBatchId = scanBatchId;
        result.scanDate = scanDate;
        result.orgHealthScore = orgHealthScore;
        result.orgRiskLevel = scoreToRiskLevel(orgHealthScore);
        result.userResults = userResults;
        result.criticalCount = countAtLevel(userResults, 'Critical');
        result.highCount = countAtLevel(userResults, 'High');
        result.mediumCount = countAtLevel(userResults, 'Medium');
        result.lowCount = countAtLevel(userResults, 'Low');
        return result;
    }

    /**
     * Calculates a single user's risk score and reasons. Public + static so it
     * can be unit tested directly without requiring a full org scan/insert.
     */
    @TestVisible
    private static UserRiskResult calculateUserRisk(User u, AggregatedPermissions perms) {
        UserRiskResult r = new UserRiskResult();
        r.userId = u.Id;
        r.displayName = u.Name;
        r.username = u.Username;
        r.profileName = u.Profile != null ? u.Profile.Name : null;
        r.roleName = u.UserRole != null ? u.UserRole.Name : null;
        r.isActive = u.IsActive;
        r.lastLoginDate = u.LastLoginDate;
        r.userType = u.UserType;

        Integer score = 0;
        List<String> dangerousPermissions = new List<String>();
        List<String> reasons = new List<String>();
        List<String> recommendedActions = new List<String>();

        // 1. Dangerous permissions (individually weighted)
        for (String permKey : DANGEROUS_PERMISSION_WEIGHTS.keySet()) {
            if (perms.hasPermission(permKey)) {
                score += DANGEROUS_PERMISSION_WEIGHTS.get(permKey);
                String label = PERMISSION_LABELS.get(permKey);
                dangerousPermissions.add(label);
                recommendedActions.add('Review whether "' + label + '" is required for this user; remove if not.');
            }
        }

        // 2. Compound risk: many dangerous permissions stacked on one user
        if (dangerousPermissions.size() >= COMPOUND_RISK_PERMISSION_COUNT) {
            score += COMPOUND_RISK_BONUS;
            reasons.add(dangerousPermissions.size() + ' dangerous permissions combined on one user (compound risk)');
        }

        // 3. Role vs permission mismatch: no management-tier role name, but has
        // high-privilege system permissions.
        Boolean looksLikeManagementRole = roleLooksLikeManagementTier(r.roleName);
        Boolean hasHighPrivilege = perms.hasPermission('PermissionsModifyAllData')
            || perms.hasPermission('PermissionsManageUsers');
        if (!looksLikeManagementRole && hasHighPrivilege) {
            score += ROLE_MISMATCH_BONUS;
            reasons.add('Role (' + (String.isBlank(r.roleName) ? 'no role assigned' : r.roleName)
                + ') does not obviously justify the permissions this user holds');
            recommendedActions.add('Confirm with the user\'s manager whether this access level matches their job role.');
        }

        // 4. Inactive user retaining dangerous access
        Boolean isInactiveLogin = u.LastLoginDate == null
            || u.LastLoginDate < System.now().addDays(-INACTIVITY_DAYS_THRESHOLD);
        if (isInactiveLogin && !dangerousPermissions.isEmpty()) {
            score += INACTIVE_WITH_ACCESS_BONUS;
            reasons.add(u.LastLoginDate == null
                ? 'User has never logged in but retains dangerous permissions'
                : 'Last login over ' + INACTIVITY_DAYS_THRESHOLD + ' days ago, but user retains dangerous permissions');
            recommendedActions.add('Consider deactivating this user or removing elevated permissions until they return.');
        }

        // 5. External / portal user with high-privilege access
        Boolean isExternalUser = u.UserType != null && u.UserType != 'Standard';
        if (isExternalUser && (perms.hasPermission('PermissionsModifyAllData') || perms.hasPermission('PermissionsViewAllData'))) {
            score += EXTERNAL_USER_BONUS;
            reasons.add('External/portal user type (' + u.UserType + ') holds org-wide data access');
            recommendedActions.add('External users should almost never have Modify/View All Data - scope this down to specific objects.');
        }

        // System Administrator profile is always at least Critical regardless of score.
        Boolean isAdminProfile = r.profileName != null && r.profileName.containsIgnoreCase('System Administrator');
        if (isAdminProfile) {
            reasons.add('Assigned the System Administrator profile');
        }

        r.riskScore = score;
        r.dangerousPermissions = dangerousPermissions;
        r.riskReasons = reasons;
        r.recommendedActions = recommendedActions;
        r.editableObjects = perms.getEditableObjects();
        r.isAdminProfile = isAdminProfile;
        r.riskLevel = deriveRiskLevel(score, isAdminProfile);
        return r;
    }

    private static String deriveRiskLevel(Integer score, Boolean isAdminProfile) {
        return isAdminProfile && score > 0 ? 'Critical' : scoreToRiskLevel(score);
    }

    /**
     * Second pass over every scored user, grouped by UserRole: for each sensitive
     * object, if only some members of a role can edit it, that split itself is
     * the signal (either an over-grant on the ones who can, or an inconsistent
     * rollout) - flag the users who have the access their same-role peers lack.
     */
    private static void applyPeerObjectAccessComparison(List<UserRiskResult> userResults) {
        // Admins are expected to hold broad access, so they're excluded from
        // this comparison entirely - both as candidates to flag and as members
        // of the peer group other users get compared against.
        Map<String, List<UserRiskResult>> byRole = new Map<String, List<UserRiskResult>>();
        for (UserRiskResult r : userResults) {
            if (String.isBlank(r.roleName) || r.isAdminProfile) {
                continue;
            }
            if (!byRole.containsKey(r.roleName)) {
                byRole.put(r.roleName, new List<UserRiskResult>());
            }
            byRole.get(r.roleName).add(r);
        }

        for (String roleName : byRole.keySet()) {
            List<UserRiskResult> peers = byRole.get(roleName);
            if (peers.size() < 2) {
                continue;
            }
            for (String objectName : SENSITIVE_OBJECTS) {
                List<UserRiskResult> withEditAccess = new List<UserRiskResult>();
                for (UserRiskResult r : peers) {
                    if (r.editableObjects.contains(objectName)) {
                        withEditAccess.add(r);
                    }
                }
                Boolean isSplitWithinRole = !withEditAccess.isEmpty() && withEditAccess.size() < peers.size();
                if (!isSplitWithinRole) {
                    continue;
                }
                for (UserRiskResult r : withEditAccess) {
                    r.riskScore += OBJECT_ACCESS_MISMATCH_BONUS;
                    r.dangerousPermissions.add('Edit Access: ' + objectName);
                    r.riskReasons.add('Has Edit access to ' + objectName + ' while ' + (peers.size() - withEditAccess.size())
                        + ' of ' + peers.size() + ' peers with the same role (' + roleName + ') do not');
                    r.recommendedActions.add('Confirm ' + objectName + ' edit access is intentional for this user and not a one-off grant relative to their role peers.');
                    r.riskLevel = deriveRiskLevel(r.riskScore, r.isAdminProfile);
                }
            }
        }
    }

    private static Boolean roleLooksLikeManagementTier(String roleName) {
        if (String.isBlank(roleName)) {
            return false;
        }
        String lower = roleName.toLowerCase();
        List<String> managementKeywords = new List<String>{
            'admin', 'manager', 'director', 'vp', 'chief', 'head', 'lead', 'it',
            'executive', 'ceo', 'cfo', 'cto', 'coo', 'president', 'founder', 'owner'
        };
        for (String keyword : managementKeywords) {
            if (lower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private static String scoreToRiskLevel(Integer score) {
        if (score >= THRESHOLD_CRITICAL) {
            return 'Critical';
        }
        if (score >= THRESHOLD_HIGH) {
            return 'High';
        }
        if (score >= THRESHOLD_MEDIUM) {
            return 'Medium';
        }
        return 'Low';
    }

    private static Integer calculateOrgHealthScore(List<UserRiskResult> userResults) {
        if (userResults.isEmpty()) {
            return 0;
        }
        Integer total = 0;
        for (UserRiskResult r : userResults) {
            total += r.riskScore;
        }
        return Math.round((Decimal) total / userResults.size() * 100) / 100;
    }

    private static Integer countAtLevel(List<UserRiskResult> userResults, String level) {
        Integer count = 0;
        for (UserRiskResult r : userResults) {
            if (r.riskLevel == level) {
                count++;
            }
        }
        return count;
    }

    private static String generateBatchId() {
        return String.valueOf(System.now().getTime()) + '-' + EncodingUtil.convertToHex(Crypto.generateAesKey(128)).substring(0, 8);
    }

    private static Permission_Risk_Log__c toLogRecord(UserRiskResult r, String scanBatchId, DateTime scanDate, Integer orgHealthScore) {
        Map<String, Object> detailsPayload = new Map<String, Object>{
            'riskReasons' => r.riskReasons,
            'recommendedActions' => r.recommendedActions,
            'profileName' => r.profileName,
            'roleName' => r.roleName,
            'userType' => r.userType,
            'lastLoginDate' => r.lastLoginDate
        };

        return new Permission_Risk_Log__c(
            User__c = r.userId,
            ScanDate__c = scanDate,
            ScanBatchId__c = scanBatchId,
            RiskScore__c = r.riskScore,
            RiskLevel__c = r.riskLevel,
            DangerousPermissions__c = String.join(r.dangerousPermissions, '|'),
            RecommendedActions__c = String.join(r.recommendedActions, '\n'),
            Details__c = JSON.serialize(detailsPayload),
            OrgHealthScore__c = orgHealthScore
        );
    }

    private static List<User> queryUsers() {
        return [
            SELECT Id, Name, Username, Email, IsActive, LastLoginDate, UserType,
                   ProfileId, Profile.Name, UserRoleId, UserRole.Name
            FROM User
            WHERE UserType != 'AutomatedProcess'
            WITH SECURITY_ENFORCED
            ORDER BY Name
        ];
    }

    private static Map<Id, AggregatedPermissions> aggregatePermissions(List<User> users) {
        Map<Id, AggregatedPermissions> result = new Map<Id, AggregatedPermissions>();
        if (users.isEmpty()) {
            return result;
        }

        Set<Id> userIds = new Map<Id, User>(users).keySet();

        List<PermissionSetAssignment> assignments = [
            SELECT AssigneeId, PermissionSetId,
                   PermissionSet.PermissionsModifyAllData,
                   PermissionSet.PermissionsViewAllData,
                   PermissionSet.PermissionsManageUsers,
                   PermissionSet.PermissionsManageProfilesPermissionsets,
                   PermissionSet.PermissionsManageRoles,
                   PermissionSet.PermissionsManageSharing,
                   PermissionSet.PermissionsResetPasswords,
                   PermissionSet.PermissionsAuthorApex
            FROM PermissionSetAssignment
            WHERE AssigneeId IN :userIds
        ];

        Set<Id> permissionSetIds = new Set<Id>();
        for (PermissionSetAssignment psa : assignments) {
            permissionSetIds.add(psa.PermissionSetId);
        }

        // Map of PermissionSetId -> set of sensitive objects that permission set can edit.
        Map<Id, Set<String>> editableObjectsByPermSet = new Map<Id, Set<String>>();
        if (!permissionSetIds.isEmpty()) {
            for (ObjectPermissions op : [
                SELECT ParentId, SobjectType
                FROM ObjectPermissions
                WHERE ParentId IN :permissionSetIds AND SobjectType IN :SENSITIVE_OBJECTS AND PermissionsEdit = true
            ]) {
                if (!editableObjectsByPermSet.containsKey(op.ParentId)) {
                    editableObjectsByPermSet.put(op.ParentId, new Set<String>());
                }
                editableObjectsByPermSet.get(op.ParentId).add(op.SobjectType);
            }
        }

        for (PermissionSetAssignment psa : assignments) {
            AggregatedPermissions agg = result.get(psa.AssigneeId);
            if (agg == null) {
                agg = new AggregatedPermissions();
                result.put(psa.AssigneeId, agg);
            }
            agg.mergeFromPermissionSet(psa.PermissionSet);
            Set<String> editableForThisPermSet = editableObjectsByPermSet.get(psa.PermissionSetId);
            if (editableForThisPermSet != null) {
                agg.mergeEditableObjects(editableForThisPermSet);
            }
        }

        return result;
    }

    /**
     * Accumulates a boolean OR across every Permission Set (including the
     * hidden profile-owned one) assigned to a user, per dangerous permission.
     */
    public class AggregatedPermissions {
        private Map<String, Boolean> flags = new Map<String, Boolean>();
        private Set<String> editableObjects = new Set<String>();

        public void mergeFromPermissionSet(PermissionSet ps) {
            mergeFlag('PermissionsModifyAllData', ps.PermissionsModifyAllData);
            mergeFlag('PermissionsViewAllData', ps.PermissionsViewAllData);
            mergeFlag('PermissionsManageUsers', ps.PermissionsManageUsers);
            mergeFlag('PermissionsManageProfilesPermissionsets', ps.PermissionsManageProfilesPermissionsets);
            mergeFlag('PermissionsManageRoles', ps.PermissionsManageRoles);
            mergeFlag('PermissionsManageSharing', ps.PermissionsManageSharing);
            mergeFlag('PermissionsResetPasswords', ps.PermissionsResetPasswords);
            mergeFlag('PermissionsAuthorApex', ps.PermissionsAuthorApex);
        }

        private void mergeFlag(String key, Boolean value) {
            Boolean current = flags.containsKey(key) ? flags.get(key) : false;
            flags.put(key, current || (value == true));
        }

        public Boolean hasPermission(String key) {
            return flags.containsKey(key) && flags.get(key) == true;
        }

        public void mergeEditableObjects(Set<String> objectNames) {
            editableObjects.addAll(objectNames);
        }

        public List<String> getEditableObjects() {
            List<String> result = new List<String>(editableObjects);
            result.sort();
            return result;
        }
    }

    /** Per-user scan output used by both the persisted log and the LWC response. */
    public class UserRiskResult implements Comparable {
        @AuraEnabled public Id userId;
        @AuraEnabled public String displayName;
        @AuraEnabled public String username;
        @AuraEnabled public String profileName;
        @AuraEnabled public String roleName;
        @AuraEnabled public Boolean isActive;
        @AuraEnabled public DateTime lastLoginDate;
        @AuraEnabled public String userType;
        @AuraEnabled public Integer riskScore;
        @AuraEnabled public String riskLevel;
        @AuraEnabled public List<String> dangerousPermissions;
        @AuraEnabled public List<String> riskReasons;
        @AuraEnabled public List<String> recommendedActions;
        @AuraEnabled public List<String> editableObjects;
        public Boolean isAdminProfile;

        // Highest risk first
        public Integer compareTo(Object other) {
            UserRiskResult o = (UserRiskResult) other;
            if (this.riskScore == o.riskScore) {
                return 0;
            }
            return this.riskScore > o.riskScore ? -1 : 1;
        }
    }

    /** Full scan output returned to the LWC after "Scan Org" is clicked. */
    public class ScanResult {
        @AuraEnabled public String scanBatchId;
        @AuraEnabled public DateTime scanDate;
        @AuraEnabled public Integer orgHealthScore;
        @AuraEnabled public String orgRiskLevel;
        @AuraEnabled public Integer criticalCount;
        @AuraEnabled public Integer highCount;
        @AuraEnabled public Integer mediumCount;
        @AuraEnabled public Integer lowCount;
        @AuraEnabled public List<UserRiskResult> userResults;
    }
}
