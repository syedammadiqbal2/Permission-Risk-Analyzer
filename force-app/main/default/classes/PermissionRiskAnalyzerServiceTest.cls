@isTest
private class PermissionRiskAnalyzerServiceTest {

    // Standard "Standard User" profile exists in every org, so this test data
    // setup doesn't depend on anything specific to this package.
    @testSetup
    static void setup() {
        System.runAs(new User(Id = UserInfo.getUserId())) {
            Profile stdProfile = [SELECT Id FROM Profile WHERE Name = 'Standard User' LIMIT 1];

            User overPrivileged = buildTestUser('OverPriv', stdProfile.Id);
            overPrivileged.IsActive = true;
            insert overPrivileged;

            User inactiveWithAccess = buildTestUser('InactiveRisky', stdProfile.Id);
            inactiveWithAccess.IsActive = true; // must be active to receive a PermissionSetAssignment in most orgs
            insert inactiveWithAccess;

            User lowRisk = buildTestUser('LowRisk', stdProfile.Id);
            lowRisk.IsActive = true;
            insert lowRisk;

            // PermissionsModifyAllData and PermissionsViewAllData are deliberately
            // excluded here: enabling either pulls in a large, release-dependent
            // chain of implied permissions (topics, dashboards, reports, event
            // monitoring, etc.) that would make this test setup brittle across
            // orgs/releases. The other dangerous permissions below are enough to
            // drive a Critical/High risk score and compound-risk check.
            PermissionSet riskySet = new PermissionSet(
                Name = 'PRA_Test_Risky_Set',
                Label = 'PRA Test Risky Set',
                PermissionsManageUsers = true,
                PermissionsManageProfilesPermissionsets = true,
                PermissionsManageRoles = true,
                PermissionsManageSharing = true,
                PermissionsResetPasswords = true,
                PermissionsAuthorApex = true,
                PermissionsModifyMetadata = true,
                PermissionsViewRoles = true,
                PermissionsViewSetup = true,
                PermissionsAssignPermissionSets = true,
                PermissionsDelegatedTwoFactor = true,
                PermissionsManageInternalUsers = true,
                PermissionsManageIpAddresses = true,
                PermissionsManageLoginAccessPolicies = true,
                PermissionsManagePasswordPolicies = true,
                PermissionsViewAllUsers = true
            );
            insert riskySet;

            insert new List<PermissionSetAssignment>{
                new PermissionSetAssignment(AssigneeId = overPrivileged.Id, PermissionSetId = riskySet.Id),
                new PermissionSetAssignment(AssigneeId = inactiveWithAccess.Id, PermissionSetId = riskySet.Id)
            };

            // Two users sharing a role, one with an extra Account edit grant the
            // other doesn't have - exercises the same-role object-access
            // comparison in applyPeerObjectAccessComparison. "Standard User"
            // already grants Account/Contact/etc. edit access by default, which
            // would make both peers identical regardless of the extra permission
            // set - so these two specifically use the near-empty baseline
            // profile instead, to isolate the effect of the extra grant.
            Profile minimalProfile = [SELECT Id FROM Profile WHERE Name = 'Minimum Access - Salesforce' LIMIT 1];

            UserRole peerRole = new UserRole(Name = 'PRA_Test_Peer_Role');
            insert peerRole;

            User peerWithEditAccess = buildTestUser('PeerWithEdit', minimalProfile.Id);
            peerWithEditAccess.IsActive = true;
            peerWithEditAccess.UserRoleId = peerRole.Id;
            insert peerWithEditAccess;

            User peerWithoutEditAccess = buildTestUser('PeerNoEdit', minimalProfile.Id);
            peerWithoutEditAccess.IsActive = true;
            peerWithoutEditAccess.UserRoleId = peerRole.Id;
            insert peerWithoutEditAccess;

            PermissionSet accountEditSet = new PermissionSet(
                Name = 'PRA_Test_Account_Edit',
                Label = 'PRA Test Account Edit'
            );
            insert accountEditSet;
            insert new ObjectPermissions(
                ParentId = accountEditSet.Id,
                SobjectType = 'Account',
                PermissionsRead = true,
                PermissionsEdit = true
            );
            insert new PermissionSetAssignment(
                AssigneeId = peerWithEditAccess.Id,
                PermissionSetId = accountEditSet.Id
            );

            // The controller's queries use WITH SECURITY_ENFORCED, so the running
            // user needs the app's own permission set (which grants FLS on the
            // custom fields) rather than relying on admin/Modify All Data to
            // bypass field-level security - it doesn't. Some orgs may already
            // have this assigned to the running admin outside of tests, so
            // check first rather than assume a clean slate.
            PermissionSet appAdminSet = [
                SELECT Id FROM PermissionSet WHERE Name = 'Permission_Risk_Analyzer_Admin' LIMIT 1
            ];
            List<PermissionSetAssignment> existingAssignment = [
                SELECT Id FROM PermissionSetAssignment
                WHERE AssigneeId = :UserInfo.getUserId() AND PermissionSetId = :appAdminSet.Id
            ];
            if (existingAssignment.isEmpty()) {
                insert new PermissionSetAssignment(
                    AssigneeId = UserInfo.getUserId(),
                    PermissionSetId = appAdminSet.Id
                );
            }
        }
    }

    private static User buildTestUser(String lastNameSuffix, Id profileId) {
        String uniqueKey = String.valueOf(Crypto.getRandomInteger()).right(6) + lastNameSuffix;
        return new User(
            FirstName = 'PRA',
            LastName = 'Test' + lastNameSuffix,
            Alias = uniqueKey.left(8),
            Email = 'pra.test.' + uniqueKey + '@example.com',
            Username = 'pra.test.' + uniqueKey + '@' + UserInfo.getOrganizationId() + '.test',
            ProfileId = profileId,
            TimeZoneSidKey = 'America/Los_Angeles',
            LocaleSidKey = 'en_US',
            EmailEncodingKey = 'UTF-8',
            LanguageLocaleKey = 'en_US'
        );
    }

    @isTest
    static void testCalculateUserRisk_flagsMultipleDangerousPermissions() {
        // Direct unit test of the scoring logic using the running test user
        // (always exists, no DML needed) plus an in-memory permission set,
        // so this test exercises pure scoring logic in isolation.
        User currentUser = [
            SELECT Id, Name, Username, IsActive, LastLoginDate, UserType,
                   ProfileId, Profile.Name, UserRoleId, UserRole.Name
            FROM User
            WHERE Id = :UserInfo.getUserId()
        ];

        PermissionRiskAnalyzerService.AggregatedPermissions agg = new PermissionRiskAnalyzerService.AggregatedPermissions();
        agg.mergeFromPermissionSet(new PermissionSet(
            PermissionsModifyAllData = true,
            PermissionsViewAllData = true,
            PermissionsManageUsers = true,
            PermissionsAuthorApex = true
        ));

        Test.startTest();
        // calculateUserRisk is private but @TestVisible, so it can be called
        // directly by name from this @isTest class in the same namespace.
        PermissionRiskAnalyzerService.UserRiskResult result =
            PermissionRiskAnalyzerService.calculateUserRisk(currentUser, agg);
        Test.stopTest();

        System.assertNotEquals(null, result, 'Expected a risk result to be returned');
        System.assert(result.riskScore > 0, 'User with 4 dangerous permissions should have a positive risk score');
        System.assertEquals(4, result.dangerousPermissions.size(), 'Expected exactly 4 dangerous permissions to be flagged');
        System.assert(
            result.riskLevel == 'Critical' || result.riskLevel == 'High',
            'Stacking Modify All Data + View All Data + Manage Users + Author Apex should be at least High risk, was: ' + result.riskLevel
        );
    }

    @isTest
    static void testAggregatedPermissions_mergesAcrossMultiplePermissionSets() {
        PermissionRiskAnalyzerService.AggregatedPermissions agg = new PermissionRiskAnalyzerService.AggregatedPermissions();
        agg.mergeFromPermissionSet(new PermissionSet(PermissionsModifyAllData = true));
        agg.mergeFromPermissionSet(new PermissionSet(PermissionsManageUsers = true));

        System.assert(agg.hasPermission('PermissionsModifyAllData'), 'Modify All Data should be true after first merge');
        System.assert(agg.hasPermission('PermissionsManageUsers'), 'Manage Users should be true after second merge');
        System.assert(!agg.hasPermission('PermissionsViewAllData'), 'View All Data was never granted and should remain false');
    }

    @isTest
    static void testScanOrg_persistsLogsAndComputesOrgHealthScore() {
        Test.startTest();
        PermissionRiskAnalyzerService.ScanResult result = PermissionRiskAnalyzerService.scanOrg();
        Test.stopTest();

        System.assertNotEquals(null, result.scanBatchId, 'Scan should generate a batch id');
        System.assert(result.userResults != null && !result.userResults.isEmpty(), 'Scan should return at least one user result');

        List<Permission_Risk_Log__c> logs = [
            SELECT Id, RiskScore__c, RiskLevel__c, ScanBatchId__c
            FROM Permission_Risk_Log__c
            WHERE ScanBatchId__c = :result.scanBatchId
        ];
        System.assertEquals(result.userResults.size(), logs.size(), 'One log record should be created per scanned user');

        Boolean foundHighRiskUser = false;
        for (Permission_Risk_Log__c log : logs) {
            if (log.RiskLevel__c == 'Critical' || log.RiskLevel__c == 'High') {
                foundHighRiskUser = true;
                break;
            }
        }
        System.assert(foundHighRiskUser, 'Expected at least one Critical/High risk user from test setup data');
    }

    @isTest
    static void testScanOrg_flagsUserWithMoreObjectAccessThanSameRolePeer() {
        Test.startTest();
        PermissionRiskAnalyzerService.ScanResult result = PermissionRiskAnalyzerService.scanOrg();
        Test.stopTest();

        Map<Id, PermissionRiskAnalyzerService.UserRiskResult> byUserId =
            new Map<Id, PermissionRiskAnalyzerService.UserRiskResult>();
        for (PermissionRiskAnalyzerService.UserRiskResult r : result.userResults) {
            byUserId.put(r.userId, r);
        }

        // Identify the two peer users by their actual role/permission-set
        // assignment rather than a LastName LIKE match - a loose wildcard
        // match risks picking up unrelated same-named users elsewhere in the
        // org and produces flaky, non-deterministic results.
        UserRole peerRole = [SELECT Id FROM UserRole WHERE Name = 'PRA_Test_Peer_Role' LIMIT 1];
        List<User> peerUsers = [SELECT Id FROM User WHERE UserRoleId = :peerRole.Id];
        System.assertEquals(2, peerUsers.size(), 'Expected exactly the two peer test users under this role');

        PermissionSet accountEditSet = [SELECT Id FROM PermissionSet WHERE Name = 'PRA_Test_Account_Edit' LIMIT 1];
        Set<Id> assigneeIdsWithEdit = new Set<Id>();
        for (PermissionSetAssignment psa : [SELECT AssigneeId FROM PermissionSetAssignment WHERE PermissionSetId = :accountEditSet.Id]) {
            assigneeIdsWithEdit.add(psa.AssigneeId);
        }

        Id withEditId;
        Id withoutEditId;
        for (User u : peerUsers) {
            if (assigneeIdsWithEdit.contains(u.Id)) {
                withEditId = u.Id;
            } else {
                withoutEditId = u.Id;
            }
        }

        PermissionRiskAnalyzerService.UserRiskResult withEditResult = byUserId.get(withEditId);
        PermissionRiskAnalyzerService.UserRiskResult withoutEditResult = byUserId.get(withoutEditId);

        System.assertNotEquals(null, withEditResult, 'Expected a scan result for the peer with Account edit access');
        System.assertNotEquals(null, withoutEditResult, 'Expected a scan result for the peer without Account edit access');

        System.assert(
            withEditResult.dangerousPermissions.contains('Edit Access: Account'),
            'User with Account edit access should be flagged for it relative to their same-role peer'
        );
        System.assert(
            !withoutEditResult.dangerousPermissions.contains('Edit Access: Account'),
            'User without Account edit access should not be flagged - they are the baseline, not the outlier'
        );
        System.assert(
            withEditResult.riskScore > withoutEditResult.riskScore,
            'The peer with more access than their same-role counterpart should score higher'
        );
    }

    @isTest
    static void testController_runScanAndFetchLatestResults() {
        // The controller's WITH SECURITY_ENFORCED queries need this test's
        // running user to see the permission set assigned in @testSetup, and
        // Apex only refreshes a user's cached FLS/permissions on a context
        // switch - so this must run inside System.runAs even though it's the
        // same user id, or the assignment from @testSetup won't be visible yet.
        PermissionRiskAnalyzerService.ScanResult scanResult;
        List<Permission_Risk_Log__c> latest;
        Permission_Risk_Log__c detail;

        System.runAs(new User(Id = UserInfo.getUserId())) {
            Test.startTest();
            scanResult = PermissionRiskAnalyzerController.runScan();
            latest = PermissionRiskAnalyzerController.getLatestScanResults();
            Test.stopTest();

            detail = PermissionRiskAnalyzerController.getUserDetail(latest[0].Id);
        }

        System.assertNotEquals(null, scanResult, 'Controller should return a scan result');
        System.assert(!latest.isEmpty(), 'getLatestScanResults should return the records from the scan just run');
        System.assertNotEquals(null, detail, 'getUserDetail should return the requested log record');
        System.assertEquals(latest[0].Id, detail.Id);
    }

    @isTest
    static void testController_getUserDetail_returnsNullForMissingId() {
        // Fabricate a syntactically valid but non-existent Id for the custom object.
        Id fakeId = Permission_Risk_Log__c.SObjectType.getDescribe().getKeyPrefix() + '000000000000AAA';

        Permission_Risk_Log__c detail;
        System.runAs(new User(Id = UserInfo.getUserId())) {
            Test.startTest();
            detail = PermissionRiskAnalyzerController.getUserDetail(fakeId);
            Test.stopTest();
        }

        System.assertEquals(null, detail, 'Unknown log id should return null rather than throwing');
    }
}
