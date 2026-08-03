# Permission Risk Analyzer

Lightning app that scans a Salesforce org's users, profiles, and permission
sets to flag over-privileged and inconsistently-provisioned users.

See PROJECT-SPEC reference in the parent AppExchange product folder for full
product spec, pricing, and roadmap.

## What it does

- **Scan Org Now** aggregates each user's effective permissions (profile +
  every assigned permission set) and scores them for risk.
- Flags individually dangerous system permissions (Modify All Data, Manage
  Users, Author Apex, etc.), compound risk (several dangerous permissions
  stacked on one user), role/permission mismatches, inactive users retaining
  access, and external/portal users with org-wide data access.
- **Same-role comparison**: flags a user who has more object-level edit
  access (Account, Contact, Opportunity, Lead, Case) than their same-role
  peers - a common sign of a one-off or leftover grant. System Administrator
  profile users are exempt from this comparison.
- Dashboard supports search (name/email/username) and filtering by role,
  profile, and severity, plus CSV export of whatever's currently filtered.
- Drill-down detail view per user, including a "Go to User" shortcut to the
  standard User record page.
- Results persist to a custom `Permission_Risk_Log__c` object per scan batch,
  so historical scans aren't lost.

## Structure

- `force-app/main/default/classes` - Apex service (scoring engine), controller, and test classes
- `force-app/main/default/lwc` - `permissionRiskDashboard` (main view) and `permissionRiskUserDetail` (drill-down modal)
- `force-app/main/default/objects` - `Permission_Risk_Log__c` custom object (one record per scanned user per scan batch)
- `force-app/main/default/permissionsets`:
  - `Permission_Risk_Analyzer_Admin` - grants access to the app itself (Apex classes, custom object, tab, app) - assign this to anyone who should be able to run scans and view results
  - `PRA_Role_*` (one per role in `roles/`) - example baseline permission sets for a sample org hierarchy, used to demonstrate the same-role comparison feature
  - `PRA_Elevated_Emergency_IT_Access` - example excess-access permission set for demonstrating privilege creep
- `force-app/main/default/roles` - example 8-role hierarchy (Broker/Owner down to individual-contributor roles) used by the sample permission sets above
- `force-app/main/default/flexipages`, `tabs`, `applications` - the app is fully packaged: installing it and assigning `Permission_Risk_Analyzer_Admin` is all that's needed, no manual Setup steps

## Deploying to an org

```
sf org login web -a priskorg
sf project deploy start --source-dir force-app -o priskorg
sf org assign permset -n Permission_Risk_Analyzer_Admin -o priskorg
sf org open -o priskorg
```

Then open the **Permission Risk Analyzer** app from the App Launcher and click
**Scan Org Now**.

## Running Apex tests

```
sf apex run test -o priskorg -n PermissionRiskAnalyzerServiceTest -r human -c
```
