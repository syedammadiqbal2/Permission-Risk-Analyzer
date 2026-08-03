# Permission Risk Analyzer

Lightning Web Component utility that scans a Salesforce org's users, profiles,
and permission sets to flag over-privileged users and security risks.

See PROJECT-SPEC reference in the parent AppExchange product folder for full
product spec, pricing, and roadmap.

## Structure

- `force-app/main/default/classes` – Apex service, controller, and test classes
- `force-app/main/default/lwc` – Dashboard and user detail Lightning Web Components
- `force-app/main/default/objects` – Permission_Risk_Log__c custom object
- `force-app/main/default/permissionsets` – Permission_Risk_Analyzer_Admin, grants access to the Apex classes + object

## Deploying to a scratch org / sandbox

```
sf org create scratch -f config/project-scratch-def.json -a priskorg
sf project deploy start -o priskorg
sf org assign permset -n Permission_Risk_Analyzer_Admin -o priskorg
sf org open -o priskorg
```

## Adding the app tab (one-time, manual)

LWC-only tabs can't be authored as source metadata directly - Salesforce
generates the CustomTab XML once you create it through the UI. After deploying:

1. Setup > Tabs > Lightning Component Tabs > New
2. Pick `permissionRiskDashboard` as the component, set a label/icon
3. Retrieve the resulting tab metadata into `force-app/main/default/tabs/`
   (`sf project retrieve start -m CustomTab:Permission_Risk_Analyzer`, adjust
   the API name to whatever you gave it)
4. Add a `<tabSettings>` entry back into
   `Permission_Risk_Analyzer_Admin.permissionset-meta.xml` referencing that tab

Until then, open the component directly via an App Page, Utility Bar, or the
component preview in Setup.

## Running Apex tests

```
sf apex run test -o priskorg -n PermissionRiskAnalyzerServiceTest -r human -c
```
