import { LightningElement, api, wire } from 'lwc';
import { NavigationMixin } from 'lightning/navigation';
import getUserDetail from '@salesforce/apex/PermissionRiskAnalyzerController.getUserDetail';

export default class PermissionRiskUserDetail extends NavigationMixin(LightningElement) {
    _recordId;
    log;
    errorMessage;

    @api
    get recordId() {
        return this._recordId;
    }
    set recordId(value) {
        this._recordId = value;
    }

    @wire(getUserDetail, { logId: '$recordId' })
    wiredDetail({ data, error }) {
        if (data) {
            this.log = data;
            this.errorMessage = undefined;
        } else if (error) {
            this.errorMessage = this.reduceError(error);
        }
    }

    get userName() {
        return this.log && this.log.User__r ? this.log.User__r.Name : '';
    }

    get username() {
        return this.log && this.log.User__r ? this.log.User__r.Username : '';
    }

    get userId() {
        return this.log ? this.log.User__c : undefined;
    }

    get profileName() {
        return this.log && this.log.User__r ? this.log.User__r.Profile.Name : '';
    }

    get roleName() {
        if (!this.log || !this.log.User__r || !this.log.User__r.UserRole) {
            return 'No role assigned';
        }
        return this.log.User__r.UserRole.Name;
    }

    get isActive() {
        return this.log && this.log.User__r ? this.log.User__r.IsActive : false;
    }

    get lastLoginDate() {
        return this.log && this.log.User__r ? this.log.User__r.LastLoginDate : null;
    }

    get riskLevel() {
        return this.log ? this.log.RiskLevel__c : '';
    }

    get riskBadgeClass() {
        const map = {
            Critical: 'risk-badge risk-critical',
            High: 'risk-badge risk-high',
            Medium: 'risk-badge risk-medium',
            Low: 'risk-badge risk-low'
        };
        return this.log ? map[this.log.RiskLevel__c] || 'risk-badge' : 'risk-badge';
    }

    get dangerousPermissions() {
        if (!this.log || !this.log.DangerousPermissions__c) {
            return [];
        }
        return this.log.DangerousPermissions__c.split('|').filter((p) => p);
    }

    get recommendedActions() {
        if (!this.log || !this.log.RecommendedActions__c) {
            return [];
        }
        return this.log.RecommendedActions__c.split('\n').filter((a) => a);
    }

    get hasDangerousPermissions() {
        return this.dangerousPermissions.length > 0;
    }

    get hasRecommendedActions() {
        return this.recommendedActions.length > 0;
    }

    handleClose() {
        this.dispatchEvent(new CustomEvent('close'));
    }

    handleGoToUser() {
        this[NavigationMixin.Navigate]({
            type: 'standard__recordPage',
            attributes: {
                recordId: this.userId,
                objectApiName: 'User',
                actionName: 'view'
            }
        });
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
