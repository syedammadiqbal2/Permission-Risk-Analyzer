import LightningDatatable from 'lightning/datatable';
import riskBadgeTemplate from './riskBadgeTemplate.html';

export default class PermissionRiskDatatable extends LightningDatatable {
    static customTypes = {
        riskBadge: {
            template: riskBadgeTemplate,
            typeAttributes: ['riskLevel', 'badgeClass']
        }
    };
}
