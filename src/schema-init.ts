import {pool} from './db-pool.js';
import {initUsers} from './user-auth.js';
import {initGrcReviews} from './grc-review.js';
import {initGrcCore} from './grc-core.js';
import {initGrcIntake} from './grc-document-intake.js';
import {initOrganizations} from './grc-organizations.js';
import {initControlRegistry} from './grc-controls.js';
import {initBuiltInFrameworkLibrary} from './framework-library.js';
import {initGovernancePerformance} from './governance-performance.js';
import {initThirdPartyRisk} from './third-party-risk.js';
import {initTprmWorkflow} from './tprm-workflow.js';
import {initAutomationOutbox} from './automation-outbox.js';
import {initPrivacyOperations} from './privacy-operations.js';
import {initArchitectureAssurance} from './architecture-assurance.js';
import {initArchitectureModels} from './architecture-model-store.js';
import {initContinuousCompliance} from './continuous-compliance.js';
import {initBusinessContinuity} from './business-continuity.js';
import {initPolicyGovernance} from './policy-governance.js';
import {initKnowledgeSources} from './grc-knowledge-sources.js';
import {initAuditManagement} from './audit-management.js';
import {initEvidenceEngine} from './grc-evidence.js';
import {initIssueRiskCapa} from './grc-remediation.js';
import {initGrcOperations} from './grc-operations.js';
import {initGrcAutomation} from './grc-automation.js';
import {initFindingReview} from './finding-review.js';
import {initFindingRisk} from './finding-risk.js';
import {initFindingPromotion} from './finding-promotion.js';
import {initAssessmentInventory} from './assessment-inventory.js';
import {initBreachAssessment} from './breach-assessment.js';
import {initIncidentResponse} from './incident-response.js';
import {initOperationalSecurity} from './operational-security.js';
import {initSecurityReportHandoffs} from './security-report-handoff.js';
import {initSecurityFindingProposals} from './security-report-findings.js';
import {initScannerJobs} from './scanner-jobs.js';

// Runtime DDL initializers, in dependency order. They run as the schema OWNER only:
// `npm run db:init` (migration role) always runs them; the HTTP server runs them only
// when its own database role owns the schema (legacy single-role deployments). With a
// separate non-owner runtime role, the server performs no DDL at all.
// tests/open-gap-closure.test.ts asserts this list matches the block in src/server.ts.
export const RUNTIME_SCHEMA_INITIALIZERS=['initUsers','initGrcReviews','initGrcCore','initGrcIntake','initOrganizations','initControlRegistry','initBuiltInFrameworkLibrary','initGovernancePerformance','initThirdPartyRisk','initTprmWorkflow','initAutomationOutbox','initPrivacyOperations','initArchitectureAssurance','initArchitectureModels','initContinuousCompliance','initBusinessContinuity','initPolicyGovernance','initKnowledgeSources','initAuditManagement','initEvidenceEngine','initIssueRiskCapa','initGrcOperations','initGrcAutomation','initFindingReview','initFindingRisk','initFindingPromotion','initAssessmentInventory','initBreachAssessment','initIncidentResponse','initOperationalSecurity','initSecurityReportHandoffs','initSecurityFindingProposals','initScannerJobs'] as const;
export async function initRuntimeSchema(){
 await initUsers();
 await initGrcReviews();
 await initGrcCore();
 await initGrcIntake();
 await initOrganizations();
 await initControlRegistry();
 await initBuiltInFrameworkLibrary();
 await initGovernancePerformance();
 await initThirdPartyRisk();
 await initTprmWorkflow();
 await initAutomationOutbox();
 await initPrivacyOperations();
 await initArchitectureAssurance();
 await initArchitectureModels();
 await initContinuousCompliance();
 await initBusinessContinuity();
 await initPolicyGovernance();
 await initKnowledgeSources();
 await initAuditManagement();
 await initEvidenceEngine();
 await initIssueRiskCapa();
 await initGrcOperations();
 await initGrcAutomation();
 await initFindingReview();
 await initFindingRisk();
 await initFindingPromotion();
 await initAssessmentInventory();
 await initBreachAssessment();
 await initIncidentResponse();
 await initOperationalSecurity();
 await initSecurityReportHandoffs();
 await initSecurityFindingProposals();
 await initScannerJobs();
}

/** True when the connected role owns the AegisGRC schema (or the schema does not exist yet). */
export async function runtimeManagesSchema(env:NodeJS.ProcessEnv=process.env){
 if(String(env.AEGIS_SKIP_RUNTIME_DDL||'').toLowerCase()==='true')return false;
 const r=(await pool.query(`SELECT pg_has_role(current_user,c.relowner,'USAGE') AS owns FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='audit_events'`)).rows[0];
 return r?Boolean(r.owns):true;
}

export type DatabaseRolePosture={role:string;superuser:boolean;ownsSchema:boolean;canCreateInSchema:boolean;hardened:boolean};
/** Describes the runtime database role. "hardened" means a non-superuser that owns nothing and cannot create objects. */
export async function databaseRolePosture():Promise<DatabaseRolePosture>{
 const r=(await pool.query(`SELECT current_user AS role,(SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS superuser,
  coalesce((SELECT pg_has_role(current_user,c.relowner,'USAGE') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='audit_events'),false) AS owns,
  has_schema_privilege(current_user,'public','CREATE') AS can_create`)).rows[0];
 const superuser=Boolean(r.superuser),ownsSchema=Boolean(r.owns),canCreateInSchema=Boolean(r.can_create);
 return {role:String(r.role),superuser,ownsSchema,canCreateInSchema,hardened:!superuser&&!ownsSchema&&!canCreateInSchema};
}
