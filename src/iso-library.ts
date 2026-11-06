import crypto from 'node:crypto';
import {pool} from './db-pool.js';

// ISO base library (target architecture, Phase 2).
//
// ISO/IEC 27001:2022 Annex A is the base: all 93 controls in four themes, each mapped onto the
// platform's canonical controls so evidence collected once satisfies every mapped framework.
// ISO/IEC 42001:2023 Annex A objectives and ISO/IEC 27701 controller/processor categories are
// mapped onto the same canonical controls.
//
// Copyright: ISO control TEXT is not stored. Only identifiers, short titles and AegisGRC's own
// implementation guidance (written for this platform, in the spirit of ISO/IEC 27002) are kept.
// Organizations need a licensed copy of the standards for the normative wording.

type Entry=[key:string,title:string,controls:string[],guidance:string];
const SRC27001='https://www.iso.org/standard/27001',SRC42001='https://www.iso.org/standard/81230.html',SRC27701='https://www.iso.org/standard/71670.html';

export const EXTRA_CANONICAL_CONTROLS=[
 {key:'PHY-01',title:'Physical and environmental security',domain:'PHYSICAL',description:'Protect premises, equipment, media and supporting utilities against unauthorized access and environmental threats.'},
 {key:'NET-01',title:'Network security and segregation',domain:'SECURITY',description:'Secure, segregate and monitor networks and network services, including filtering of outbound web access.'}
];

export const ISO27001_ANNEX_A:Entry[]=[
 // A.5 Organizational controls (37)
 ['A.5.1','Policies for information security',['POL-01','GOV-01'],'Approve a top-level policy and topic policies, publish them to staff and review them on a set cycle or after major change.'],
 ['A.5.2','Information security roles and responsibilities',['GOV-01'],'Assign named owners for security activities and assets; record them in the RACI and keep them current.'],
 ['A.5.3','Segregation of duties',['IAM-01','GOV-01'],'Split conflicting duties (request/approve, build/deploy, create/close) and enforce the split in tooling.'],
 ['A.5.4','Management responsibilities',['GOV-01','PEO-01'],'Managers require staff and contractors to follow policy and confirm it through attestations and reviews.'],
 ['A.5.5','Contact with authorities',['IR-01'],'Keep a current list of regulators, law enforcement and CERT contacts and when each must be notified.'],
 ['A.5.6','Contact with special interest groups',['GOV-01'],'Join relevant security forums and ISACs and record what intelligence or guidance is consumed from them.'],
 ['A.5.7','Threat intelligence',['LOG-01','VUL-01'],'Collect threat information relevant to your stack, analyse it and feed it into detection and patch priorities.'],
 ['A.5.8','Information security in project management',['GOV-01','APP-01'],'Add a security risk review and acceptance criteria to every project gate.'],
 ['A.5.9','Inventory of information and other associated assets',['AST-01'],'Maintain an owned inventory of systems, data stores and applications, linked to risks and controls.'],
 ['A.5.10','Acceptable use of information and other associated assets',['POL-01','PEO-01'],'Publish acceptable-use rules and collect acknowledgement from everyone with access.'],
 ['A.5.11','Return of assets',['AST-01','PEO-01'],'Recover equipment, data and credentials at exit or role change, with a checklist as evidence.'],
 ['A.5.12','Classification of information',['DAT-01'],'Define a classification scheme and classify data stores by confidentiality, integrity and availability needs.'],
 ['A.5.13','Labelling of information',['DAT-01'],'Label documents and data sets according to the classification scheme, automatically where possible.'],
 ['A.5.14','Information transfer',['DAT-01','CRY-01'],'Set rules and agreements for transferring information internally and with third parties, with encryption.'],
 ['A.5.15','Access control',['IAM-01'],'Define access rules from business and security requirements; default deny and least privilege.'],
 ['A.5.16','Identity management',['IAM-01'],'Manage the full identity lifecycle: unique identities, joiner-mover-leaver and removal of unused accounts.'],
 ['A.5.17','Authentication information',['IAM-01','CRY-01'],'Control issuance and protection of passwords, keys and MFA secrets; never share or store them in plaintext.'],
 ['A.5.18','Access rights',['IAM-01'],'Grant, review and revoke access rights through an approved process with periodic access reviews.'],
 ['A.5.19','Information security in supplier relationships',['TPRM-01'],'Assess suppliers by risk tier before onboarding and set security expectations for each tier.'],
 ['A.5.20','Addressing information security within supplier agreements',['TPRM-01'],'Put security, audit and incident-notification clauses into supplier contracts.'],
 ['A.5.21','Managing information security in the ICT supply chain',['TPRM-01','VUL-01'],'Track software and service dependencies (SBOM) and the security posture of upstream providers.'],
 ['A.5.22','Monitoring, review and change management of supplier services',['TPRM-01'],'Review supplier performance and security at the scheduled review date and on material change.'],
 ['A.5.23','Information security for use of cloud services',['TPRM-01','CFG-01'],'Define how cloud services are selected, configured, monitored and exited, including shared responsibilities.'],
 ['A.5.24','Information security incident management planning and preparation',['IR-01'],'Maintain an incident plan with roles, severity levels, playbooks and contact lists; rehearse it.'],
 ['A.5.25','Assessment and decision on information security events',['IR-01','LOG-01'],'Triage security events against criteria to decide whether they are incidents.'],
 ['A.5.26','Response to information security incidents',['IR-01'],'Contain, eradicate and recover according to playbooks; keep a timeline of actions.'],
 ['A.5.27','Learning from information security incidents',['IR-01','CAPA-01'],'Run post-incident reviews and track the resulting corrective actions to closure.'],
 ['A.5.28','Collection of evidence',['EVD-01','IR-01'],'Collect and preserve evidence with integrity protection and chain of custody (hashing, append-only storage).'],
 ['A.5.29','Information security during disruption',['BCM-01'],'Keep security controls working during disruption and define the minimum acceptable level.'],
 ['A.5.30','ICT readiness for business continuity',['BCM-01'],'Set recovery objectives for ICT services and prove them with tested restores and failover exercises.'],
 ['A.5.31','Legal, statutory, regulatory and contractual requirements',['GOV-01','PRI-01'],'Keep a register of applicable legal and contractual obligations with owners and review dates.'],
 ['A.5.32','Intellectual property rights',['GOV-01'],'Track software licences and use of third-party content to stay within licence terms.'],
 ['A.5.33','Protection of records',['EVD-01','DAT-01'],'Protect records against loss, falsification and unauthorized deletion for their retention period.'],
 ['A.5.34','Privacy and protection of PII',['PRI-01','DAT-01'],'Identify PII processing, its lawful basis and safeguards, and meet privacy obligations.'],
 ['A.5.35','Independent review of information security',['AUD-01'],'Have the ISMS reviewed independently at planned intervals and on significant change.'],
 ['A.5.36','Compliance with policies, rules and standards for information security',['AUD-01','GOV-01'],'Check compliance with policies regularly and act on non-conformities.'],
 ['A.5.37','Documented operating procedures',['GOV-01','POL-01'],'Document operating procedures for security-relevant activities and keep them available to those who need them.'],
 // A.6 People controls (8)
 ['A.6.1','Screening',['PEO-01'],'Run background checks proportional to role, data access and legal limits before access is granted.'],
 ['A.6.2','Terms and conditions of employment',['PEO-01'],'State security responsibilities in employment and contractor terms.'],
 ['A.6.3','Information security awareness, education and training',['PEO-01'],'Deliver role-based security training and track completion.'],
 ['A.6.4','Disciplinary process',['PEO-01'],'Have a known, fair disciplinary process for policy violations.'],
 ['A.6.5','Responsibilities after termination or change of employment',['PEO-01','IAM-01'],'Define security duties that survive exit or role change and remove access promptly.'],
 ['A.6.6','Confidentiality or non-disclosure agreements',['PEO-01'],'Use NDAs that reflect the information handled, signed before access and reviewed periodically.'],
 ['A.6.7','Remote working',['PEO-01','CFG-01'],'Set security requirements for remote work: managed devices, VPN or zero-trust access, home-office rules.'],
 ['A.6.8','Information security event reporting',['IR-01','PEO-01'],'Give staff a simple channel to report suspected events and acknowledge every report.'],
 // A.7 Physical controls (14)
 ['A.7.1','Physical security perimeters',['PHY-01'],'Define and protect the perimeters of areas that hold information and processing facilities.'],
 ['A.7.2','Physical entry',['PHY-01'],'Control entry to secure areas and keep an access log.'],
 ['A.7.3','Securing offices, rooms and facilities',['PHY-01'],'Apply physical security appropriate to the sensitivity of each room or facility.'],
 ['A.7.4','Physical security monitoring',['PHY-01'],'Monitor premises for unauthorized access (alarms, CCTV) and review alerts.'],
 ['A.7.5','Protecting against physical and environmental threats',['PHY-01','BCM-01'],'Protect against fire, flood, power and climate threats proportionate to the risk.'],
 ['A.7.6','Working in secure areas',['PHY-01'],'Set rules for working in secure areas, including supervision of visitors.'],
 ['A.7.7','Clear desk and clear screen',['PHY-01','PEO-01'],'Enforce clear-desk and screen-lock rules for papers, media and unattended devices.'],
 ['A.7.8','Equipment siting and protection',['PHY-01'],'Site and protect equipment (for example the local server) against environmental and unauthorized access risks.'],
 ['A.7.9','Security of assets off-premises',['PHY-01','AST-01'],'Protect devices and media used outside the premises: encryption, tracking and loss reporting.'],
 ['A.7.10','Storage media',['PHY-01','DAT-01'],'Manage removable media through its lifecycle: approval, encryption, transport and disposal.'],
 ['A.7.11','Supporting utilities',['PHY-01','BCM-01'],'Protect against power and utility failure (for example UPS) and test the protection.'],
 ['A.7.12','Cabling security',['PHY-01'],'Protect power and network cabling from interception, interference and damage.'],
 ['A.7.13','Equipment maintenance',['PHY-01','AST-01'],'Maintain equipment on schedule and control who performs maintenance.'],
 ['A.7.14','Secure disposal or re-use of equipment',['PHY-01','DAT-01'],'Wipe or destroy storage before disposal or re-use and keep a certificate of destruction.'],
 // A.8 Technological controls (34)
 ['A.8.1','User endpoint devices',['CFG-01'],'Harden, encrypt and centrally manage endpoints; define rules for personal devices.'],
 ['A.8.2','Privileged access rights',['IAM-01'],'Restrict, approve and monitor privileged access; review it more often than normal access.'],
 ['A.8.3','Information access restriction',['IAM-01','DAT-01'],'Enforce access to information according to the access control policy, including tenant isolation.'],
 ['A.8.4','Access to source code',['IAM-01','APP-01'],'Limit write access to source code and protect the main branches with reviews.'],
 ['A.8.5','Secure authentication',['IAM-01'],'Use strong authentication (MFA, SSO) proportionate to the sensitivity of the system.'],
 ['A.8.6','Capacity management',['BCM-01','LOG-01'],'Monitor capacity and plan ahead so services stay available.'],
 ['A.8.7','Protection against malware',['CFG-01','LOG-01'],'Prevent, detect and recover from malware with tools and user awareness.'],
 ['A.8.8','Management of technical vulnerabilities',['VUL-01'],'Scan authorized targets, triage findings, remediate within SLA and prove the fix with a retest.'],
 ['A.8.9','Configuration management',['CFG-01'],'Define secure baselines, apply them consistently and detect drift.'],
 ['A.8.10','Information deletion',['DAT-01','PRI-01'],'Delete information when no longer needed, with evidence of deletion.'],
 ['A.8.11','Data masking',['DAT-01','PRI-01'],'Mask or pseudonymize sensitive data where full values are not needed.'],
 ['A.8.12','Data leakage prevention',['DAT-01','LOG-01'],'Detect and prevent unauthorized disclosure of sensitive data across endpoints, email and cloud.'],
 ['A.8.13','Information backup',['BCM-01','CRY-01'],'Back up per policy, encrypt backups, keep them off-site and test restores regularly.'],
 ['A.8.14','Redundancy of information processing facilities',['BCM-01'],'Provide redundancy that meets availability requirements and test failover.'],
 ['A.8.15','Logging',['LOG-01','EVD-01'],'Produce, protect and retain logs of security-relevant activity; make them tamper-evident.'],
 ['A.8.16','Monitoring activities',['LOG-01'],'Monitor networks, systems and applications for anomalous behaviour and act on alerts.'],
 ['A.8.17','Clock synchronization',['LOG-01'],'Synchronize clocks to an approved time source so evidence and logs line up.'],
 ['A.8.18','Use of privileged utility programs',['IAM-01','CFG-01'],'Restrict and log use of utilities that can override system or application controls.'],
 ['A.8.19','Installation of software on operational systems',['CFG-01'],'Control software installation on production through approved, pinned packages.'],
 ['A.8.20','Networks security',['NET-01'],'Secure and manage networks: firewalls, no unnecessary inbound exposure, monitored egress.'],
 ['A.8.21','Security of network services',['NET-01','TPRM-01'],'Define and monitor security requirements for network services, including edge and tunnel providers.'],
 ['A.8.22','Segregation of networks',['NET-01'],'Separate networks by trust level (for example scanners, application and database).'],
 ['A.8.23','Web filtering',['NET-01'],'Filter access to external websites to reduce exposure to malicious content.'],
 ['A.8.24','Use of cryptography',['CRY-01'],'Define where and how cryptography and key management are used, including signing keys.'],
 ['A.8.25','Secure development life cycle',['APP-01'],'Build security into each development stage: requirements, design, code review, testing and release.'],
 ['A.8.26','Application security requirements',['APP-01'],'Identify and approve security requirements when developing or acquiring applications.'],
 ['A.8.27','Secure system architecture and engineering principles',['APP-01','CFG-01'],'Apply documented secure-architecture principles such as least privilege, zero trust and defence in depth.'],
 ['A.8.28','Secure coding',['APP-01','VUL-01'],'Apply secure coding standards and automated checks (SAST, secrets and dependency scanning).'],
 ['A.8.29','Security testing in development and acceptance',['APP-01','VUL-01'],'Test security before release (DAST, retests) and block release on unresolved critical findings.'],
 ['A.8.30','Outsourced development',['APP-01','TPRM-01'],'Direct, monitor and review outsourced development against your security requirements.'],
 ['A.8.31','Separation of development, test and production environments',['CFG-01','APP-01'],'Keep development, test and production separate with controlled promotion between them.'],
 ['A.8.32','Change management',['CFG-01','GOV-01'],'Approve, test and record changes to systems, with rollback plans.'],
 ['A.8.33','Test information',['DAT-01','APP-01'],'Select and protect test data; do not use production PII in tests without safeguards.'],
 ['A.8.34','Protection of information systems during audit testing',['AUD-01','VUL-01'],'Plan and authorize audit and penetration tests so they do not disrupt operations (scope, approval, timing).']
];

export const ISO42001_ANNEX_A:Entry[]=[
 ['A.2','Policies related to AI',['AI-01','POL-01'],'Approve an AI policy aligned with business objectives and other policies, and review it.'],
 ['A.3','Internal organization',['AI-01','GOV-01'],'Assign roles, responsibilities and reporting lines for AI systems, including concern reporting.'],
 ['A.4','Resources for AI systems',['AI-01','AST-01'],'Document data, tooling, compute and human resources used by each AI system.'],
 ['A.5','Assessing impacts of AI systems',['AI-02','RSK-01'],'Run AI impact assessments on individuals, groups and society, and record the results.'],
 ['A.6','AI system life cycle',['AI-01','APP-01'],'Govern AI systems from design to retirement: requirements, verification, deployment, monitoring.'],
 ['A.7','Data for AI systems',['AI-01','DAT-01'],'Manage data quality, provenance and preparation for AI development and operation.'],
 ['A.8','Information for interested parties of AI systems',['AI-02','GOV-01'],'Give users and affected parties the documentation and channels they need, including incident communication.'],
 ['A.9','Use of AI systems',['AI-01','POL-01'],'Define and monitor responsible use of AI systems within their intended purpose.'],
 ['A.10','Third-party and customer relationships',['AI-01','TPRM-01'],'Allocate AI responsibilities between the organization, suppliers and customers.']
];

export const ISO27701_CATEGORIES:Entry[]=[
 ['7.2','Controller: conditions for collection and processing',['PRI-01','DAT-01'],'Identify purposes and lawful basis, obtain and record consent where needed, and assess privacy impact.'],
 ['7.3','Controller: obligations to PII principals',['PRI-01'],'Inform PII principals and handle access, correction, erasure and objection requests on time.'],
 ['7.4','Controller: privacy by design and privacy by default',['PRI-01','DAT-01'],'Minimize collection and processing, limit retention and de-identify or delete when done.'],
 ['7.5','Controller: PII sharing, transfer and disclosure',['PRI-01','TPRM-01'],'Record disclosures and cross-border transfers and the safeguards that apply.'],
 ['8.2','Processor: conditions for collection and processing',['PRI-01','TPRM-01'],'Process PII only on documented customer instructions and support their obligations.'],
 ['8.3','Processor: obligations to PII principals',['PRI-01'],'Help customers respond to PII principal requests.'],
 ['8.4','Processor: privacy by design and privacy by default',['PRI-01','DAT-01'],'Return or delete PII at contract end and control temporary files.'],
 ['8.5','Processor: PII sharing, transfer and disclosure',['PRI-01','TPRM-01'],'Disclose sub-processors and transfers to customers and obtain approval where required.']
];

const uid=(key:string)=>{const h=crypto.createHash('sha256').update('aegis-framework-library:'+key).digest('hex').slice(0,32).split('');h[12]='4';h[16]=((parseInt(h[16],16)&3)|8).toString(16);return h.slice(0,8).join('')+'-'+h.slice(8,12).join('')+'-'+h.slice(12,16).join('')+'-'+h.slice(16,20).join('')+'-'+h.slice(20).join('')};

export async function initIsoLibrary(){
 const c=await pool.connect();
 try{
  await c.query('BEGIN');
  for(const x of EXTRA_CANONICAL_CONTROLS)await c.query(`INSERT INTO grc_canonical_controls(id,control_key,title,description,domain,version,active) VALUES($1,$2,$3,$4,$5,1,true)
   ON CONFLICT(control_key) DO UPDATE SET title=EXCLUDED.title,description=EXCLUDED.description,domain=EXCLUDED.domain,active=true,updated_at=now()`,[uid('control:'+x.key),x.key,x.title,x.description,x.domain]);
  const sets:[string,string,string,Entry[]][]=[['ISO27001','2022',SRC27001,ISO27001_ANNEX_A],['ISO42001','2023',SRC42001,ISO42001_ANNEX_A],['ISO27701','2019',SRC27701,ISO27701_CATEGORIES]];
  for(const [fw,ver,src,entries] of sets)for(const [key,title,controls,guidance] of entries){
   const rid=uid('requirement:'+fw+':'+ver+':'+key);
   await c.query(`INSERT INTO grc_framework_requirements(id,framework,framework_version,requirement_key,title,summary,source_url,active) VALUES($1,$2,$3,$4,$5,$6,$7,true)
    ON CONFLICT(framework,framework_version,requirement_key) DO UPDATE SET title=EXCLUDED.title,summary=EXCLUDED.summary,source_url=EXCLUDED.source_url,active=true`,[rid,fw,ver,key,title,guidance,src]);
   const actual=(await c.query('SELECT id FROM grc_framework_requirements WHERE framework=$1 AND framework_version=$2 AND requirement_key=$3',[fw,ver,key])).rows[0].id;
   for(const ck of controls){const cid=(await c.query('SELECT id FROM grc_canonical_controls WHERE control_key=$1',[ck])).rows[0]?.id;if(!cid)throw new Error('Unknown canonical control '+ck+' for '+fw+' '+key);
    await c.query(`INSERT INTO grc_control_framework_mappings(control_id,requirement_id,mapping_type,mapping_version) VALUES($1,$2,'SUPPORTS',1) ON CONFLICT(control_id,requirement_id,mapping_version) DO NOTHING`,[cid,actual])}
  }
  await c.query('COMMIT');
 }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}
