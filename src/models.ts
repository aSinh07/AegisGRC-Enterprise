export type Severity='INFO'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL';
export interface Finding {
 id:string; assessmentId:string; source:'nmap'|'wapiti'|'semgrep'|'http'|'zap'|'sqlmap'|'nuclei'|'trivy'|'openvas'|'wazuh'|'prowler'|'gitleaks'|'document';
 title:string; description:string; severity:Severity; cwe?:string; cvss?:number;
 asset:string; evidenceHash:string; createdAt:string;
 mappings:{owasp?:string[];iso27001?:string[];iso42001?:string[];nist?:string[];nistCsf?:string[];nistAiRmf?:string[];cis?:string[];soc2?:string[];pci?:string[];gdpr?:string[];dpdp?:string[];hipaa?:string[]};
 remediation?:string; status?:'OPEN'|'ACCEPTED'|'REMEDIATED'|'FALSE_POSITIVE'; owner?:string;
 confidence?:'OBSERVED'|'SCANNER_REPORTED'|'VALIDATED'|'CONFIRMED'; externalIds?:{cve?:string[];cwe?:string[];scannerId?:string}; fingerprint?:string;
 duplicateOf?:string; occurrence?:number;
}
export interface Assessment {
 id:string; target:string; authorizedAt:string; status:'AUTHORIZED'|'RUNNING'|'COMPLETED'|'PARTIAL'|'FAILED'|'INTERRUPTED';
 findings:Finding[]; evidenceIds:string[];
 scanCoverage?:{required:string[];succeeded:string[];failed:string[];notRun:string[];complete:boolean};
}
export interface Evidence {
 id:string; assessmentId:string; source:string; sha256:string; createdAt:string;
 exitCode?:number|null; stdout?:string; stderr?:string; metadata:Record<string,unknown>;
}
export interface AuditEvent { id:string; assessmentId?:string; action:string; actor:string; createdAt:string; metadata:Record<string,unknown>; }
