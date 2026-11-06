import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('Defensive UI exposes governed finding decisions and never client-closes findings',async()=>{
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.match(js,/CONFIRMED/);
 assert.match(js,/FALSE_POSITIVE/);
 assert.match(js,/ACCEPTED/);
 assert.match(js,/REMEDIATED/);
 assert.match(js,/Retest evidence ID \(required for REMEDIATED\)/);
 assert.match(js,/Analyst rationale \(10–4000 characters\)/);
 assert.match(js,/Closure is server-gated\. AI cannot mark this finding remediated\./);
 assert.match(js,/\/findings\/'\+id\+'\/review/);
 assert.match(js,/\/findings\/'\+id\+'\/reviews/);
 assert.doesNotMatch(js,/finding\.status\s*=\s*['"]REMEDIATED['"]/);
});

test('Defensive closure controls have responsive presentation rules',async()=>{
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 assert.match(css,/\.defense-closure\{/);
 assert.match(css,/\.defense-closure-grid\{/);
 assert.match(css,/\.defense-history\{/);
 assert.match(css,/@media\(max-width:760px\)\{\.defense-closure-grid\{grid-template-columns:1fr\}/);
});


test('Defensive Wazuh findings expose fingerprint-bound targeted retest workflow',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(js,/Import Wazuh targeted retest/);assert.match(js,/runWazuhDefensiveRetest/);assert.match(js,/\/wazuh-retest/);assert.match(js,/same vulnerability\/detection fingerprint is still present/);assert.match(js,/d\.evidenceId/)});


test('Defensive Prowler findings use same-asset fingerprint-bound imported retest',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');assert.match(js,/Import Prowler targeted retest/);assert.match(js,/runProwlerDefensiveRetest/);assert.match(server,/\/prowler-retest/);assert.match(server,/Prowler retest must use the same cloud asset as the original finding/);assert.match(server,/Completed Prowler retest attestation required/);assert.match(server,/IMPORTED_PROWLER_TARGETED_RETEST/);assert.match(server,/saveFindingRetest/)});


test('Defensive OpenVAS findings expose existing fingerprint-bound infrastructure retest',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(js,/Import OpenVAS targeted retest/);assert.match(js,/runOpenvasDefensiveRetest/);assert.match(js,/\/openvas-retest/);assert.match(js,/same OpenVAS vulnerability fingerprint is still present/);assert.match(js,/ready for governed REMEDIATED review/)});


test('Defensive Trivy findings execute native same-asset fingerprint-bound retest',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');assert.match(js,/Run native Trivy targeted retest/);assert.match(js,/runTrivyDefensiveRetest/);assert.match(server,/\/trivy-retest/);assert.match(server,/Trivy retest must use the same container asset as the original finding/);assert.match(server,/NATIVE_TRIVY_TARGETED_RETEST/);assert.match(server,/remediation state was not advanced/)});


test('native web and network retests distinguish execution success from vulnerability absence',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');assert.match(server,/\['nmap','wapiti','zap','nuclei','sqlmap','http'\]/);assert.match(server,/const stillPresent=Array\.isArray\(rr\.findings\)/);assert.match(server,/stillPresent\?409:200/);assert.match(js,/runNativeDefensiveRetest/);assert.match(js,/same vulnerability fingerprint is still present/);assert.match(js,/ready for governed REMEDIATED review/)});


test('Defensive Semgrep retest is repository-bound and fingerprint-gated',async()=>{const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');assert.match(js,/Run native Semgrep targeted retest/);assert.match(server,/Semgrep retest must use the same repository asset as the original finding/);assert.match(server,/NATIVE_SEMGREP_TARGETED_RETEST/);assert.match(server,/mode:'SEMGREP_TARGETED_RETEST'/);assert.match(js,/rule\/file\/location fingerprint is still present/)});


test('Defensive UI exposes governed secret-safe Gitleaks targeted retest',async()=>{const s=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(s,/defenseGitleaksAsset-/);assert.match(s,/runGitleaksDefensiveRetest/);assert.match(s,/gitleaks-retest/);assert.match(s,/secret-redacted evidence/);assert.match(s,/same secret-detection fingerprint remains/);});


test('Defensive capability catalog is separated from current assessment coverage',async()=>{const s=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');assert.match(s,/Current assessment coverage/);assert.match(s,/\/coverage/);assert.match(s,/No authoritative layer coverage has been recorded/);assert.match(s,/NOT OBSERVED/);});
