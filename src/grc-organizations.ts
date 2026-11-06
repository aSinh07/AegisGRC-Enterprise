import {pool} from './db-pool.js';
import crypto from 'node:crypto';
import pg from 'pg';



export type OrgRole='ORG_ADMIN'|'GRC_MANAGER'|'GRC_CONSULTANT'|'GRC_ANALYST'|'SECURITY_ANALYST'|'DEVELOPER'|'CONTROL_OWNER'|'RISK_OWNER'|'REVIEWER'|'AUDITOR'|'VIEWER';
const roles:OrgRole[]=['ORG_ADMIN','GRC_MANAGER','GRC_CONSULTANT','GRC_ANALYST','SECURITY_ANALYST','DEVELOPER','CONTROL_OWNER','RISK_OWNER','REVIEWER','AUDITOR','VIEWER'];
const permissions={
 read:new Set<OrgRole>(roles),
 manageOrg:new Set<OrgRole>(['ORG_ADMIN']),
 manageScope:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST']),
 manageControl:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','CONTROL_OWNER']),
 manageRisk:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','RISK_OWNER']),
 // SECURITY_ANALYST runs authorized scans and triages findings without GRC administration rights.
 manageAssessment:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','SECURITY_ANALYST']),
 initiateAudit:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','AUDITOR']),
 findingReview:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','SECURITY_ANALYST','REVIEWER']),
 // Retest collects fresh evidence for an existing finding. DEVELOPER can prove a fix this way but
 // cannot close the finding (findingReview), start new assessments or change GRC records.
 retest:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','SECURITY_ANALYST','DEVELOPER']),
 // Approving a verified scan target is separate from requesting it (see target-authorization.ts).
 approveTarget:new Set<OrgRole>(['ORG_ADMIN','GRC_MANAGER']),
 review:new Set<OrgRole>(['GRC_MANAGER','GRC_CONSULTANT','REVIEWER','AUDITOR'])
};
export type OrgPermission=keyof typeof permissions;
export function roleAllows(role:OrgRole,permission:OrgPermission){return permissions[permission].has(role)}

export async function initOrganizations(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS grc_organizations(
   id uuid PRIMARY KEY,name text NOT NULL,industry text,status text NOT NULL DEFAULT 'ACTIVE',
   created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
   created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
 );
 ALTER TABLE grc_organizations ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'ACTIVE';
 ALTER TABLE grc_organizations ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES app_users(id) ON DELETE SET NULL;
 ALTER TABLE grc_organizations ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
 CREATE TABLE IF NOT EXISTS grc_organization_members(
   organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
   user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
   role text NOT NULL CHECK(role IN ('ORG_ADMIN','GRC_MANAGER','GRC_CONSULTANT','GRC_ANALYST','SECURITY_ANALYST','DEVELOPER','CONTROL_OWNER','RISK_OWNER','REVIEWER','AUDITOR','VIEWER')),
   status text NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','SUSPENDED')),
   created_at timestamptz NOT NULL DEFAULT now(),
   PRIMARY KEY(organization_id,user_id)
 );
 ALTER TABLE grc_organization_members DROP CONSTRAINT IF EXISTS grc_organization_members_role_check;
 ALTER TABLE grc_organization_members ADD CONSTRAINT grc_organization_members_role_check CHECK(role IN ('ORG_ADMIN','GRC_MANAGER','GRC_CONSULTANT','GRC_ANALYST','SECURITY_ANALYST','DEVELOPER','CONTROL_OWNER','RISK_OWNER','REVIEWER','AUDITOR','VIEWER'));
 CREATE INDEX IF NOT EXISTS grc_org_members_user_idx ON grc_organization_members(user_id,status);
 CREATE TABLE IF NOT EXISTS grc_scopes(
   id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
   name text NOT NULL,description text,status text NOT NULL DEFAULT 'DRAFT',
   created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
   created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
   UNIQUE(organization_id,name)
 );
 ALTER TABLE grc_scopes ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES app_users(id) ON DELETE SET NULL;
 ALTER TABLE grc_scopes ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
 `);
}

export async function createOrganization(userId:string,input:{name:string;industry?:string}){
 const name=String(input.name||'').trim();
 if(name.length<2||name.length>160)throw new Error('Organization name must be 2-160 characters');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const id=crypto.randomUUID();
  const org=(await client.query(`INSERT INTO grc_organizations(id,name,industry,created_by) VALUES($1,$2,$3,$4) RETURNING *`,
    [id,name,String(input.industry||'').trim()||null,userId])).rows[0];
  await client.query(`INSERT INTO grc_organization_members(organization_id,user_id,role) VALUES($1,$2,'ORG_ADMIN')`,[id,userId]);
  await client.query('COMMIT');
  return org;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function memberships(userId:string){
 return (await pool.query(`SELECT o.id,o.name,o.industry,m.role,m.status
 FROM grc_organization_members m JOIN grc_organizations o ON o.id=m.organization_id
 WHERE m.user_id=$1 AND m.status='ACTIVE' AND o.status='ACTIVE' ORDER BY o.name`,[userId])).rows;
}
export async function membership(userId:string,organizationId:string){
 return (await pool.query(`SELECT m.organization_id,m.user_id,m.role,m.status,o.name
 FROM grc_organization_members m JOIN grc_organizations o ON o.id=m.organization_id
 WHERE m.user_id=$1 AND m.organization_id=$2 AND m.status='ACTIVE' AND o.status='ACTIVE'`,[userId,organizationId])).rows[0]||null;
}
export async function requireOrgPermission(userId:string,organizationId:string,permission:OrgPermission){
 const m=await membership(userId,organizationId);
 if(!m)throw Object.assign(new Error('Organization membership required'),{statusCode:403});
 if(!roleAllows(m.role as OrgRole,permission))throw Object.assign(new Error('Insufficient organization role'),{statusCode:403});
 return m;
}
export async function createScope(userId:string,organizationId:string,input:{name:string;description?:string}){
 await requireOrgPermission(userId,organizationId,'manageScope');
 const name=String(input.name||'').trim();if(name.length<2||name.length>160)throw new Error('Scope name must be 2-160 characters');
 const id=crypto.randomUUID();
 return (await pool.query(`INSERT INTO grc_scopes(id,organization_id,name,description,created_by)
 VALUES($1,$2,$3,$4,$5) RETURNING *`,[id,organizationId,name,String(input.description||'').trim()||null,userId])).rows[0];
}
export async function listScopes(userId:string,organizationId:string){
 await requireOrgPermission(userId,organizationId,'read');
 return (await pool.query(`SELECT id,organization_id,name,description,status,created_at,updated_at FROM grc_scopes
 WHERE organization_id=$1 ORDER BY created_at DESC`,[organizationId])).rows;
}
export async function addMemberByEmail(actorId:string,organizationId:string,email:string,role:OrgRole){
 await requireOrgPermission(actorId,organizationId,'manageOrg');
 email=String(email||'').trim().toLowerCase();
 if(!email)throw new Error('Member email is required');
 if(!roles.includes(role))throw new Error('Invalid organization role');
 const user=(await pool.query('SELECT id,totp_verified FROM app_users WHERE lower(email)=lower($1)',[email])).rows[0];
 if(!user||!user.totp_verified)throw Object.assign(new Error('Registered and MFA-verified AegisGRC user not found for this email'),{statusCode:404});
 return addMember(actorId,organizationId,user.id,role);
}

export async function addMember(actorId:string,organizationId:string,userId:string,role:OrgRole){
 await requireOrgPermission(actorId,organizationId,'manageOrg');
 if(!roles.includes(role))throw new Error('Invalid organization role');
 if(actorId===userId&&role!=='ORG_ADMIN')throw Object.assign(new Error('Organization admin cannot demote self'),{statusCode:409});
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  await client.query('SELECT id FROM grc_organizations WHERE id=$1 FOR UPDATE',[organizationId]);
  const exists=(await client.query('SELECT id FROM app_users WHERE id=$1',[userId])).rows[0];if(!exists)throw Object.assign(new Error('User not found'),{statusCode:404});
  const current=(await client.query('SELECT role,status FROM grc_organization_members WHERE organization_id=$1 AND user_id=$2 FOR UPDATE',[organizationId,userId])).rows[0];
  if(current?.role==='ORG_ADMIN'&&current?.status==='ACTIVE'&&role!=='ORG_ADMIN'){
   const admins=Number((await client.query("SELECT count(*) c FROM grc_organization_members WHERE organization_id=$1 AND role='ORG_ADMIN' AND status='ACTIVE'",[organizationId])).rows[0].c);
   if(admins<=1)throw Object.assign(new Error('Organization must retain at least one active administrator'),{statusCode:409});
  }
  const out=(await client.query(`INSERT INTO grc_organization_members(organization_id,user_id,role,status)
   VALUES($1,$2,$3,'ACTIVE') ON CONFLICT(organization_id,user_id)
   DO UPDATE SET role=EXCLUDED.role,status='ACTIVE' RETURNING organization_id,user_id,role,status`,[organizationId,userId,role])).rows[0];
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}

export async function setMemberStatus(actorId:string,organizationId:string,userId:string,status:'ACTIVE'|'SUSPENDED'){
 await requireOrgPermission(actorId,organizationId,'manageOrg');
 if(status!=='ACTIVE'&&status!=='SUSPENDED')throw new Error('Invalid member status');
 if(actorId===userId&&status==='SUSPENDED')throw Object.assign(new Error('Organization administrator cannot suspend self'),{statusCode:409});
 const client=await pool.connect();
 try{
  await client.query('BEGIN');await client.query('SELECT id FROM grc_organizations WHERE id=$1 FOR UPDATE',[organizationId]);
  const member=(await client.query('SELECT role,status FROM grc_organization_members WHERE organization_id=$1 AND user_id=$2 FOR UPDATE',[organizationId,userId])).rows[0];
  if(!member)throw Object.assign(new Error('Organization member not found'),{statusCode:404});
  if(member.role==='ORG_ADMIN'&&member.status==='ACTIVE'&&status==='SUSPENDED'){
   const admins=Number((await client.query("SELECT count(*) c FROM grc_organization_members WHERE organization_id=$1 AND role='ORG_ADMIN' AND status='ACTIVE'",[organizationId])).rows[0].c);
   if(admins<=1)throw Object.assign(new Error('Organization must retain at least one active administrator'),{statusCode:409});
  }
  const out=(await client.query('UPDATE grc_organization_members SET status=$3 WHERE organization_id=$1 AND user_id=$2 RETURNING organization_id,user_id,role,status',[organizationId,userId,status])).rows[0];
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}

export async function listMembers(userId:string,organizationId:string){
 await requireOrgPermission(userId,organizationId,'read');
 return (await pool.query(`SELECT m.user_id,u.email,m.role,m.status,m.created_at
 FROM grc_organization_members m JOIN app_users u ON u.id=m.user_id
 WHERE m.organization_id=$1 ORDER BY u.email`,[organizationId])).rows;
}

export async function assignAssessmentToOrganization(userId:string,organizationId:string,assessmentId:string){
 await requireOrgPermission(userId,organizationId,'manageScope');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const row=(await client.query('SELECT id,organization_id,created_by FROM assessments WHERE id=$1 FOR UPDATE',[assessmentId])).rows[0];
  if(!row)throw Object.assign(new Error('Assessment not found'),{statusCode:404});
  if(row.organization_id&&row.organization_id!==organizationId)throw Object.assign(new Error('Assessment already belongs to another organization'),{statusCode:409});
  if(!row.organization_id&&row.created_by!==userId)throw Object.assign(new Error('Unassigned assessments require verified creator ownership; legacy records need an administrator-led migration'),{statusCode:403});
  const updated=(await client.query(`UPDATE assessments SET organization_id=$1,created_by=COALESCE(created_by,$2),updated_at=now()
   WHERE id=$3 RETURNING id,organization_id,created_by,authorized_at,status,target`,[organizationId,userId,assessmentId])).rows[0];
  await client.query('COMMIT');return updated;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function requireAssessmentAccess(userId:string,assessmentId:string){
 const r=(await pool.query(`SELECT a.id,a.organization_id,a.target,a.status
 FROM assessments a JOIN grc_organization_members m ON m.organization_id=a.organization_id
 JOIN grc_organizations o ON o.id=a.organization_id
 WHERE a.id=$1 AND m.user_id=$2 AND m.status='ACTIVE' AND o.status='ACTIVE'`,[assessmentId,userId])).rows[0];
 if(!r)throw Object.assign(new Error('Assessment organization access required'),{statusCode:403});
 return r;
}
