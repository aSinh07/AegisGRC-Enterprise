import 'dotenv/config';import { readFile } from 'node:fs/promises';import pg from 'pg';

// Schema migration. Runs as the schema OWNER: MIGRATION_DATABASE_URL when set (recommended),
// otherwise DATABASE_URL (legacy single-role deployments).
//  1. db/schema.sql in one transaction.
//  2. Every runtime DDL initializer (src/schema-init.ts), so the HTTP server never needs DDL rights.
//  3. When AEGIS_DB_RUNTIME_ROLE is set, provisions that least-privilege runtime role: login,
//     no superuser/createdb/createrole, no CREATE on the schema, DML only, and no UPDATE/DELETE
//     on append-only evidence tables. The app then connects with DATABASE_URL as that role.
const ownerUrl=process.env.MIGRATION_DATABASE_URL||process.env.DATABASE_URL;
if(!ownerUrl) throw new Error('MIGRATION_DATABASE_URL or DATABASE_URL is required');
// Application modules create their pool from DATABASE_URL at import time: point them at the owner.
process.env.DATABASE_URL=ownerUrl;
const ssl=process.env.PGSSL==='disable'?false:{rejectUnauthorized:false};
const pool=new pg.Pool({connectionString:ownerUrl,ssl});
const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');

const APPEND_ONLY=['evidence','audit_events','audit_chain_checkpoints','report_records'];
export function runtimeRoleStatements(role:string,password:string,database:string,quote:{ident:(x:string)=>string;literal:(x:string)=>string}){
 if(!/^[a-z_][a-z0-9_]{0,62}$/.test(role))throw new Error('AEGIS_DB_RUNTIME_ROLE must be a lowercase PostgreSQL identifier');
 if(password.length<24)throw new Error('AEGIS_DB_RUNTIME_PASSWORD must be at least 24 characters');
 const r=quote.ident(role);
 return [
  `DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=${quote.literal(role)}) THEN CREATE ROLE ${r} LOGIN; END IF; END$$`,
  `ALTER ROLE ${r} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD ${quote.literal(password)}`,
  `GRANT CONNECT ON DATABASE ${quote.ident(database)} TO ${r}`,
  `REVOKE CREATE ON SCHEMA public FROM PUBLIC`,
  `REVOKE CREATE ON SCHEMA public FROM ${r}`,
  `GRANT USAGE ON SCHEMA public TO ${r}`,
  `GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO ${r}`,
  `REVOKE TRUNCATE,REFERENCES,TRIGGER ON ALL TABLES IN SCHEMA public FROM ${r}`,
  `REVOKE UPDATE,DELETE ON ${APPEND_ONLY.join(',')} FROM ${r}`,
  `REVOKE DELETE ON documents FROM ${r}`,
  `GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO ${r}`,
  `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ${r}`,
 ];
}

const client=await pool.connect();
try{
 await client.query('BEGIN');
 await client.query(sql);
 await client.query('COMMIT');
 console.log('AegisGRC database schema initialized transactionally');
}catch(e){
 await client.query('ROLLBACK');
 console.error('AegisGRC database schema initialization failed; transaction rolled back');
 client.release();await pool.end();
 throw e;
}
try{
 const {initRuntimeSchema}=await import('../src/schema-init.js');
 await initRuntimeSchema();
 console.log('AegisGRC runtime schema initializers applied as the schema owner');
 const role=String(process.env.AEGIS_DB_RUNTIME_ROLE||'').trim();
 if(role){
  const owner=(await client.query('SELECT current_user AS u,current_database() AS d')).rows[0];
  if(owner.u===role)throw new Error('AEGIS_DB_RUNTIME_ROLE must differ from the migration (owner) role');
  const stmts=runtimeRoleStatements(role,String(process.env.AEGIS_DB_RUNTIME_PASSWORD||''),owner.d,{ident:x=>client.escapeIdentifier(x),literal:x=>client.escapeLiteral(x)});
  await client.query('BEGIN');for(const s of stmts)await client.query(s);await client.query('COMMIT');
  console.log('AegisGRC least-privilege runtime role '+role+' provisioned (DML only; evidence tables append-only)');
 }
}catch(e){try{await client.query('ROLLBACK')}catch{}throw e}
finally{
 client.release();
 await pool.end();
 const {pool:appPool}=await import('../src/db-pool.js');await appPool.end().catch(()=>{});
}
