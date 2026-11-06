-- Bootstrap identity and tenancy parents before assessment foreign keys.
-- Runtime initializers may add compatible columns/indexes, but a clean database must
-- be valid before the HTTP server starts.
CREATE TABLE IF NOT EXISTS app_users (
 id uuid PRIMARY KEY,
 email text UNIQUE NOT NULL,
 password_hash text NOT NULL,
 password_salt text NOT NULL,
 totp_secret text NOT NULL, -- plaintext legacy rows remain readable; new rows are AES-256-GCM encrypted when TOTP_ENCRYPTION_KEY is configured
 totp_verified boolean NOT NULL DEFAULT false,
 full_name text,
 designation text,
 company_name text,
 role text NOT NULL DEFAULT 'analyst',
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_auth_attempts (
 attempt_key text PRIMARY KEY,
 failures int NOT NULL DEFAULT 0,
 window_started_at timestamptz NOT NULL DEFAULT now(),
 blocked_until timestamptz,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_auth_attempts_blocked_idx ON app_auth_attempts(blocked_until);

CREATE TABLE IF NOT EXISTS grc_organizations (
 id uuid PRIMARY KEY,
 name text NOT NULL,
 industry text,
 status text NOT NULL DEFAULT 'ACTIVE',
 created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assessments (
 id uuid PRIMARY KEY, target text NOT NULL, authorized_at timestamptz NOT NULL, status text NOT NULL, payload jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
 id uuid PRIMARY KEY, assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, source text NOT NULL, sha256 text NOT NULL, created_at timestamptz NOT NULL, payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_assessment_idx ON evidence(assessment_id);
CREATE TABLE IF NOT EXISTS findings (
 id uuid PRIMARY KEY, assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, severity text NOT NULL, source text NOT NULL, created_at timestamptz NOT NULL, payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_assessment_idx ON findings(assessment_id);
CREATE TABLE IF NOT EXISTS audit_events (
 id uuid PRIMARY KEY, assessment_id uuid, action text NOT NULL, created_at timestamptz NOT NULL, payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_assessment_idx ON audit_events(assessment_id);

CREATE TABLE IF NOT EXISTS documents (
 id uuid PRIMARY KEY,
 assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
 filename text NOT NULL,
 mime_type text NOT NULL,
 size_bytes integer NOT NULL,
 sha256 text NOT NULL,
 created_at timestamptz NOT NULL,
 content bytea NOT NULL
);
CREATE INDEX IF NOT EXISTS documents_assessment_idx ON documents(assessment_id);

-- Assessment tenancy is additive for legacy compatibility. Existing rows remain NULL until explicitly assigned.
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES grc_organizations(id) ON DELETE RESTRICT;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES app_users(id) ON DELETE SET NULL;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS assessments_organization_idx ON assessments(organization_id,authorized_at DESC);

-- Evidence integrity metadata. Existing evidence is retained; integrity_verified_at is NULL until server verification.
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS byte_length bigint;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS integrity_verified_at timestamptz;
-- SHA-256 format is enforced by application writes. The named database constraint may
-- already exist from an earlier migration; do not recreate or drop it during startup.


-- Evidence Vault immutability (architecture: "Hashed, Tenant Scoped, Immutable, Auditable").
-- Scanner evidence and audit events are append-only at the database layer, not only by
-- application convention. A deliberate, audited retention purge must opt in per transaction:
--   BEGIN; SET LOCAL aegis.allow_evidence_purge='on'; DELETE ...; COMMIT;
CREATE OR REPLACE FUNCTION aegis_forbid_evidence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- The purge override is honoured only for the table owner (migration role). A non-owner runtime
 -- role can set the GUC but still cannot rewrite or delete evidence.
 IF current_setting('aegis.allow_evidence_purge', true) = 'on' AND pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER') THEN
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
 END IF;
 RAISE EXCEPTION 'AegisGRC % is append-only: % is not permitted', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS evidence_append_only ON evidence;
CREATE TRIGGER evidence_append_only BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION aegis_forbid_evidence_mutation();
DROP TRIGGER IF EXISTS evidence_no_truncate ON evidence;
CREATE TRIGGER evidence_no_truncate BEFORE TRUNCATE ON evidence FOR EACH STATEMENT EXECUTE FUNCTION aegis_forbid_evidence_mutation();
DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION aegis_forbid_evidence_mutation();
DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION aegis_forbid_evidence_mutation();

-- Uploaded evidence documents are retained: "delete" is a soft withdrawal that keeps the bytes and hash.
ALTER TABLE documents ADD COLUMN IF NOT EXISTS withdrawn_at timestamptz;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS withdrawn_by uuid;
CREATE OR REPLACE FUNCTION aegis_protect_document_content() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- The purge override is honoured only for the table owner (migration role). A non-owner runtime
 -- role can set the GUC but still cannot rewrite or delete evidence.
 IF current_setting('aegis.allow_evidence_purge', true) = 'on' AND pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid=TG_RELID),'MEMBER') THEN
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP = 'DELETE' THEN
  RAISE EXCEPTION 'AegisGRC documents are retained evidence: use withdrawal, not DELETE' USING ERRCODE = 'insufficient_privilege';
 END IF;
 IF NEW.content IS DISTINCT FROM OLD.content OR NEW.sha256 IS DISTINCT FROM OLD.sha256 OR NEW.assessment_id IS DISTINCT FROM OLD.assessment_id
    OR NEW.filename IS DISTINCT FROM OLD.filename OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR (OLD.withdrawn_at IS NOT NULL AND NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at) THEN
  RAISE EXCEPTION 'AegisGRC document content, hash and withdrawal history are immutable' USING ERRCODE = 'insufficient_privilege';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS documents_content_immutable ON documents;
CREATE TRIGGER documents_content_immutable BEFORE UPDATE OR DELETE ON documents FOR EACH ROW EXECUTE FUNCTION aegis_protect_document_content();

-- Deleting an assessment must not silently cascade away its evidence trail.
ALTER TABLE evidence DROP CONSTRAINT IF EXISTS evidence_assessment_id_fkey;
ALTER TABLE evidence ADD CONSTRAINT evidence_assessment_id_fkey FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE RESTRICT;
ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_assessment_id_fkey;
ALTER TABLE documents ADD CONSTRAINT documents_assessment_id_fkey FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE RESTRICT;

-- Keyed evidence integrity. The HMAC (EVIDENCE_HMAC_KEY, held only by the application)
-- covers the canonical evidence record, so a database-only writer cannot forge evidence.
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS hmac_sha256 text;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS hmac_key_id text;

-- Tamper-evident audit trail: every audit event is hash-chained to its predecessor at
-- insert time, whichever code path writes it. Chaining runs under a transaction-scoped
-- advisory lock so concurrent writers produce one linear chain.
CREATE SEQUENCE IF NOT EXISTS audit_events_chain_seq;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS chain_seq bigint;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash text;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS entry_hash text;
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_chain_seq_idx ON audit_events(chain_seq);

CREATE OR REPLACE FUNCTION aegis_audit_entry_hash(prev text,event_id uuid,assessment uuid,act text,created timestamptz,body jsonb) RETURNS text LANGUAGE sql STABLE AS $$
 SELECT encode(sha256(convert_to(
  'aegis-audit-v1|'||prev||'|'||event_id::text||'|'||coalesce(assessment::text,'')||'|'||act||'|'||
  to_char(created AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')||'|'||body::text,'UTF8')),'hex')
$$;

CREATE OR REPLACE FUNCTION aegis_chain_audit_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_hash text;
BEGIN
 PERFORM pg_advisory_xact_lock(7314159265);
 SELECT entry_hash INTO last_hash FROM audit_events WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1;
 NEW.chain_seq := nextval('audit_events_chain_seq');
 NEW.prev_hash := coalesce(last_hash,repeat('0',64));
 NEW.entry_hash := aegis_audit_entry_hash(NEW.prev_hash,NEW.id,NEW.assessment_id,NEW.action,NEW.created_at,NEW.payload);
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS audit_events_hash_chain ON audit_events;
CREATE TRIGGER audit_events_hash_chain BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION aegis_chain_audit_event();

-- Chain rows that predate the hash chain, in creation order (one-time, idempotent).
DO $$
DECLARE r record; last_hash text; h text; s bigint;
BEGIN
 IF EXISTS (SELECT 1 FROM audit_events WHERE chain_seq IS NULL) THEN
  PERFORM pg_advisory_xact_lock(7314159265);
  PERFORM set_config('aegis.allow_evidence_purge','on',true);
  SELECT entry_hash INTO last_hash FROM audit_events WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1;
  last_hash := coalesce(last_hash,repeat('0',64));
  FOR r IN SELECT id,assessment_id,action,created_at,payload FROM audit_events WHERE chain_seq IS NULL ORDER BY created_at,id LOOP
   s := nextval('audit_events_chain_seq');
   h := aegis_audit_entry_hash(last_hash,r.id,r.assessment_id,r.action,r.created_at,r.payload);
   UPDATE audit_events SET chain_seq=s,prev_hash=last_hash,entry_hash=h WHERE id=r.id;
   last_hash := h;
  END LOOP;
  PERFORM set_config('aegis.allow_evidence_purge','off',true);
 END IF;
END;
$$;

-- HMAC-signed chain-head checkpoints. Recomputing the whole chain after tampering is
-- detectable because the checkpoint MAC needs the application-held EVIDENCE_HMAC_KEY.
CREATE TABLE IF NOT EXISTS audit_chain_checkpoints(
 id uuid PRIMARY KEY,
 chain_seq bigint NOT NULL,
 entry_hash text NOT NULL,
 hmac_sha256 text NOT NULL,
 key_id text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_chain_checkpoints_seq_idx ON audit_chain_checkpoints(chain_seq DESC);
DROP TRIGGER IF EXISTS audit_chain_checkpoints_append_only ON audit_chain_checkpoints;
CREATE TRIGGER audit_chain_checkpoints_append_only BEFORE UPDATE OR DELETE ON audit_chain_checkpoints FOR EACH ROW EXECUTE FUNCTION aegis_forbid_evidence_mutation();
DROP TRIGGER IF EXISTS audit_chain_checkpoints_no_truncate ON audit_chain_checkpoints;
CREATE TRIGGER audit_chain_checkpoints_no_truncate BEFORE TRUNCATE ON audit_chain_checkpoints FOR EACH STATEMENT EXECUTE FUNCTION aegis_forbid_evidence_mutation();

-- Target authorization: proof of hostname control (DNS TXT or /.well-known file) plus a
-- second-person approval. The CHECK enforces separation of duties in the database itself.
CREATE TABLE IF NOT EXISTS target_authorizations(
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE RESTRICT,
 hostname text NOT NULL,
 origin text NOT NULL,
 method text NOT NULL CHECK(method IN ('DNS_TXT','HTTP_FILE')),
 token text NOT NULL,
 status text NOT NULL CHECK(status IN ('PENDING_VERIFICATION','VERIFIED','APPROVED','REJECTED','REVOKED')),
 requested_by uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
 justification text,
 verified_at timestamptz,
 verification_evidence jsonb,
 decided_by uuid REFERENCES app_users(id) ON DELETE RESTRICT,
 decided_at timestamptz,
 decision_note text,
 expires_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT target_authorizations_separation_of_duties CHECK(decided_by IS NULL OR decided_by<>requested_by),
 CONSTRAINT target_authorizations_approval_complete CHECK(status<>'APPROVED' OR (decided_by IS NOT NULL AND verified_at IS NOT NULL AND expires_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS target_authorizations_lookup_idx ON target_authorizations(organization_id,hostname,status,expires_at);

-- Issued reports: exact bytes, SHA-256 and an HMAC (REPORT_SIGNING_KEY) over the record.
CREATE TABLE IF NOT EXISTS report_records(
 id uuid PRIMARY KEY,
 organization_id uuid REFERENCES grc_organizations(id) ON DELETE RESTRICT,
 assessment_id uuid REFERENCES assessments(id) ON DELETE RESTRICT,
 scope_ref text,
 report_type text NOT NULL,
 format text NOT NULL,
 filename text NOT NULL,
 content_type text NOT NULL,
 sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 size_bytes bigint NOT NULL,
 content bytea NOT NULL,
 hmac_sha256 text,
 key_id text,
 generated_by uuid,
 generated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS report_records_sha_type_idx ON report_records(sha256,report_type);
CREATE INDEX IF NOT EXISTS report_records_org_idx ON report_records(organization_id,generated_at DESC);
DROP TRIGGER IF EXISTS report_records_append_only ON report_records;
CREATE TRIGGER report_records_append_only BEFORE UPDATE OR DELETE ON report_records FOR EACH ROW EXECUTE FUNCTION aegis_forbid_evidence_mutation();
DROP TRIGGER IF EXISTS report_records_no_truncate ON report_records;
CREATE TRIGGER report_records_no_truncate BEFORE TRUNCATE ON report_records FOR EACH STATEMENT EXECUTE FUNCTION aegis_forbid_evidence_mutation();

-- Durable URL scan jobs (profile + approval) and their per-tool tasks (leased by a scanner worker).
CREATE TABLE IF NOT EXISTS url_scan_jobs(
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE RESTRICT,
 assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE RESTRICT,
 target_authorization_id uuid REFERENCES target_authorizations(id) ON DELETE RESTRICT,
 origin text NOT NULL,
 hostname text NOT NULL,
 pinned_addresses text[] NOT NULL,
 profile text NOT NULL CHECK(profile IN ('QUICK','STANDARD','DEEP')),
 purpose text NOT NULL DEFAULT 'ASSESSMENT' CHECK(purpose IN ('ASSESSMENT','SCHEDULED')),
 status text NOT NULL CHECK(status IN ('AWAITING_APPROVAL','QUEUED','RUNNING','COMPLETED','PARTIAL','FAILED','REJECTED','CANCELLED')),
 requested_by uuid REFERENCES app_users(id) ON DELETE RESTRICT,
 approved_by uuid REFERENCES app_users(id) ON DELETE RESTRICT,
 approved_at timestamptz,
 decision_note text,
 coverage jsonb,
 created_at timestamptz NOT NULL DEFAULT now(),
 started_at timestamptz,
 completed_at timestamptz,
 CONSTRAINT url_scan_jobs_separation_of_duties CHECK(approved_by IS NULL OR approved_by<>requested_by)
);
CREATE INDEX IF NOT EXISTS url_scan_jobs_assessment_idx ON url_scan_jobs(assessment_id,created_at DESC);
CREATE INDEX IF NOT EXISTS url_scan_jobs_org_status_idx ON url_scan_jobs(organization_id,status);
CREATE TABLE IF NOT EXISTS url_scan_tasks(
 id uuid PRIMARY KEY,
 job_id uuid NOT NULL REFERENCES url_scan_jobs(id) ON DELETE RESTRICT,
 tool text NOT NULL CHECK(tool IN ('http','nmap','nuclei','wapiti','zap','sqlmap')),
 options jsonb NOT NULL DEFAULT '{}'::jsonb,
 state text NOT NULL CHECK(state IN ('BLOCKED','QUEUED','LEASED','SUCCEEDED','FAILED','TIMEOUT','CANCELLED')),
 attempts int NOT NULL DEFAULT 0,
 max_attempts int NOT NULL DEFAULT 2,
 lease_owner text,
 lease_token text,
 lease_expires_at timestamptz,
 evidence_id uuid,
 evidence_sha256 text,
 finding_count int,
 error text,
 created_at timestamptz NOT NULL DEFAULT now(),
 started_at timestamptz,
 completed_at timestamptz,
 UNIQUE(job_id,tool)
);
CREATE INDEX IF NOT EXISTS url_scan_tasks_queue_idx ON url_scan_tasks(state,created_at);
-- Replay protection for signed scanner-worker requests.
CREATE TABLE IF NOT EXISTS scanner_worker_nonces(
 worker_id text NOT NULL,
 nonce text NOT NULL,
 seen_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(worker_id,nonce)
);
CREATE TABLE IF NOT EXISTS scanner_workers(
 id text PRIMARY KEY,
 last_seen_at timestamptz,
 last_ip text,
 version text
);
