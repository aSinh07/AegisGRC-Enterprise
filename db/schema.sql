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
 IF current_setting('aegis.allow_evidence_purge', true) = 'on' THEN
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
 IF current_setting('aegis.allow_evidence_purge', true) = 'on' THEN
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
