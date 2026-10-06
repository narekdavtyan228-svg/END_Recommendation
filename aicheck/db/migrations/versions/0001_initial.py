"""Initial schema: journal, queue, catalog, rule packages, document base.

Revision ID: 0001
"""

from alembic import op

revision = "0001"
down_revision = None

JOURNAL = ("check_run", "run_event", "finding", "finding_action", "kb_event")
SERVICE = (
    "ruleset",
    "catalog_snapshot",
    "job",
    "callback_outbox",
    "llm_cache",
    "kb_document",
    "kb_clause",
    "kb_rule_ref",
    "kb_job",
)

SCHEMA = """
CREATE SCHEMA aicheck;

CREATE TABLE aicheck.ruleset (
  id bigserial PRIMARY KEY,
  org_code text NOT NULL,
  version text NOT NULL,
  status text NOT NULL CHECK (status IN ('draft','active','archived')),
  body jsonb NOT NULL,
  body_sha256 text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  UNIQUE (org_code, version)
);
CREATE UNIQUE INDEX one_active_ruleset ON aicheck.ruleset (org_code) WHERE status = 'active';

CREATE TABLE aicheck.catalog_snapshot (
  org_code text NOT NULL,
  version text NOT NULL,
  body jsonb NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_code, version)
);

CREATE TABLE aicheck.check_run (
  id uuid PRIMARY KEY,
  end_ref text NOT NULL,
  content_hash text NOT NULL,
  ruleset_id bigint NOT NULL REFERENCES aicheck.ruleset(id),
  catalog_version text NOT NULL,
  request jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (end_ref, content_hash, ruleset_id)
);
CREATE INDEX check_run_user ON aicheck.check_run ((request->'requestedBy'->>'userRef'), created_at);
CREATE INDEX check_run_hash ON aicheck.check_run (end_ref, content_hash);

CREATE TABLE aicheck.run_event (
  id bigserial PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES aicheck.check_run(id),
  status text NOT NULL,
  llm_status text NOT NULL,
  model text, prompt_version text, duration_ms integer,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX run_event_run ON aicheck.run_event (run_id, id DESC);

CREATE TABLE aicheck.finding (
  id uuid PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES aicheck.check_run(id),
  rule_code text NOT NULL,
  source text NOT NULL CHECK (source IN ('rules','ai')),
  severity text NOT NULL,
  kind text NOT NULL,
  target jsonb NOT NULL,
  body jsonb NOT NULL,
  generated boolean NOT NULL DEFAULT false,
  confidence numeric(3,2),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX finding_run ON aicheck.finding (run_id);

CREATE TABLE aicheck.finding_action (
  id uuid PRIMARY KEY,
  finding_id uuid NOT NULL REFERENCES aicheck.finding(id),
  action text NOT NULL CHECK (action IN ('accept','edit','reject','answer','hide','reopen')),
  reason_code text, comment text, applied_text text,
  user_ref text NOT NULL, user_role text NOT NULL,
  idempotency_key text UNIQUE,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX finding_action_finding ON aicheck.finding_action (finding_id, created_at);

CREATE TABLE aicheck.job (
  id bigserial PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES aicheck.check_run(id),
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','done','failed')),
  attempts smallint NOT NULL DEFAULT 0,
  not_before timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz
);
CREATE INDEX job_state ON aicheck.job (state, not_before);

CREATE TABLE aicheck.callback_outbox (
  id bigserial PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES aicheck.check_run(id),
  payload jsonb NOT NULL,
  attempts smallint NOT NULL DEFAULT 0,
  next_try_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);

CREATE TABLE aicheck.llm_cache (
  key text PRIMARY KEY,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE aicheck.kb_document (
  id bigserial PRIMARY KEY,
  code text NOT NULL,
  version_no integer NOT NULL,
  status text NOT NULL CHECK (status IN ('draft','active','archived')),
  meta jsonb NOT NULL,
  org_codes text[] NOT NULL DEFAULT '{}',
  work_types text[] NOT NULL DEFAULT '{}',
  categories text[] NOT NULL DEFAULT '{}',
  file_name text NOT NULL,
  file_bytes bytea NOT NULL,
  file_sha256 text NOT NULL,
  parse_report jsonb,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (code, version_no)
);
CREATE UNIQUE INDEX one_active_doc ON aicheck.kb_document (code) WHERE status = 'active';
CREATE INDEX kb_document_org ON aicheck.kb_document USING gin (org_codes);
CREATE INDEX kb_document_cat ON aicheck.kb_document USING gin (categories);

CREATE TABLE aicheck.kb_clause (
  id bigserial PRIMARY KEY,
  document_id bigint NOT NULL REFERENCES aicheck.kb_document(id),
  clause_no text NOT NULL,
  heading text,
  body text NOT NULL,
  body_sha256 text NOT NULL,
  position integer NOT NULL,
  excluded boolean NOT NULL DEFAULT false,
  tsv tsvector GENERATED ALWAYS AS (to_tsvector('russian', coalesce(heading,'') || ' ' || body)) STORED
);
CREATE INDEX kb_clause_tsv ON aicheck.kb_clause USING gin (tsv);
CREATE INDEX kb_clause_doc ON aicheck.kb_clause (document_id, clause_no);

CREATE TABLE aicheck.kb_rule_ref (
  rule_code text NOT NULL,
  doc_code text NOT NULL,
  clause_no text NOT NULL,
  PRIMARY KEY (rule_code, doc_code, clause_no)
);

CREATE TABLE aicheck.kb_event (
  id bigserial PRIMARY KEY,
  document_id bigint, action text NOT NULL, user_ref text NOT NULL,
  details jsonb, created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE aicheck.kb_job (
  id bigserial PRIMARY KEY,
  document_id bigint NOT NULL REFERENCES aicheck.kb_document(id),
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','done','failed')),
  attempts smallint NOT NULL DEFAULT 0,
  not_before timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz
);
CREATE INDEX kb_job_state ON aicheck.kb_job (state, not_before);

CREATE FUNCTION aicheck.forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;
"""


def upgrade() -> None:
    op.execute(SCHEMA)
    for table in JOURNAL:
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON aicheck.{table} "
            "FOR EACH ROW EXECUTE FUNCTION aicheck.forbid_change()"
        )
    op.execute(
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aicheck_app') "
        "THEN CREATE ROLE aicheck_app LOGIN; END IF; END $$"
    )
    op.execute("GRANT USAGE ON SCHEMA aicheck TO aicheck_app")
    for table in JOURNAL:
        op.execute(f"GRANT INSERT, SELECT ON aicheck.{table} TO aicheck_app")
    for table in SERVICE:
        op.execute(f"GRANT INSERT, SELECT, UPDATE ON aicheck.{table} TO aicheck_app")
    op.execute(
        "GRANT DELETE ON aicheck.llm_cache, aicheck.kb_clause, aicheck.kb_rule_ref TO aicheck_app"
    )
    op.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA aicheck TO aicheck_app")


def downgrade() -> None:
    op.execute("DROP SCHEMA aicheck CASCADE")
