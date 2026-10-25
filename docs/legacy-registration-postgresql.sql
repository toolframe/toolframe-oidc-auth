-- Run only after the database-level writer fence described in registration.md.
-- Supply application_id, oidc_schema, oidc_meta, auth_schema and auth_meta.
-- Dry-run by default; set apply=true only after reviewing the candidate IDs.
\set ON_ERROR_STOP on
\if :{?apply}
\else
  \set apply false
\endif
BEGIN;
SET LOCAL lock_timeout = '5s';
LOCK TABLE _toolframe_platform.identity, :"oidc_meta".identity, :"auth_meta".identity,
  :"oidc_schema".oauth_clients, :"oidc_schema".oauth_flows,
  :"oidc_schema".oauth_codes, :"oidc_schema".oauth_tokens,
  :"auth_schema".agent_grants IN ACCESS EXCLUSIVE MODE;
SELECT
  (SELECT count(*)=1 AND bool_and(application_id=:'application_id') FROM _toolframe_platform.identity)
  AND (SELECT count(*)=1 AND bool_and(application_id=:'application_id' AND owner='oidc-auth') FROM :"oidc_meta".identity)
  AND (SELECT count(*)=1 AND bool_and(application_id=:'application_id' AND owner='auth') FROM :"auth_meta".identity)
  AND NOT EXISTS (SELECT 1 FROM :"oidc_schema".oauth_flows WHERE expires_at>extract(epoch FROM clock_timestamp()))
  AND NOT EXISTS (SELECT 1 FROM :"oidc_schema".oauth_codes WHERE jsonb_typeof(data::jsonb->'client_id') IS DISTINCT FROM 'string')
  AS safe \gset
\if :safe
\else
  \echo 'Recovery refused: identity, live flow, or code evidence is unsafe.'
  ROLLBACK;
  DO $$ BEGIN RAISE EXCEPTION 'Recovery refused'; END $$;
\endif
CREATE TEMP TABLE recovery_candidates ON COMMIT DROP AS
SELECT c.id FROM :"oidc_schema".oauth_clients c
WHERE c.registration_state='legacy'
  AND NOT EXISTS (SELECT 1 FROM :"auth_schema".agent_grants g WHERE g.client_id=c.id)
  AND NOT EXISTS (SELECT 1 FROM :"oidc_schema".oauth_tokens t WHERE t.client_id=c.id)
  AND NOT EXISTS (SELECT 1 FROM :"oidc_schema".oauth_codes x WHERE x.data::jsonb->>'client_id'=c.id);
TABLE recovery_candidates;
\if :apply
  UPDATE :"oidc_schema".oauth_clients SET registration_state='pending',protected_until=0
    WHERE id IN (SELECT id FROM recovery_candidates) AND registration_state='legacy';
  COMMIT;
\else
  ROLLBACK;
\endif
