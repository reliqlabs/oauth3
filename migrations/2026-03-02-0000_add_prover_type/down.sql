-- SQLite doesn't support DROP COLUMN, recreate table
CREATE TABLE prove_jobs_backup AS SELECT id, status, request_uri, response_body, quote_hex, proof_json, error_message, created_at, updated_at FROM prove_jobs;
DROP TABLE prove_jobs;
ALTER TABLE prove_jobs_backup RENAME TO prove_jobs;
CREATE INDEX idx_prove_jobs_status ON prove_jobs(status);
