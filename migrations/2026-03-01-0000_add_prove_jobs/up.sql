CREATE TABLE prove_jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending',
    request_uri TEXT NOT NULL,
    response_body BYTEA NOT NULL,
    quote_hex TEXT,
    proof_json TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_prove_jobs_status ON prove_jobs(status);
