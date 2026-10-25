ALTER TABLE oauth_clients ADD COLUMN registration_state TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE oauth_clients ADD COLUMN protected_until DOUBLE PRECISION NOT NULL DEFAULT 0;
CREATE INDEX oauth_clients_registration ON oauth_clients(registration_state,created_at);
