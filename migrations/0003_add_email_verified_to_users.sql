-- Add migration script here
-- Migration 0003: Add email_verified field to users

ALTER TABLE users
ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- Index for filtering verified users
CREATE INDEX idx_users_email_verified ON users(email_verified);
