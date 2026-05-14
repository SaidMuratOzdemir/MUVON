-- Extensions are loaded here so they are available before muvon migrations run.
-- muvon migrations will run CREATE EXTENSION IF NOT EXISTS ... again (idempotent).
CREATE EXTENSION IF NOT EXISTS pg_uuidv7;
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS pg_search;
