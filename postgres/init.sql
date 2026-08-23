-- Extensions are created here, at database init, so they land in `public` and
-- are visible to every service whatever its search_path. The migrations run
-- CREATE EXTENSION IF NOT EXISTS again and find them already in place.
CREATE EXTENSION IF NOT EXISTS pg_uuidv7;
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
