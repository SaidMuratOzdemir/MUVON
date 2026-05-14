FROM paradedb/paradedb:latest

USER root

# Install pg_uuidv7 (v1.7+) and TimescaleDB
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        postgresql-server-dev-18 \
        build-essential \
        git \
        ca-certificates \
        curl \
        gnupg && \
    # pg_uuidv7
    git clone --depth=1 https://github.com/fboulnois/pg_uuidv7 /tmp/pg_uuidv7 && \
    cd /tmp/pg_uuidv7 && \
    make PG_CONFIG=/usr/lib/postgresql/18/bin/pg_config && \
    make install PG_CONFIG=/usr/lib/postgresql/18/bin/pg_config && \
    rm -rf /tmp/pg_uuidv7 && \
    # TimescaleDB
    curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey | gpg --dearmor -o /usr/share/keyrings/timescaledb.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/debian/ bookworm main" \
        > /etc/apt/sources.list.d/timescaledb.list && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends timescaledb-2-postgresql-18 && \
    # Cleanup
    apt-get remove -y build-essential git postgresql-server-dev-18 curl gnupg && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER postgres
