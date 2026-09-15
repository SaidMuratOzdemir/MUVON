# Official PostgreSQL plus the one extension the stack adds to it. A vendor
# base image brings its own init scripts, which run on every fresh volume.
FROM postgres:18-trixie

ARG TIMESCALEDB_VERSION=2.30.0

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey | gpg --dearmor -o /usr/share/keyrings/timescaledb.gpg; \
    . /etc/os-release; \
    echo "deb [signed-by=/usr/share/keyrings/timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/debian/ $VERSION_CODENAME main" \
        > /etc/apt/sources.list.d/timescaledb.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        "timescaledb-2-postgresql-18=${TIMESCALEDB_VERSION}~*" \
        "timescaledb-2-loader-postgresql-18=${TIMESCALEDB_VERSION}~*"; \
    apt-get purge -y --auto-remove curl gnupg; \
    rm -rf /var/lib/apt/lists/*
