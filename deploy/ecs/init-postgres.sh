#!/bin/bash
set -e

# Create openfga database if it doesn't exist
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE openfga' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'openfga')\gexec
EOSQL
