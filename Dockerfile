FROM postgres:16.10
ADD audit.sql /docker-entrypoint-initdb.d/
