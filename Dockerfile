FROM postgres:16.4
ADD audit.sql /docker-entrypoint-initdb.d/
