FROM postgres:16.9
ADD audit.sql /docker-entrypoint-initdb.d/
