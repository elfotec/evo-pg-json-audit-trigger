FROM postgres:16.8
ADD audit.sql /docker-entrypoint-initdb.d/
