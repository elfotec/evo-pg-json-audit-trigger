FROM postgres:17.6
ADD audit.sql /docker-entrypoint-initdb.d/
