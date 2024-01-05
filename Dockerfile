FROM postgres:14.9
ADD audit.sql /docker-entrypoint-initdb.d/
