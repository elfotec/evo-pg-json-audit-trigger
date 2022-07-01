# PG JSON Audit Trigger

A simple, customisable table audit system for PostgreSQL implemented using
triggers.

This trigger is based on https://github.com/2ndQuadrant/audit-trigger.
It has been modified to include the following features:

  * Customizable "application.name" setting for specifying source application
  * Customizable "application.user" setting for specifying active application user
  * The original and diff columns are now stored in JSON instead of HSTORE.
    The JSON diff value is a recursive JSON diff of changes made to the original
    record and any JSON columns within.
  * Additional naming convention tweaks
  * row_key has been added for a key back to the row in the audited table

Requires PostgreSQL 9.5+

----

## Elfotec changes

   * Added "tenant_id" field

## More info about changes for row_key
* a key value from the audited row is stored in the row_key column of the log table as text
* the source column is configurable and defaults to 'id'
    * if the column is not found, the row_key is just set to NULL
* audit_table functions have been changed for setting of the row_key source column name
* an index on (schema_name, table_name, row_key, action_tstamp_tx DESC) has been added to the log table
 for queries to find recent changes for a given row of a given table


### Basic Usage

To enable auditing:

    SELECT audit.audit_table('target_table_name');
    
To disable auditing:

    DROP TRIGGER audit_trigger_row ON target_table_name;
    DROP TRIGGER audit_trigger_stm ON target_table_name;
    
### Additional Options

To use a different source column for row_key

    SELECT audit.audit_table('target_table_name', 'row_key_column_name');

Arguments for full version of audit_table function:
    
* target_table:     Table name, schema qualified if not on search_path
* audit_rows:       Record each row change, or only audit at a statement level
* audit_query_text: Record the text of the client query that triggered the audit event?
* ignored_cols:     Columns to exclude from update diffs, ignore updates that change only ignored cols.
* row_key_col:      Column used to identify a row in the target_table.

an example using all of these

    SELECT audit.audit_table('target_table_name', 'true', 'false', '{version_col, changed_by, changed_timestamp}'::text[], 'row_key_column_name');
    
### See also:

https://wiki.postgresql.org/wiki/Audit_trigger_91plus  
and the comments in the SQL.  
