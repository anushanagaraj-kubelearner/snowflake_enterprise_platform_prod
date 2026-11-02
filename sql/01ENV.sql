-- =============================================================================
-- 01_environment.sql
-- WHAT   The platform the blinding sits on: warehouse, database, schema, and the two feed layers
--          <LANDING_TABLE>            loaded by the pipeline — not created here
--            -> <FEED_VIEW>_ROWS      row layer   (row access policy goes here, 02a)
--            -> <FEED_VIEW>           feed view   (masking policy goes here, 02a; people query this)
--        Two layers because one column cannot sit in both policies' signatures on the same object.
-- ROLES  SYSADMIN only
-- NEEDS  the landing table exists, owned by SYSADMIN
-- RUN    Set Section 0, Run All. Re-runnable: nothing that exists is replaced. Checks: 03_checks.sql
-- =============================================================================


-- Section 0 PARAMETERS — the only place a name is typed --------------------------------
SET BUILD_ROLE    = 'SYSADMIN';
SET ROLE_CREATOR  = 'USERADMIN';            -- creates the study roles in 02b Section 1
SET WH            = 'ODM_BLINDING_WH';
SET DB            = 'DEV_MEDIDATA_ODM_DATA_PRODUCT';
SET SCHEMA        = 'RAW_ODM';
SET LANDING_TABLE = 'POC_PATIENT_ITEM_DATA';
SET FEED_VIEW     = 'SV_PATIENT_ITEM_DATA';

SET FQ_SCHEMA  = $DB || '.' || $SCHEMA;
SET FQ_LANDING = $FQ_SCHEMA || '.' || $LANDING_TABLE;
SET FQ_ROWS    = $FQ_SCHEMA || '.' || $FEED_VIEW || '_ROWS';
SET FQ_FEED    = $FQ_SCHEMA || '.' || $FEED_VIEW;


-- Section 1 SYSADMIN: warehouse, database, schema -------------------------------------
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;

-- 1.1 Warehouse for the blinding build, the app and study queries (XS, suspends after 60 s)
CREATE WAREHOUSE IF NOT EXISTS IDENTIFIER($WH)
  WITH WAREHOUSE_SIZE = XSMALL AUTO_SUSPEND = 60 AUTO_RESUME = TRUE INITIALLY_SUSPENDED = TRUE
  COMMENT = 'Blinding build, app and study queries.';
USE WAREHOUSE IDENTIFIER($WH);
GRANT USAGE ON WAREHOUSE IDENTIFIER($WH) TO ROLE IDENTIFIER($ROLE_CREATOR);   -- 02b Section 1 runs on it

-- 1.2 Database and schema of the feed
CREATE DATABASE IF NOT EXISTS IDENTIFIER($DB);
CREATE SCHEMA   IF NOT EXISTS IDENTIFIER($FQ_SCHEMA);


-- Section 2 SYSADMIN: the two feed layers ----------------------------------------------
--   SECURE: each runs with its owner's rights, so readers need nothing on the layer beneath.
--   Created once (IF NOT EXISTS): replacing a layer would drop its policy, so changing a layer is a
--   controlled change, never a re-run of this file. Granted to nobody here: study roles get the feed
--   view in 02b, after the policies are on.
--   One block: a view body is stored as text, so the names must be written into it, not $variables.
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
BEGIN
  LET landing STRING := (SELECT $FQ_LANDING);
  LET rows_v  STRING := (SELECT $FQ_ROWS);
  LET feed_v  STRING := (SELECT $FQ_FEED);
  -- 2.1 Row layer: the landing table, filtered by the row access policy
  EXECUTE IMMEDIATE 'CREATE SECURE VIEW IF NOT EXISTS ' || :rows_v
    || ' COMMENT = ''Row layer: landing table filtered by RAP_STUDY_ACCESS. Granted to nobody; read by the feed view.'''
    || ' AS SELECT * FROM ' || :landing;
  -- 2.2 Feed view: the row layer, value columns masked by MASK_ITEM_VALUE. The only object people query.
  EXECUTE IMMEDIATE 'CREATE SECURE VIEW IF NOT EXISTS ' || :feed_v
    || ' COMMENT = ''Patient item data, all studies. Rows via the row layer; value columns masked.'''
    || ' AS SELECT * FROM ' || :rows_v;
  RETURN :feed_v || ' -> ' || :rows_v || ' -> ' || :landing;
END;

-- END. Next: 02a_account_build.sql
