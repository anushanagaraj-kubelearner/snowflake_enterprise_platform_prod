-- =============================================================================
-- 04_app_deploy.sql
-- WHAT   The ONE way the blinding app is deployed: on the WAREHOUSE runtime. There CURRENT_USER() is empty (no
--        READ SESSION), so the app passes the viewer Streamlit reports and 02a SP_ACTOR uses it. (Workspace "Deploy"
--        uses a compute pool, where the app runs as a service user and stops itself: never use it for this app.)
--        Then every registered study's roles get USAGE on the app (02a SP_GRANT_STUDY_ACCESS, the one grant list).
-- ROLES  SYSADMIN
-- NEEDS  02a, 02b for at least one study. The app's three files on the stage (Section 2).
-- RUN    First time: Section 0, Section 1, upload (Section 2), Section 3. Code change: re-upload streamlit_app.py (overwrite), Section 0, Section 3.
-- =============================================================================


-- Section 0 PARAMETERS -----------------------------------------------------------------
SET BUILD_ROLE = 'SYSADMIN';
SET WH         = 'ODM_BLINDING_WH';
SET DB         = 'DEV_MEDIDATA_ODM_DATA_PRODUCT';
SET SCHEMA     = 'RAW_ODM';
SET FEED_VIEW  = 'SV_PATIENT_ITEM_DATA';
SET APP        = 'BLINDING_APP';
SET SRC_STAGE  = 'BLINDING_APP_SRC';

SET FQ_SCHEMA = $DB || '.' || $SCHEMA;
SET FQ_STAGE  = $FQ_SCHEMA || '.' || $SRC_STAGE;


-- Section 1 SYSADMIN: the stage holding the app's source (once) ----------------------------
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
CREATE STAGE IF NOT EXISTS IDENTIFIER($FQ_STAGE) DIRECTORY = (ENABLE = TRUE) ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE')
  COMMENT = 'Source of BLINDING_APP: streamlit_app.py + environment.yml at the root, .streamlit/config.toml (theme). Uploaded in Snowsight.';


-- Section 2 UPLOAD — in Snowsight, not SQL ------------------------------------------------
--   Catalog > Database Explorer > DEV_MEDIDATA_ODM_DATA_PRODUCT > RAW_ODM > Stages > BLINDING_APP_SRC > + Files
--   Upload 1: streamlit_app.py and environment.yml (from v5/app).   Path: empty (stage root).
--   Upload 2: config.toml (from v5/app/.streamlit).                    Path: .streamlit
--   Section 3 refuses to deploy unless all three files are there.


-- Section 3 SYSADMIN: deploy, make live, grant to every registered study --------------------
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);
BEGIN
  LET stg STRING := (SELECT $FQ_STAGE);  LET app STRING := (SELECT $APP);  LET wh STRING := (SELECT $WH);
  LET db  STRING := (SELECT $DB);        LET sch STRING := (SELECT $SCHEMA); LET feed STRING := (SELECT $FEED_VIEW);
  LET n NUMBER := 0;  LET out STRING := '';

  -- 3.1 all three files on the stage, or stop
  EXECUTE IMMEDIATE 'ALTER STAGE ' || :stg || ' REFRESH';
  EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM DIRECTORY(@' || :stg || ') WHERE RELATIVE_PATH IN (''streamlit_app.py'', ''environment.yml'', ''.streamlit/config.toml'')';
  SELECT $1 INTO :n FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
  IF (:n < 3) THEN RETURN 'STOPPED: upload streamlit_app.py + environment.yml (root) and config.toml (path .streamlit) to ' || :stg || ' (Section 2)'; END IF;

  -- 3.2 the app on the warehouse runtime (replaces any earlier version, including a workspace/compute-pool one)
  EXECUTE IMMEDIATE 'CREATE OR REPLACE STREAMLIT ' || :app || ' FROM @' || :stg
                 || ' MAIN_FILE = ''streamlit_app.py'' QUERY_WAREHOUSE = ' || :wh
                 || ' RUNTIME_NAME = ''SYSTEM$WAREHOUSE_RUNTIME'' TITLE = ''' || :app || ''''
                 || ' COMMENT = ''Blinding control app. Warehouse runtime; the viewer is passed to the procedures (SP_ACTOR). Deployed by 04.''';
  EXECUTE IMMEDIATE 'ALTER STREAMLIT ' || :app || ' ADD LIVE VERSION FROM LAST';

  -- 3.3 the replace dropped the app's grants: every registered study's roles get them back (the one grant list)
  LET rs RESULTSET := (SELECT ROLE_PREFIX FROM STUDY_REGISTRY WHERE ACTIVE ORDER BY STUDY_OID);
  LET c CURSOR FOR rs;
  FOR s IN c DO
    LET p STRING := s.ROLE_PREFIX;
    LET r STRING := '';
    CALL SP_GRANT_STUDY_ACCESS(:p, :db, :sch, :wh, :feed, :app) INTO :r;
    out := :out || ' | ' || :r;
  END FOR;
  RETURN 'OK: ' || :app || ' deployed on the warehouse runtime' || :out;
END;

DESC STREAMLIT IDENTIFIER($APP);   -- expect main_file streamlit_app.py, query_warehouse ODM_BLINDING_WH, no compute pool

-- END. Section 3's result lists, per study, "including USAGE on BLINDING_APP". Open Projects > Streamlit > BLINDING_APP:
--      the sidebar must show YOUR login (if it shows another name, the app stops itself: identity guard).