-- =============================================================================
-- 02b_study_onboard.sql
-- WHAT   Brings ONE study under the mechanism:
--          roles      <PREFIX>_{STAT,PROG,DM}_{BLINDED,UNBLINDED}, <PREFIX>_ADHOC_BLINDED   7 working roles
--                     <PREFIX>_GOVERNANCE    approves access and rules; owns the 7 working roles
--                     <PREFIX>_LINE_MANAGER  requests access
--          grants     SP_GRANT_STUDY_ACCESS (02a): the one list of what the study's roles may reach
--          people     governance lead(s) and line managers appointed
--          registry   the study's STUDY_REGISTRY row
--          procedure  <PREFIX>_SP_SET_WORKING_ROLE, owned by governance: the only code that grants a working role
--                     (called by the app's procedures on approval / suspension / expiry)
--        It ends with no rules and no access: every value BLINDED until the first rules proposal is approved.
-- ROLES  Section 1 USERADMIN · Section 2 SYSADMIN · Section 3 <PREFIX>_GOVERNANCE · Section 4 SYSADMIN
-- NEEDS  02a_account_build.sql. The person running Section 3 is one of GOV_USERS.
-- RUN    Set Section 0, Run All. New study: change Section 0, Run All. Re-runnable. CHECKS: 03_checks.sql
-- =============================================================================


-- Section 0 PARAMETERS -----------------------------------------------------------------
SET BUILD_ROLE   = 'SYSADMIN';
SET ROLE_CREATOR = 'USERADMIN';
SET WH           = 'ODM_BLINDING_WH';
SET DB           = 'DEV_MEDIDATA_ODM_DATA_PRODUCT';
SET SCHEMA       = 'RAW_ODM';
SET FEED_VIEW    = 'SV_PATIENT_ITEM_DATA';
SET APP          = 'BLINDING_APP';                  -- the Streamlit app (04); granted to the study's roles if deployed

SET STUDY_OID    = 'IMC-F106C-101';                 -- exactly as the feed spells it
SET ROLE_PREFIX  = 'CT_IMC_F106C_101';              -- A-Z 0-9 _ only
SET BLIND_PLAN   = 'BP-101 v1.0';
SET GOV_USERS    = 'KAPPANURAG';                    -- governance lead(s): Snowflake user names, comma separated
SET LM_USERS     = 'SAM_ADAM,MICHELLE_PERRY';       -- line managers, comma separated

SET FQ_SCHEMA = $DB || '.' || $SCHEMA;
SET GOV_ROLE  = $ROLE_PREFIX || '_GOVERNANCE';
SET LM_ROLE   = $ROLE_PREFIX || '_LINE_MANAGER';


-- Section 1 USERADMIN: create the study's 9 roles and hand each to its owner -------------
--   Working roles -> owned by GOVERNANCE (it alone hands them out). GOVERNANCE, LINE_MANAGER -> owned by SYSADMIN.
--   Neither GOVERNANCE nor LINE_MANAGER is granted to SYSADMIN: SYSADMIN does not inherit them.
--   A role already handed over is left as it is (re-run safe).
USE ROLE IDENTIFIER($ROLE_CREATOR);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
BEGIN
  LET p   STRING := (SELECT $ROLE_PREFIX);
  LET gov STRING := (SELECT $GOV_ROLE);
  LET sa  STRING := (SELECT $BUILD_ROLE);
  IF (NOT REGEXP_LIKE(:p, '^[A-Z][A-Z0-9_]*$')) THEN RETURN 'STOPPED: ROLE_PREFIX must be A-Z 0-9 _'; END IF;
  -- role suffix -> its owner. GOVERNANCE first: the working roles are handed to it.
  LET roles ARRAY := ARRAY_CONSTRUCT(
      ARRAY_CONSTRUCT('_GOVERNANCE',      :sa),
      ARRAY_CONSTRUCT('_LINE_MANAGER',    :sa),
      ARRAY_CONSTRUCT('_STAT_BLINDED',    :gov), ARRAY_CONSTRUCT('_STAT_UNBLINDED', :gov),
      ARRAY_CONSTRUCT('_PROG_BLINDED',    :gov), ARRAY_CONSTRUCT('_PROG_UNBLINDED', :gov),
      ARRAY_CONSTRUCT('_DM_BLINDED',      :gov), ARRAY_CONSTRUCT('_DM_UNBLINDED',   :gov),
      ARRAY_CONSTRUCT('_ADHOC_BLINDED',   :gov));
  LET out STRING := '';
  FOR i IN 0 TO ARRAY_SIZE(:roles) - 1 DO
    LET r     STRING := :p || GET(GET(:roles, :i), 0)::STRING;
    LET owner STRING := GET(GET(:roles, :i), 1)::STRING;
    LET now_owner STRING := '';
    EXECUTE IMMEDIATE 'CREATE ROLE IF NOT EXISTS ' || :r;
    EXECUTE IMMEDIATE 'SHOW ROLES LIKE ''' || :r || '''';
    SELECT MAX("owner") INTO :now_owner FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
    IF (:now_owner = CURRENT_ROLE()) THEN
      EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ROLE ' || :r || ' TO ROLE ' || :owner || ' REVOKE CURRENT GRANTS';
      now_owner := :owner;
    END IF;
    out := :out || ' | ' || :r || ' -> ' || :now_owner;
  END FOR;
  RETURN 'roles' || :out;
END;


-- Section 2 SYSADMIN: grants, appointments, registry ------------------------------------
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);

-- 2.1 What the study's roles may reach (the one list, 02a 1.6k)
CALL SP_GRANT_STUDY_ACCESS($ROLE_PREFIX, $DB, $SCHEMA, $WH, $FEED_VIEW, $APP);

-- 2.2 Appoint the governance lead(s) and line managers
BEGIN
  LET gov STRING := (SELECT $GOV_ROLE);   LET gov_users STRING := (SELECT $GOV_USERS);
  LET lm  STRING := (SELECT $LM_ROLE);    LET lm_users  STRING := (SELECT $LM_USERS);
  LET people ARRAY := ARRAY_CONSTRUCT(ARRAY_CONSTRUCT(:gov, :gov_users), ARRAY_CONSTRUCT(:lm, :lm_users));
  LET out STRING := '';
  FOR i IN 0 TO 1 DO
    LET r STRING := GET(GET(:people, :i), 0)::STRING;
    LET users ARRAY := SPLIT(GET(GET(:people, :i), 1)::STRING, ',');
    FOR j IN 0 TO ARRAY_SIZE(:users) - 1 DO
      LET u STRING := UPPER(TRIM(GET(:users, :j)::STRING));
      IF (:u <> '') THEN
        EXECUTE IMMEDIATE 'GRANT ROLE ' || :r || ' TO USER "' || :u || '"';
        out := :out || ' | ' || :u || ' -> ' || :r;
      END IF;
    END FOR;
  END FOR;
  RETURN 'appointed' || :out;
END;

-- 2.3 Register the study (once)
INSERT INTO STUDY_REGISTRY (STUDY_OID, ROLE_PREFIX, BLIND_PLAN)
SELECT $STUDY_OID, $ROLE_PREFIX, $BLIND_PLAN
WHERE NOT EXISTS (SELECT 1 FROM STUDY_REGISTRY WHERE STUDY_OID = $STUDY_OID);

-- 2.4 TEMPORARY: governance may create its role procedure (Section 3). Section 4 takes it back, so afterwards
--     governance can never replace that procedure's body.
GRANT CREATE PROCEDURE ON SCHEMA IDENTIFIER($FQ_SCHEMA) TO ROLE IDENTIFIER($GOV_ROLE);


-- Section 3 GOVERNANCE: the study's role procedure -----------------------------------------
--   Owned by governance (which owns the 7 working roles), so it is the only code that can grant them.
--   Gives a person exactly one working role of this study, or none ('NONE'): grants the new one first,
--   then revokes the other six. Refuses any role that is not one of this study's seven.
--   SYSADMIN may call it — only from the app's procedures (02a SP_SET_ROLE).
USE ROLE IDENTIFIER($GOV_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);
BEGIN
  LET proc STRING := (SELECT $ROLE_PREFIX || '_SP_SET_WORKING_ROLE');
  LET sa   STRING := (SELECT $BUILD_ROLE);
  LET body STRING := $$
BEGIN
  LET suffixes ARRAY := ARRAY_CONSTRUCT('_STAT_BLINDED', '_STAT_UNBLINDED', '_PROG_BLINDED', '_PROG_UNBLINDED',
                                        '_DM_BLINDED', '_DM_UNBLINDED', '_ADHOC_BLINDED');
  IF (NOT REGEXP_LIKE(COALESCE(P_USER, ''), '^[A-Z0-9_.@-]{1,255}$')) THEN RETURN 'REFUSED: invalid login'; END IF;
  IF (P_ROLE <> 'NONE' AND NOT ARRAY_CONTAINS(REPLACE(P_ROLE, P_PREFIX, '')::VARIANT, suffixes)) THEN
    RETURN 'REFUSED: ' || P_ROLE || ' is not a working role of this study';
  END IF;
  IF (P_ROLE <> 'NONE') THEN
    EXECUTE IMMEDIATE 'GRANT ROLE ' || P_ROLE || ' TO USER "' || P_USER || '"';
  END IF;
  FOR i IN 0 TO ARRAY_SIZE(suffixes) - 1 DO
    LET r VARCHAR := P_PREFIX || GET(suffixes, i)::VARCHAR;
    IF (r <> P_ROLE) THEN
      EXECUTE IMMEDIATE 'REVOKE ROLE ' || r || ' FROM USER "' || P_USER || '"';
    END IF;
  END FOR;
  RETURN 'OK: ' || P_USER || ' holds ' || IFF(P_ROLE = 'NONE', 'no working role', P_ROLE);
EXCEPTION WHEN OTHER THEN RETURN 'FAILED: ' || SQLERRM;
END;
$$;
  EXECUTE IMMEDIATE 'CREATE OR REPLACE PROCEDURE ' || :proc || '(P_PREFIX VARCHAR, P_USER VARCHAR, P_ROLE VARCHAR) '
                 || 'RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER AS ' || '$' || '$' || :body || '$' || '$';
  EXECUTE IMMEDIATE 'GRANT USAGE ON PROCEDURE ' || :proc || '(VARCHAR, VARCHAR, VARCHAR) TO ROLE ' || :sa;
  RETURN :proc || ' created; ' || :sa || ' may call it';
END;


-- Section 4 SYSADMIN: take back governance's CREATE PROCEDURE (granted in 2.4 for Section 3 only) -----------------
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;
REVOKE CREATE PROCEDURE ON SCHEMA IDENTIFIER($FQ_SCHEMA) FROM ROLE IDENTIFIER($GOV_ROLE);


-- END. Next: 03_checks.sql. (The app: 04_app_deploy.sql grants it to every registered study.)
