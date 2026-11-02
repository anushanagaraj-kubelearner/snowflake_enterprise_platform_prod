-- =============================================================================
-- 02a_account_build.sql
-- WHAT   The shared blinding mechanism, used by every study:
--          tables     STUDY_REGISTRY · ACCESS_REQUEST · ACCESS_DECISION · ACCESS_ACTIVE (the register)
--                     RULE_REQUEST · RULE_REQUEST_ROW · RULE_DECISION · BLINDING_RULE · ITEM_KEY_STATE · AUDIT_LOG
--          views      V_ACCESS_REQUEST_STATUS · V_RULE_REQUEST_STATUS · V_BLINDING_RULE_EFFECTIVE · V_ITEM_KEYS
--          stage      BLINDING_FILES (Excel uploads from the app, kept as evidence)
--          procedures the app's actions (Section 1.6) and SP_GRANT_STUDY_ACCESS (used by 02b and 04)
--          identity   SP_ACTOR decides who is acting: Snowflake's CURRENT_USER() when it is set (worksheets),
--                     otherwise the viewer the app passes (the deployed app, where CURRENT_USER() is empty)
--          policies   MASK_ITEM_VALUE on the feed view's value columns · RAP_STUDY_ACCESS on the row layer
-- ROLES  Section 1 SYSADMIN · Section 2 MASKING_ADMIN · Section 3 SYSADMIN
-- NEEDS  01_environment.sql
-- RUN    Set Section 0, Run All. Re-runnable: tables are kept; views, procedures and policy bodies are replaced.
-- CHECKS 03_checks.sql
--
-- WHO SEES WHAT (read by both policies; written only by the app's procedures)
--   rows/values only while the person USES the working role their register row names, for that study, today (London)
--   no matching row (or another role in use)                     -> no rows
--   ADHOC                                                        -> every value BLINDED
--   UNBLINDED                                                    -> every value
--   BLINDED                                                      -> value only where ITEM_KEY_STATE says CLEAR
-- Names inside procedure, view and policy bodies are unqualified: Snowflake resolves them in the
-- object's own schema (the schema set in Section 0).
-- =============================================================================


-- Section 0 PARAMETERS -----------------------------------------------------------------
SET BUILD_ROLE    = 'SYSADMIN';
SET MASKING_ROLE  = 'MASKING_ADMIN';
SET WH            = 'ODM_BLINDING_WH';
SET DB            = 'DEV_MEDIDATA_ODM_DATA_PRODUCT';
SET SCHEMA        = 'RAW_ODM';
SET FEED_VIEW     = 'SV_PATIENT_ITEM_DATA';
SET VALUE_COLUMNS = 'ITEM_VALUE,CODELIST_ITEM_UUID,CODELIST_ITEM_DECODE,MEAS_UNIT,MEAS_UNIT_UUID';   -- masked on the feed view

SET FQ_SCHEMA = $DB || '.' || $SCHEMA;


-- Section 1 SYSADMIN: tables, views, stage, procedures ----------------------------------
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);

-- 1.1 Studies under the mechanism (one row per study, written by 02b). LOCK_AT is touched by every change,
--     so changes to one study happen one at a time.
CREATE TABLE IF NOT EXISTS STUDY_REGISTRY (
    STUDY_OID   VARCHAR NOT NULL,              -- exactly as the feed spells it
    ROLE_PREFIX VARCHAR NOT NULL,              -- CT_<study>
    BLIND_PLAN  VARCHAR NOT NULL,
    ACTIVE      BOOLEAN DEFAULT TRUE,
    LOCK_AT     TIMESTAMP_TZ,
    CREATED_BY  VARCHAR DEFAULT CURRENT_USER(),
    CREATED_AT  TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP());

-- 1.2 Access: the line manager's signed request -> the governance lead's signed decision -> the register
CREATE TABLE IF NOT EXISTS ACCESS_REQUEST (            -- insert-only
    REQUEST_ID     VARCHAR NOT NULL,
    STUDY_OID      VARCHAR NOT NULL,
    USER_NAME      VARCHAR NOT NULL,                   -- the person getting access (Snowflake user name)
    PERSON_NAME    VARCHAR NOT NULL,
    ROLE_FUNCTION  VARCHAR NOT NULL,                   -- STAT | PROG | DM | ADHOC
    SIGHT          VARCHAR NOT NULL,                   -- BLINDED | UNBLINDED (ADHOC: BLINDED only)
    EFFECTIVE_FROM DATE    NOT NULL,                   -- inclusive, London date
    EFFECTIVE_TO   DATE    NOT NULL,                   -- inclusive
    JUSTIFICATION  VARCHAR NOT NULL,
    FORM_REF       VARCHAR NOT NULL,                   -- the signed access form this request records
    FORM_DATE      DATE    NOT NULL,                   -- the date that form was signed
    REQUESTED_BY   VARCHAR NOT NULL,
    SIGNATURE      VARCHAR NOT NULL,
    REQUESTED_AT   TIMESTAMP_TZ NOT NULL);
CREATE TABLE IF NOT EXISTS ACCESS_DECISION (           -- insert-only; one row per request
    REQUEST_ID VARCHAR NOT NULL,
    DECISION   VARCHAR NOT NULL,                       -- APPROVED | REJECTED
    COMMENT    VARCHAR,
    DECIDED_BY VARCHAR NOT NULL,
    SIGNATURE  VARCHAR NOT NULL,
    DECIDED_AT TIMESTAMP_TZ NOT NULL);
CREATE TABLE IF NOT EXISTS ACCESS_ACTIVE (             -- THE REGISTER: one row per person per study
    STUDY_OID      VARCHAR NOT NULL,
    USER_NAME      VARCHAR NOT NULL,
    PERSON_NAME    VARCHAR NOT NULL,
    ROLE_FUNCTION  VARCHAR NOT NULL,
    SIGHT          VARCHAR NOT NULL,
    EFFECTIVE_FROM DATE    NOT NULL,
    EFFECTIVE_TO   DATE    NOT NULL,
    ROLE_NAME      VARCHAR NOT NULL,                   -- the working role granted with it
    REQUEST_ID     VARCHAR NOT NULL,
    APPROVED_BY    VARCHAR NOT NULL,
    APPROVED_AT    TIMESTAMP_TZ NOT NULL);

-- 1.3 Rules: the governance lead enters a signed Blinding form (Excel or manual), applied at once with its decision row
--     -> BLINDING_RULE history -> ITEM_KEY_STATE (what the mask reads)
--     A rule BLINDS a form (ITEM_OID NULL) or an item: ACTION ADD puts it in force, REMOVE takes it out.
CREATE TABLE IF NOT EXISTS RULE_REQUEST (              -- insert-only
    RULE_REQUEST_ID  VARCHAR NOT NULL,
    STUDY_OID        VARCHAR NOT NULL,
    SOURCE           VARCHAR NOT NULL,                 -- EXCEL | MANUAL
    FORM_REF         VARCHAR NOT NULL,                 -- Blinding form reference
    FORM_SIGNED_DATE DATE    NOT NULL,
    FILE_NAME        VARCHAR,                          -- EXCEL: path on BLINDING_FILES
    FILE_MD5         VARCHAR,                          -- EXCEL: md5 read from the stage at proposal
    ROW_COUNT        NUMBER  NOT NULL,
    PROPOSED_BY      VARCHAR NOT NULL,
    PROPOSED_BY_NAME VARCHAR NOT NULL,
    SIGNATURE        VARCHAR NOT NULL,
    PROPOSED_AT      TIMESTAMP_TZ NOT NULL);
CREATE TABLE IF NOT EXISTS RULE_REQUEST_ROW (          -- insert-only
    RULE_REQUEST_ID VARCHAR NOT NULL,
    ROW_NO          NUMBER  NOT NULL,
    FORM_OID        VARCHAR NOT NULL,
    ITEM_OID        VARCHAR,                           -- NULL = whole form
    ACTION          VARCHAR NOT NULL,                  -- ADD (blind) | REMOVE (lift a rule) | CLEAR (new, reviewed: stays visible)
    REASON          VARCHAR NOT NULL);
CREATE TABLE IF NOT EXISTS RULE_DECISION (             -- insert-only; one row per proposal
    RULE_REQUEST_ID VARCHAR NOT NULL,
    DECISION        VARCHAR NOT NULL,                  -- APPROVED | REJECTED
    COMMENT         VARCHAR,
    DECIDED_BY      VARCHAR NOT NULL,
    SIGNATURE       VARCHAR NOT NULL,
    DECIDED_AT      TIMESTAMP_TZ NOT NULL);
CREATE TABLE IF NOT EXISTS BLINDING_RULE (             -- insert-only history of every approved ADD / REMOVE
    RULE_ID         NUMBER IDENTITY START 1 INCREMENT 1,
    STUDY_OID       VARCHAR NOT NULL,
    FORM_OID        VARCHAR NOT NULL,
    ITEM_OID        VARCHAR,
    ACTION          VARCHAR NOT NULL,                  -- ADD | REMOVE
    REASON          VARCHAR NOT NULL,
    RULE_REQUEST_ID VARCHAR NOT NULL,
    APPROVED_BY     VARCHAR NOT NULL,
    CREATED_AT      TIMESTAMP_TZ NOT NULL);
CREATE TABLE IF NOT EXISTS ITEM_KEY_STATE (            -- every form/item of a study: BLIND or CLEAR. A key not here is BLIND.
    STUDY_OID     VARCHAR NOT NULL,
    FORM_OID      VARCHAR NOT NULL,
    ITEM_OID      VARCHAR,
    STATE         VARCHAR NOT NULL,                    -- BLIND | CLEAR
    RULE_ID       NUMBER,                              -- the rule in force that blinds it
    CLASSIFIED_AT TIMESTAMP_TZ NOT NULL);

-- 1.4 Audit: every action, one hash chain per study (each ROW_HASH covers the row and the previous hash)
CREATE SEQUENCE IF NOT EXISTS BLINDING_SEQ;
CREATE TABLE IF NOT EXISTS AUDIT_LOG (
    EVENT_ID   NUMBER NOT NULL,
    EVENT_TS   TIMESTAMP_TZ NOT NULL,
    STUDY_OID  VARCHAR NOT NULL,
    EVENT_TYPE VARCHAR NOT NULL,
    ACTOR      VARCHAR NOT NULL,
    REF        VARCHAR,
    DETAIL     VARCHAR,
    PREV_HASH  VARCHAR NOT NULL,
    ROW_HASH   VARCHAR NOT NULL);
CREATE OR REPLACE FUNCTION UF_AUDIT_HASH(P_PREV VARCHAR, P_ID NUMBER, P_TS TIMESTAMP_TZ, P_STUDY VARCHAR, P_TYPE VARCHAR,
                                         P_ACTOR VARCHAR, P_REF VARCHAR, P_DETAIL VARCHAR)
RETURNS VARCHAR
AS $$ SHA2(TO_JSON(ARRAY_CONSTRUCT(P_PREV, P_ID, TO_VARCHAR(P_TS, 'YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM'),
                                   P_STUDY, P_TYPE, P_ACTOR, P_REF, P_DETAIL)), 256) $$;

-- 1.5 Views and stage
CREATE OR REPLACE VIEW V_ACCESS_REQUEST_STATUS AS     -- PENDING | APPROVED | REJECTED | EXPIRED
SELECT r.*, d.DECISION, d.COMMENT AS DECISION_COMMENT, d.DECIDED_BY, d.DECIDED_AT,
       CASE WHEN d.DECISION IS NOT NULL THEN d.DECISION
            WHEN r.EFFECTIVE_TO < CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE THEN 'EXPIRED'
            ELSE 'PENDING' END AS STATUS
FROM ACCESS_REQUEST r LEFT JOIN ACCESS_DECISION d ON d.REQUEST_ID = r.REQUEST_ID;

CREATE OR REPLACE VIEW V_RULE_REQUEST_STATUS AS       -- PENDING | APPROVED | REJECTED
SELECT q.*, d.DECISION, d.COMMENT AS DECISION_COMMENT, d.DECIDED_BY, d.DECIDED_AT, COALESCE(d.DECISION, 'PENDING') AS STATUS
FROM RULE_REQUEST q LEFT JOIN RULE_DECISION d ON d.RULE_REQUEST_ID = q.RULE_REQUEST_ID;

CREATE OR REPLACE VIEW V_BLINDING_RULE_EFFECTIVE AS   -- rules in force: latest row per study/form/item, kept if ADD
SELECT * FROM BLINDING_RULE
QUALIFY ROW_NUMBER() OVER (PARTITION BY STUDY_OID, FORM_OID, COALESCE(ITEM_OID, '~FORM~') ORDER BY RULE_ID DESC) = 1
    AND ACTION = 'ADD';

CREATE OR REPLACE VIEW V_ITEM_KEYS AS                 -- every real study/form/item in the feed, no values
SELECT STUDY_OID, FORM_OID, ITEM_OID, COUNT(*) AS ROWS_TOTAL
FROM POC_PATIENT_ITEM_DATA
WHERE FORM_OID IS NOT NULL
GROUP BY STUDY_OID, FORM_OID, ITEM_OID;

CREATE STAGE IF NOT EXISTS BLINDING_FILES DIRECTORY = (ENABLE = TRUE) ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE')
  COMMENT = 'Rule workbooks uploaded through the app; read by SP_APPLY_RULES and kept as evidence.';

-- 1.6 Procedures. All SYSADMIN-owned, EXECUTE AS OWNER, called by the app (owned by SYSADMIN); granted to nobody else.
--     Each acts as the person SP_ACTOR names and returns 'OK: …', 'REFUSED: …' or 'FAILED: …'.
--     The app actions take P_VIEWER last: the app passes the logged-in viewer; a worksheet caller passes NULL.
--     Old signatures (without P_VIEWER) are dropped so only one version of each exists.
DROP PROCEDURE IF EXISTS SP_AUDIT(VARCHAR, VARCHAR, VARCHAR, VARCHAR);
DROP PROCEDURE IF EXISTS SP_REQUEST_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, DATE, DATE, VARCHAR, VARCHAR, DATE, BOOLEAN);
DROP PROCEDURE IF EXISTS SP_REQUEST_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, DATE, DATE, VARCHAR, BOOLEAN);   -- earlier, before form ref/date
DROP PROCEDURE IF EXISTS SP_DECIDE_ACCESS(VARCHAR, VARCHAR, VARCHAR, BOOLEAN);
DROP PROCEDURE IF EXISTS SP_SUSPEND_ACCESS(VARCHAR, VARCHAR, VARCHAR);
DROP PROCEDURE IF EXISTS SP_END_EXPIRED(VARCHAR);
DROP PROCEDURE IF EXISTS SP_APPLY_RULES(VARCHAR, VARCHAR, VARCHAR, DATE, VARCHAR, VARCHAR, BOOLEAN);
DROP PROCEDURE IF EXISTS SP_SET_LINE_MANAGER(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, BOOLEAN);
DROP PROCEDURE IF EXISTS SP_REBUILD_KEY_STATE(VARCHAR);                                  -- now takes the entry (#3)

-- 1.6.0 Internal: who is acting. The one place this rule lives.
--   CURRENT_USER() set (worksheet)          -> that user; a different P_VIEWER is refused (no impersonation from a worksheet)
--   CURRENT_USER() empty (deployed app)     -> P_VIEWER, the viewer Streamlit reports
--   neither                                 -> NULL: every action refuses
--   Names are compared exactly, never case-changed, and must be upper case (A-Z 0-9 _ . @ -): a quoted lower-case
--   login is refused on every path, so two users ("alice" and ALICE) can never be taken for one another.
CREATE OR REPLACE PROCEDURE SP_ACTOR(P_VIEWER VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE cu VARCHAR; v VARCHAR;
BEGIN
  cu := CURRENT_USER();
  v  := NULLIF(TRIM(COALESCE(P_VIEWER, '')), '');
  IF (cu IS NOT NULL AND NOT REGEXP_LIKE(cu, '^[A-Z0-9_.@-]{1,255}$')) THEN RETURN NULL; END IF;
  IF (v  IS NOT NULL AND NOT REGEXP_LIKE(v,  '^[A-Z0-9_.@-]{1,255}$')) THEN RETURN NULL; END IF;
  IF (cu IS NOT NULL AND v IS NOT NULL AND v <> cu) THEN RETURN NULL; END IF;
  RETURN COALESCE(cu, v);
END;
$$;

-- 1.6a Internal: write one audit event
--      ACTOR comes from SP_ACTOR: if nobody can be identified the insert fails (ACTOR is NOT NULL) and the caller rolls back.
CREATE OR REPLACE PROCEDURE SP_AUDIT(P_STUDY VARCHAR, P_TYPE VARCHAR, P_REF VARCHAR, P_DETAIL VARCHAR, P_VIEWER VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE prev VARCHAR; id NUMBER; ts TIMESTAMP_TZ; actor VARCHAR;
BEGIN
  CALL SP_ACTOR(:P_VIEWER) INTO :actor;
  SELECT COALESCE(MAX_BY(ROW_HASH, EVENT_ID), 'GENESIS') INTO :prev FROM AUDIT_LOG WHERE STUDY_OID = :P_STUDY;
  SELECT BLINDING_SEQ.NEXTVAL, CURRENT_TIMESTAMP() INTO :id, :ts;
  INSERT INTO AUDIT_LOG
  SELECT :id, :ts, :P_STUDY, :P_TYPE, :actor, :P_REF, :P_DETAIL, :prev,
         UF_AUDIT_HASH(:prev, :id, :ts, :P_STUDY, :P_TYPE, :actor, :P_REF, :P_DETAIL);
  RETURN 'OK';
END;
$$;

-- 1.6b Internal: does this user hold this role (granted directly)
CREATE OR REPLACE PROCEDURE SP_HOLDS_ROLE(P_USER VARCHAR, P_ROLE VARCHAR)
RETURNS BOOLEAN LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE n NUMBER DEFAULT 0;
BEGIN
  IF (NOT REGEXP_LIKE(COALESCE(P_ROLE, ''), '^[A-Z][A-Z0-9_]*$')) THEN RETURN FALSE; END IF;
  EXECUTE IMMEDIATE 'SHOW GRANTS OF ROLE ' || P_ROLE;
  SELECT COUNT(*) INTO :n FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "granted_to" = 'USER' AND "grantee_name" = :P_USER;
  RETURN n > 0;
EXCEPTION WHEN OTHER THEN RETURN FALSE;
END;
$$;

-- 1.6c Internal: re-classify a study's keys from the rules in force (BLIND if a rule covers it, else CLEAR).
--      New keys are classified only if THIS entry names them with an ADD or CLEAR row (P_ENTRY): a key no signed entry
--      names stays absent = BLIND for blinded users. Then every classified row of the study (in the feed or not) is
--      re-derived from the rules in force, so no stale CLEAR survives a rule change.
CREATE OR REPLACE PROCEDURE SP_REBUILD_KEY_STATE(P_STUDY VARCHAR, P_ENTRY VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
BEGIN
  -- 1) keys THIS entry names with an ADD or CLEAR row (whole form = every key of the form), inserted or updated
  MERGE INTO ITEM_KEY_STATE t
  USING (SELECT n.STUDY_OID, n.FORM_OID, n.ITEM_OID, IFF(MAX(r.RULE_ID) IS NULL, 'CLEAR', 'BLIND') AS STATE, MAX(r.RULE_ID) AS RULE_ID
           FROM (SELECT DISTINCT k.STUDY_OID, k.FORM_OID, k.ITEM_OID
                   FROM V_ITEM_KEYS k
                   JOIN RULE_REQUEST_ROW w
                     ON w.FORM_OID = k.FORM_OID AND (w.ITEM_OID IS NULL OR w.ITEM_OID = k.ITEM_OID)
                  WHERE k.STUDY_OID = :P_STUDY AND w.RULE_REQUEST_ID = :P_ENTRY AND w.ACTION IN ('ADD', 'CLEAR')) n
           LEFT JOIN V_BLINDING_RULE_EFFECTIVE r
                  ON r.STUDY_OID = n.STUDY_OID AND r.FORM_OID = n.FORM_OID AND (r.ITEM_OID IS NULL OR r.ITEM_OID = n.ITEM_OID)
          GROUP BY n.STUDY_OID, n.FORM_OID, n.ITEM_OID) src
     ON t.STUDY_OID = src.STUDY_OID AND t.FORM_OID = src.FORM_OID AND EQUAL_NULL(t.ITEM_OID, src.ITEM_OID)
  WHEN MATCHED THEN UPDATE SET t.STATE = src.STATE, t.RULE_ID = src.RULE_ID, t.CLASSIFIED_AT = CURRENT_TIMESTAMP()
  WHEN NOT MATCHED THEN INSERT (STUDY_OID, FORM_OID, ITEM_OID, STATE, RULE_ID, CLASSIFIED_AT)
                        VALUES (src.STUDY_OID, src.FORM_OID, src.ITEM_OID, src.STATE, src.RULE_ID, CURRENT_TIMESTAMP());
  -- 2) every classified row of the study, including keys not in the feed right now
  UPDATE ITEM_KEY_STATE t
     SET STATE = IFF(x.RID IS NULL, 'CLEAR', 'BLIND'), RULE_ID = x.RID, CLASSIFIED_AT = CURRENT_TIMESTAMP()
    FROM (SELECT s.STUDY_OID, s.FORM_OID, s.ITEM_OID, MAX(r.RULE_ID) AS RID
            FROM ITEM_KEY_STATE s
            LEFT JOIN V_BLINDING_RULE_EFFECTIVE r
                   ON r.STUDY_OID = s.STUDY_OID AND r.FORM_OID = s.FORM_OID AND (r.ITEM_OID IS NULL OR r.ITEM_OID = s.ITEM_OID)
           WHERE s.STUDY_OID = :P_STUDY
           GROUP BY s.STUDY_OID, s.FORM_OID, s.ITEM_OID) x
   WHERE t.STUDY_OID = x.STUDY_OID AND t.FORM_OID = x.FORM_OID AND EQUAL_NULL(t.ITEM_OID, x.ITEM_OID)
     AND (t.STATE <> IFF(x.RID IS NULL, 'CLEAR', 'BLIND') OR NOT EQUAL_NULL(t.RULE_ID, x.RID));
  RETURN 'OK';
END;
$$;

-- 1.6d Internal: give a person the study's working role (or none) via the study's governance procedure (02b)
CREATE OR REPLACE PROCEDURE SP_SET_ROLE(P_STUDY VARCHAR, P_USER VARCHAR, P_ROLE VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE prefix VARCHAR; usr VARCHAR; role_name VARCHAR; res VARCHAR; n NUMBER DEFAULT 0; owned NUMBER DEFAULT 0;
BEGIN
  usr := P_USER; role_name := P_ROLE;
  SELECT MAX(ROLE_PREFIX) INTO :prefix FROM STUDY_REGISTRY WHERE STUDY_OID = :P_STUDY;
  IF (prefix IS NULL) THEN RETURN 'FAILED: study not registered'; END IF;
  -- exactly one version, owned by the study's governance role (governance holds no CREATE PROCEDURE after 02b, so
  -- it cannot replace the body; anything else of that name is refused)
  SELECT COUNT(*), COUNT_IF(PROCEDURE_OWNER = :prefix || '_GOVERNANCE') INTO :n, :owned
    FROM INFORMATION_SCHEMA.PROCEDURES
   WHERE PROCEDURE_SCHEMA = CURRENT_SCHEMA() AND PROCEDURE_NAME = :prefix || '_SP_SET_WORKING_ROLE';
  IF (n <> 1 OR owned <> 1) THEN RETURN 'FAILED: the study''s role procedure is missing or not owned by its governance role'; END IF;
  EXECUTE IMMEDIATE 'CALL ' || prefix || '_SP_SET_WORKING_ROLE(?, ?, ?)' USING (prefix, usr, role_name);
  SELECT $1 INTO :res FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
  RETURN res;
EXCEPTION WHEN OTHER THEN RETURN 'FAILED: ' || SQLERRM;
END;
$$;

-- 1.6e APP · line manager requests access for a team member
CREATE OR REPLACE PROCEDURE SP_REQUEST_ACCESS(P_STUDY VARCHAR, P_USER VARCHAR, P_PERSON VARCHAR, P_FUNCTION VARCHAR, P_SIGHT VARCHAR,
                                              P_FROM DATE, P_TO DATE, P_JUSTIFICATION VARCHAR, P_FORM_REF VARCHAR, P_FORM_DATE DATE,
                                              P_SIGNED BOOLEAN, P_VIEWER VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE me VARCHAR; usr VARCHAR; fn VARCHAR; sight VARCHAR; today DATE; prefix VARCHAR; ok BOOLEAN; n NUMBER; id VARCHAR; sig VARCHAR;
BEGIN
  CALL SP_ACTOR(:P_VIEWER) INTO :me;
  IF (me IS NULL) THEN RETURN 'REFUSED: you could not be identified'; END IF;
  usr := UPPER(TRIM(COALESCE(P_USER, ''))); fn := UPPER(TRIM(COALESCE(P_FUNCTION, ''))); sight := UPPER(TRIM(COALESCE(P_SIGHT, '')));
  today := CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE;
  SELECT MAX(ROLE_PREFIX) INTO :prefix FROM STUDY_REGISTRY WHERE STUDY_OID = :P_STUDY AND ACTIVE;
  IF (prefix IS NULL)                                      THEN RETURN 'REFUSED: study is not under blinding'; END IF;
  IF (NOT REGEXP_LIKE(usr, '^[A-Z0-9_.@-]{1,255}$'))        THEN RETURN 'REFUSED: login missing or invalid'; END IF;
  IF (usr = me)                                            THEN RETURN 'REFUSED: you cannot request access for yourself'; END IF;
  IF (COALESCE(TRIM(P_PERSON), '') = '')                   THEN RETURN 'REFUSED: name is empty'; END IF;
  IF (fn NOT IN ('STAT', 'PROG', 'DM', 'ADHOC'))           THEN RETURN 'REFUSED: function must be STAT, PROG, DM or ADHOC'; END IF;
  IF (sight NOT IN ('BLINDED', 'UNBLINDED'))               THEN RETURN 'REFUSED: sight must be BLINDED or UNBLINDED'; END IF;
  IF (fn = 'ADHOC' AND sight = 'UNBLINDED')                THEN RETURN 'REFUSED: ADHOC is blinded only'; END IF;
  IF (P_FROM IS NULL OR P_TO IS NULL OR P_TO < P_FROM)     THEN RETURN 'REFUSED: dates missing or end before start'; END IF;
  IF (P_TO < today)                                        THEN RETURN 'REFUSED: the period has already ended'; END IF;
  IF (DATEDIFF('day', P_FROM, P_TO) > 365)                 THEN RETURN 'REFUSED: at most 366 days (inclusive) per approval'; END IF;
  IF (LENGTH(TRIM(COALESCE(P_JUSTIFICATION, ''))) < 10)    THEN RETURN 'REFUSED: justification under 10 characters'; END IF;
  IF (COALESCE(TRIM(P_FORM_REF), '') = '')                 THEN RETURN 'REFUSED: access form reference is empty'; END IF;
  IF (P_FORM_DATE IS NULL OR P_FORM_DATE > today)          THEN RETURN 'REFUSED: access form date missing or in the future'; END IF;
  IF (NOT COALESCE(P_SIGNED, FALSE))                       THEN RETURN 'REFUSED: signature not confirmed'; END IF;
  CALL SP_HOLDS_ROLE(:me, :prefix || '_LINE_MANAGER') INTO :ok;
  IF (NOT ok) THEN RETURN 'REFUSED: you are not a line manager on ' || P_STUDY; END IF;

  BEGIN TRANSACTION;
  UPDATE STUDY_REGISTRY SET LOCK_AT = CURRENT_TIMESTAMP() WHERE STUDY_OID = :P_STUDY;
  SELECT COUNT(*) INTO :n FROM V_ACCESS_REQUEST_STATUS WHERE STUDY_OID = :P_STUDY AND USER_NAME = :usr AND STATUS = 'PENDING';
  IF (n > 0) THEN ROLLBACK; RETURN 'REFUSED: ' || usr || ' already has a pending request'; END IF;
  SELECT 'AR-' || LPAD(BLINDING_SEQ.NEXTVAL::VARCHAR, 8, '0') INTO :id;
  sig := me || ' (line manager) requests ' || fn || ' ' || sight || ' on ' || P_STUDY || ' for ' || TRIM(P_PERSON)
         || ' (' || usr || ') from ' || P_FROM || ' to ' || P_TO || ', per access form ' || TRIM(P_FORM_REF)
         || ' signed ' || P_FORM_DATE || '. Electronic signature.';
  INSERT INTO ACCESS_REQUEST VALUES (:id, :P_STUDY, :usr, TRIM(:P_PERSON), :fn, :sight, :P_FROM, :P_TO,
                                     TRIM(:P_JUSTIFICATION), TRIM(:P_FORM_REF), :P_FORM_DATE, :me, :sig, CURRENT_TIMESTAMP());
  CALL SP_AUDIT(:P_STUDY, 'ACCESS_REQUESTED', :id, :sig, :me);
  COMMIT;
  RETURN 'OK: ' || id || ' sent to the governance lead';
EXCEPTION WHEN OTHER THEN ROLLBACK; RETURN 'FAILED: ' || SQLERRM;
END;
$$;

-- 1.6f APP · governance lead approves (role granted + register row) or rejects
--      Order: role first (a role without a register row shows nothing), then the register. A failure leaves less access.
CREATE OR REPLACE PROCEDURE SP_DECIDE_ACCESS(P_REQUEST_ID VARCHAR, P_DECISION VARCHAR, P_COMMENT VARCHAR, P_SIGNED BOOLEAN, P_VIEWER VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE me VARCHAR; decision VARCHAR; ok BOOLEAN; st VARCHAR; study VARCHAR; prefix VARCHAR; req_by VARCHAR; usr VARCHAR;
        person VARCHAR; fn VARCHAR; sight VARCHAR; d_from DATE; d_to DATE; role_name VARCHAR; res VARCHAR; sig VARCHAR; form_ref VARCHAR;
BEGIN
  CALL SP_ACTOR(:P_VIEWER) INTO :me;
  IF (me IS NULL) THEN RETURN 'REFUSED: you could not be identified'; END IF;
  decision := UPPER(TRIM(COALESCE(P_DECISION, '')));
  IF (decision NOT IN ('APPROVED', 'REJECTED'))  THEN RETURN 'REFUSED: decision must be APPROVED or REJECTED'; END IF;
  IF (NOT COALESCE(P_SIGNED, FALSE))             THEN RETURN 'REFUSED: signature not confirmed'; END IF;
  IF (decision = 'REJECTED' AND LENGTH(TRIM(COALESCE(P_COMMENT, ''))) < 5) THEN RETURN 'REFUSED: a rejection needs a comment'; END IF;
  SELECT MAX(r.STUDY_OID), MAX(s.ROLE_PREFIX), MAX(r.REQUESTED_BY), MAX(r.USER_NAME), MAX(r.PERSON_NAME), MAX(r.ROLE_FUNCTION),
         MAX(r.SIGHT), MAX(r.EFFECTIVE_FROM), MAX(r.EFFECTIVE_TO), MAX(r.STATUS), MAX(r.FORM_REF)
    INTO :study, :prefix, :req_by, :usr, :person, :fn, :sight, :d_from, :d_to, :st, :form_ref
    FROM V_ACCESS_REQUEST_STATUS r JOIN STUDY_REGISTRY s ON s.STUDY_OID = r.STUDY_OID AND s.ACTIVE
   WHERE r.REQUEST_ID = :P_REQUEST_ID;
  IF (study IS NULL)   THEN RETURN 'REFUSED: request ' || P_REQUEST_ID || ' not found, or its study is not active'; END IF;
  CALL SP_HOLDS_ROLE(:me, :prefix || '_GOVERNANCE') INTO :ok;
  IF (NOT ok)          THEN RETURN 'REFUSED: you are not the governance lead on ' || study; END IF;
  IF (me = req_by)     THEN RETURN 'REFUSED: you submitted this request; another governance lead must decide'; END IF;
  IF (me = usr)        THEN RETURN 'REFUSED: you cannot decide your own access'; END IF;
  IF (st <> 'PENDING') THEN RETURN 'REFUSED: ' || P_REQUEST_ID || ' is ' || st; END IF;
  role_name := prefix || '_' || fn || '_' || sight;
  sig := me || ' (governance lead) ' || decision || ' ' || P_REQUEST_ID || ': ' || fn || ' ' || sight || ' on ' || study
         || ' for ' || usr || ' from ' || d_from || ' to ' || d_to || ', checked against access form ' || form_ref
         || '. Electronic signature.';

  IF (decision = 'APPROVED') THEN
    CALL SP_SET_ROLE(:study, :usr, :role_name) INTO :res;
    IF (NOT STARTSWITH(COALESCE(res, ''), 'OK')) THEN RETURN 'FAILED: role not granted — ' || COALESCE(res, 'no result'); END IF;
  END IF;
  BEGIN TRANSACTION;
  UPDATE STUDY_REGISTRY SET LOCK_AT = CURRENT_TIMESTAMP() WHERE STUDY_OID = :study;
  SELECT STATUS INTO :st FROM V_ACCESS_REQUEST_STATUS WHERE REQUEST_ID = :P_REQUEST_ID;
  IF (st <> 'PENDING') THEN ROLLBACK; RETURN 'REFUSED: ' || P_REQUEST_ID || ' was decided meanwhile'; END IF;
  INSERT INTO ACCESS_DECISION VALUES (:P_REQUEST_ID, :decision, NULLIF(TRIM(:P_COMMENT), ''), :me, :sig, CURRENT_TIMESTAMP());
  IF (decision = 'APPROVED') THEN
    DELETE FROM ACCESS_ACTIVE WHERE STUDY_OID = :study AND USER_NAME = :usr;
    INSERT INTO ACCESS_ACTIVE VALUES (:study, :usr, :person, :fn, :sight, :d_from, :d_to, :role_name, :P_REQUEST_ID, :me, CURRENT_TIMESTAMP());
  END IF;
  CALL SP_AUDIT(:study, 'ACCESS_' || :decision, :P_REQUEST_ID, :sig, :me);
  COMMIT;
  RETURN 'OK: ' || P_REQUEST_ID || ' ' || decision || IFF(decision = 'APPROVED', ' — ' || usr || ' holds ' || role_name, '');
EXCEPTION WHEN OTHER THEN ROLLBACK; RETURN 'FAILED: ' || SQLERRM;
END;
$$;

-- 1.6g APP · remove access now (governance lead, or the person themselves); also closes their pending requests
CREATE OR REPLACE PROCEDURE SP_SUSPEND_ACCESS(P_STUDY VARCHAR, P_USER VARCHAR, P_REASON VARCHAR, P_VIEWER VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE me VARCHAR; usr VARCHAR; prefix VARCHAR; ok BOOLEAN; res VARCHAR; sig VARCHAR;
BEGIN
  CALL SP_ACTOR(:P_VIEWER) INTO :me;
  IF (me IS NULL) THEN RETURN 'REFUSED: you could not be identified'; END IF;
  usr := UPPER(TRIM(COALESCE(P_USER, '')));
  SELECT MAX(ROLE_PREFIX) INTO :prefix FROM STUDY_REGISTRY WHERE STUDY_OID = :P_STUDY;
  IF (prefix IS NULL)                            THEN RETURN 'REFUSED: study is not under blinding'; END IF;
  IF (LENGTH(TRIM(COALESCE(P_REASON, ''))) < 5)  THEN RETURN 'REFUSED: give a reason'; END IF;
  CALL SP_HOLDS_ROLE(:me, :prefix || '_GOVERNANCE') INTO :ok;
  IF (me <> usr AND NOT ok) THEN RETURN 'REFUSED: only the governance lead or the person themselves can suspend'; END IF;
  sig := me || ' suspended ' || usr || ' on ' || P_STUDY || ': ' || TRIM(P_REASON);

  BEGIN TRANSACTION;
  UPDATE STUDY_REGISTRY SET LOCK_AT = CURRENT_TIMESTAMP() WHERE STUDY_OID = :P_STUDY;
  DELETE FROM ACCESS_ACTIVE WHERE STUDY_OID = :P_STUDY AND USER_NAME = :usr;
  INSERT INTO ACCESS_DECISION
  SELECT REQUEST_ID, 'REJECTED', 'Closed by suspension', :me, :sig, CURRENT_TIMESTAMP()
    FROM V_ACCESS_REQUEST_STATUS WHERE STUDY_OID = :P_STUDY AND USER_NAME = :usr AND STATUS = 'PENDING';
  CALL SP_AUDIT(:P_STUDY, 'ACCESS_SUSPENDED', :usr, :sig, :me);
  COMMIT;
  CALL SP_SET_ROLE(:P_STUDY, :usr, 'NONE') INTO :res;     -- after the register: the row is already gone
  IF (NOT STARTSWITH(COALESCE(res, ''), 'OK')) THEN
    RETURN 'FAILED: register row removed (no data visible), but the role was not revoked — ' || COALESCE(res, 'no result');
  END IF;
  RETURN 'OK: ' || usr || ' has no access to ' || P_STUDY || ' (' || res || ')';
EXCEPTION WHEN OTHER THEN ROLLBACK; RETURN 'FAILED: ' || SQLERRM;
END;
$$;

-- 1.6h APP · governance lead tidies a study: register rows past their end date removed, roles revoked
CREATE OR REPLACE PROCEDURE SP_END_EXPIRED(P_STUDY VARCHAR, P_VIEWER VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE me VARCHAR; prefix VARCHAR; ok BOOLEAN; res VARCHAR; done NUMBER DEFAULT 0; problems VARCHAR DEFAULT '';
BEGIN
  CALL SP_ACTOR(:P_VIEWER) INTO :me;
  IF (me IS NULL) THEN RETURN 'REFUSED: you could not be identified'; END IF;
  SELECT MAX(ROLE_PREFIX) INTO :prefix FROM STUDY_REGISTRY WHERE STUDY_OID = :P_STUDY;
  CALL SP_HOLDS_ROLE(:me, :prefix || '_GOVERNANCE') INTO :ok;
  IF (NOT ok) THEN RETURN 'REFUSED: you are not the governance lead on ' || P_STUDY; END IF;
  LET rs RESULTSET := (SELECT USER_NAME FROM ACCESS_ACTIVE
                        WHERE STUDY_OID = :P_STUDY AND EFFECTIVE_TO < CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE);
  LET c CURSOR FOR rs;
  FOR x IN c DO
    LET usr VARCHAR := x.USER_NAME;
    LET gone NUMBER := 0;
    BEGIN TRANSACTION;                                     -- the row goes only with its audit row
    DELETE FROM ACCESS_ACTIVE WHERE STUDY_OID = :P_STUDY AND USER_NAME = :usr
       AND EFFECTIVE_TO < CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE;   -- a fresh approval is not touched
    gone := SQLROWCOUNT;
    IF (gone > 0) THEN
      CALL SP_AUDIT(:P_STUDY, 'ACCESS_EXPIRED', :usr, 'end date passed; removed by ' || :me, :me);
    END IF;
    COMMIT;
    IF (gone > 0) THEN
      CALL SP_SET_ROLE(:P_STUDY, :usr, 'NONE') INTO :res;     -- after the commit (GRANT/REVOKE would end the transaction)
      IF (NOT STARTSWITH(COALESCE(res, ''), 'OK')) THEN problems := problems || ' | ' || usr || ': ' || COALESCE(res, 'no result'); END IF;
      done := done + 1;
    END IF;
  END FOR;
  IF (problems <> '') THEN RETURN 'FAILED: ' || done || ' expired row(s) removed, but a role was not revoked' || problems; END IF;
  RETURN 'OK: ' || done || ' expired access row(s) removed on ' || P_STUDY;
EXCEPTION WHEN OTHER THEN ROLLBACK; RETURN 'FAILED: ' || SQLERRM;
END;
$$;

-- 1.6i APP · governance lead applies the rules recorded on a signed Blinding form: an uploaded workbook (read here,
--      from the stage) or manual rows (JSON). Rules are decided in the blinding meeting and recorded on that form; the
--      form's signatures are the approval, so the entry is applied at once: request + rows + decision + rules +
--      key state + audit, all or nothing.
--      Workbook: sheet RULES, headers FORM_OID | ITEM_OID | ACTION | REASON. ITEM_OID blank = whole form.
--      ACTION: ADD (blind) · REMOVE (lift a rule in force) · CLEAR (a form/item new in the feed, reviewed: stays visible).
--      Every form/item not yet classified must be named by an ADD or CLEAR row (whole form or the item), or the entry is
--      refused — also a new item on a form blinded as a whole (CLEAR on the item keeps it BLIND under that rule).
--      Checks run under the study lock. The person applying it must hold no data access on the study.
DROP PROCEDURE IF EXISTS SP_PROPOSE_RULES(VARCHAR, VARCHAR, VARCHAR, DATE, VARCHAR, VARCHAR, BOOLEAN);   -- replaced by SP_APPLY_RULES
DROP PROCEDURE IF EXISTS SP_DECIDE_RULES(VARCHAR, VARCHAR, VARCHAR, BOOLEAN);                             -- no second step any more
CREATE OR REPLACE PROCEDURE SP_APPLY_RULES(P_STUDY VARCHAR, P_NAME VARCHAR, P_FORM_REF VARCHAR, P_FORM_DATE DATE,
                                           P_FILE_NAME VARCHAR, P_ROWS_JSON VARCHAR, P_SIGNED BOOLEAN, P_VIEWER VARCHAR)
RETURNS VARCHAR LANGUAGE PYTHON RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'openpyxl') HANDLER = 'run' EXECUTE AS OWNER
AS $$
import io, json
import openpyxl
from snowflake.snowpark.files import SnowflakeFile

HEADERS = ["FORM_OID", "ITEM_OID", "ACTION", "REASON"]

def one(session, sql, params=None):
    return session.sql(sql, params=params or []).collect()

def read_workbook(session, file_name):
    """Rows from the RULES sheet of the uploaded workbook, as dicts. Raises ValueError with a plain message."""
    with SnowflakeFile.open("@BLINDING_FILES/" + file_name, "rb", require_scoped_url=False) as f:
        data = f.read()
    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=False)
    if "RULES" not in wb.sheetnames:
        raise ValueError("the workbook has no RULES sheet")
    ws = wb["RULES"]
    if ws.merged_cells.ranges:
        raise ValueError("the RULES sheet has merged cells")
    grid = list(ws.iter_rows())
    header = [str(c.value or "").strip().upper() for c in grid[0][:4]] if grid else []
    if header != HEADERS:
        raise ValueError("headers must be " + ", ".join(HEADERS))
    rows = []
    for r in grid[1:]:
        cells = r[:4]
        if any(c.data_type == "f" for c in cells):
            raise ValueError("row " + str(cells[0].row) + " holds a formula; type the values")
        vals = [str(c.value).strip() if c.value is not None else "" for c in cells] + [""] * (4 - len(cells))
        if any(vals):
            rows.append({"form": vals[0], "item": vals[1], "action": vals[2], "reason": vals[3]})
    return rows

def run(session, p_study, p_name, p_form_ref, p_form_date, p_file_name, p_rows_json, p_signed, p_viewer):
    me = one(session, "CALL SP_ACTOR(?)", [p_viewer])[0][0]
    if not me:                                         return "REFUSED: you could not be identified"
    today = one(session, "SELECT CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE")[0][0]
    reg = one(session, "SELECT ROLE_PREFIX FROM STUDY_REGISTRY WHERE STUDY_OID = ? AND ACTIVE", [p_study])
    if not reg:                                        return "REFUSED: study is not under blinding"
    if not (p_name or "").strip():                     return "REFUSED: your name is empty"
    if not (p_form_ref or "").strip():                 return "REFUSED: Blinding form reference is empty"
    if p_form_date is None or p_form_date > today:     return "REFUSED: Blinding form date missing or in the future"
    if not p_signed:                                   return "REFUSED: signature not confirmed"
    prefix = reg[0][0]
    if not one(session, "CALL SP_HOLDS_ROLE(?, ?)", [me, prefix + "_GOVERNANCE"])[0][0]:
        return "REFUSED: you are not the governance lead on " + p_study
    # the rows: from the workbook on the stage, or manual
    source, md5 = ("EXCEL", None) if (p_file_name or "").strip() else ("MANUAL", None)
    try:
        if source == "EXCEL":
            one(session, "ALTER STAGE BLINDING_FILES REFRESH")
            m = one(session, "SELECT MD5 FROM DIRECTORY(@BLINDING_FILES) WHERE RELATIVE_PATH = ?", [p_file_name])
            if not m:                                  return "REFUSED: uploaded file not found"
            md5 = m[0][0]
            rows = read_workbook(session, p_file_name)
        else:
            rows = json.loads(p_rows_json or "[]")
    except Exception as e:
        return "REFUSED: rows could not be read — " + str(e)
    if not 1 <= len(rows) <= 500:                      return "REFUSED: between 1 and 500 rows"

    # checks and writes run under the study lock, so they see one state (two entries at once cannot both pass)
    def refuse(msg):
        one(session, "ROLLBACK")
        return msg
    one(session, "BEGIN")
    try:
        one(session, "UPDATE STUDY_REGISTRY SET LOCK_AT = CURRENT_TIMESTAMP() WHERE STUDY_OID = ?", [p_study])
        # whoever changes what is blinded must not be able to see the data themselves
        if one(session, "SELECT COUNT(*) FROM ACCESS_ACTIVE WHERE STUDY_OID = ? AND USER_NAME = ?", [p_study, me])[0][0] > 0:
            return refuse("REFUSED: you have data access on " + p_study + "; a governance lead without data access must change its rules")
        # every row checked against the live keys and the rules in force
        keys = {(r[0], r[1]) for r in one(session, "SELECT FORM_OID, ITEM_OID FROM V_ITEM_KEYS WHERE STUDY_OID = ?", [p_study])}
        forms = {k[0] for k in keys}
        in_force = {(r[0], r[1]) for r in one(session, "SELECT FORM_OID, COALESCE(ITEM_OID, '') FROM V_BLINDING_RULE_EFFECTIVE WHERE STUDY_OID = ?", [p_study])}
        # keys in the feed that no signed entry has classified yet (blinded until one does)
        unclassified = {(r[0], r[1]) for r in one(session, """SELECT k.FORM_OID, k.ITEM_OID FROM V_ITEM_KEYS k
                                                           LEFT JOIN ITEM_KEY_STATE s ON s.STUDY_OID = k.STUDY_OID AND s.FORM_OID = k.FORM_OID
                                                                                     AND EQUAL_NULL(s.ITEM_OID, k.ITEM_OID)
                                                          WHERE k.STUDY_OID = ? AND s.FORM_OID IS NULL""", [p_study])}

        def covers(form, item, key):
            """A row covers a key: same form, and whole form (no item) or the same item."""
            return key[0] == form and (not item or key[1] == item)

        errors, seen, clean = [], set(), []
        for i, r in enumerate(rows, start=1):
            form = str(r.get("form") or "").strip(); item = str(r.get("item") or "").strip()
            action = str(r.get("action") or "").strip().upper(); reason = str(r.get("reason") or "").strip()
            e = []
            if not form:                                  e.append("form missing")
            elif form not in forms:                       e.append("form not in the data")
            if item and (form, item) not in keys:         e.append("item not in this form")
            if action not in ("ADD", "REMOVE", "CLEAR"):  e.append("action must be ADD, REMOVE or CLEAR")
            if action == "ADD" and (form, item) in in_force:      e.append("already blinded")
            if action == "REMOVE" and (form, item) not in in_force: e.append("no rule in force to remove")
            if action == "CLEAR" and (form, item) in in_force and not any(covers(form, item, k) for k in unclassified):
                e.append("a rule is in force here: use REMOVE")              # (naming a new key here is fine: it stays BLIND)
            if action == "CLEAR" and not any(covers(form, item, k) for k in unclassified):     # CLEAR only names new keys
                e.append("nothing new here to clear (CLEAR is only for forms/items not yet classified)")
            if len(reason) < 10:                          e.append("reason under 10 characters")
            if (form, item) in seen:                      e.append("repeated in this entry")
            seen.add((form, item))
            if e:
                errors.append("row " + str(i) + ": " + ", ".join(e))
            clean.append({"n": i, "form": form, "item": item or None, "action": action, "reason": reason})
        if errors:
            return refuse("REFUSED: " + " | ".join(errors))
        # every form/item new in the feed must be classified by this entry (ADD = blind it, CLEAR = reviewed, stays visible):
        # nothing becomes visible to blinded users without a signed decision naming it
        names = [r for r in clean if r["action"] in ("ADD", "CLEAR")]      # a REMOVE lifts a rule; it never names a new key
        left = sorted({f + ("." + i if i else "") for f, i in unclassified
                       if not any(covers(r["form"], r["item"], (f, i)) for r in names)})
        if left:
            return refuse("REFUSED: not yet classified and not on this entry: " + ", ".join(left[:30]) + (" …" if len(left) > 30 else "")
                          + ". Add a row for each (ADD to blind, CLEAR to leave visible) as recorded on the Blinding form.")
        n_new = sum(1 for k in unclassified if any(covers(r["form"], r["item"], k) for r in names))

        # write: entry + rows + decision + rules + key state + audit, all or nothing
        rid = "RR-" + str(one(session, "SELECT BLINDING_SEQ.NEXTVAL")[0][0]).zfill(8)
        sig = (p_name.strip() + " (" + me + "), governance lead, applies " + str(len(clean)) + " row(s) on " + p_study
               + ", classifying " + str(n_new) + " new form/item(s),"
               + " as recorded on signed Blinding form " + p_form_ref.strip() + " (signed " + str(p_form_date) + ")"
               + (" from file " + p_file_name + ", md5 " + md5 if source == "EXCEL" else "") + ". Electronic signature.")
        one(session, "INSERT INTO RULE_REQUEST VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP())",
            [rid, p_study, source, p_form_ref.strip(), p_form_date, p_file_name if source == "EXCEL" else None, md5,
             len(clean), me, p_name.strip(), sig])
        one(session, """INSERT INTO RULE_REQUEST_ROW
                        SELECT ?, f.VALUE:n::NUMBER, f.VALUE:form::STRING, f.VALUE:item::STRING, f.VALUE:action::STRING, f.VALUE:reason::STRING
                          FROM TABLE(FLATTEN(INPUT => PARSE_JSON(?))) f""", [rid, json.dumps(clean)])
        one(session, "INSERT INTO RULE_DECISION VALUES (?, 'APPROVED', ?, ?, ?, CURRENT_TIMESTAMP())",
            [rid, "Applied as recorded on Blinding form " + p_form_ref.strip(), me, sig])
        one(session, """INSERT INTO BLINDING_RULE (STUDY_OID, FORM_OID, ITEM_OID, ACTION, REASON, RULE_REQUEST_ID, APPROVED_BY, CREATED_AT)
                        SELECT ?, FORM_OID, ITEM_OID, ACTION, REASON, RULE_REQUEST_ID, ?, CURRENT_TIMESTAMP()
                          FROM RULE_REQUEST_ROW WHERE RULE_REQUEST_ID = ? AND ACTION IN ('ADD', 'REMOVE') ORDER BY ROW_NO""",
            [p_study, me, rid])                                   # CLEAR rows classify only; they are not rules
        one(session, "CALL SP_REBUILD_KEY_STATE(?, ?)", [p_study, rid])
        one(session, "CALL SP_AUDIT(?, 'RULES_APPLIED', ?, ?, ?)", [p_study, rid, sig, me])
        one(session, "COMMIT")
        return "OK: " + rid + " — " + str(len(clean)) + " row(s) applied on " + p_study + ", " + str(n_new) + " new form/item(s) classified"
    except Exception as e:
        one(session, "ROLLBACK")
        return "FAILED: " + str(e)
$$;

-- 1.6j APP · governance lead appoints or removes a line manager on their study (the LINE_MANAGER role is
--      SYSADMIN-owned, so this owner's-rights procedure does the grant). Governance leads themselves are
--      appointed only by 02b, never here.
CREATE OR REPLACE PROCEDURE SP_SET_LINE_MANAGER(P_STUDY VARCHAR, P_USER VARCHAR, P_PERSON VARCHAR, P_ACTION VARCHAR,
                                                P_FORM_REF VARCHAR, P_REASON VARCHAR, P_SIGNED BOOLEAN, P_VIEWER VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE me VARCHAR; usr VARCHAR; act VARCHAR; prefix VARCHAR; lm VARCHAR; ok BOOLEAN; holds BOOLEAN; sig VARCHAR;
BEGIN
  CALL SP_ACTOR(:P_VIEWER) INTO :me;
  IF (me IS NULL) THEN RETURN 'REFUSED: you could not be identified'; END IF;
  usr := UPPER(TRIM(COALESCE(P_USER, ''))); act := UPPER(TRIM(COALESCE(P_ACTION, '')));
  SELECT MAX(ROLE_PREFIX) INTO :prefix FROM STUDY_REGISTRY WHERE STUDY_OID = :P_STUDY AND ACTIVE;
  IF (prefix IS NULL)                                    THEN RETURN 'REFUSED: study is not under blinding'; END IF;
  IF (NOT REGEXP_LIKE(usr, '^[A-Z0-9_.@-]{1,255}$'))      THEN RETURN 'REFUSED: login missing or invalid'; END IF;
  IF (act NOT IN ('ADD', 'REMOVE'))                      THEN RETURN 'REFUSED: action must be ADD or REMOVE'; END IF;
  IF (usr = me)                                          THEN RETURN 'REFUSED: you cannot appoint or remove yourself'; END IF;
  IF (COALESCE(TRIM(P_PERSON), '') = '')                 THEN RETURN 'REFUSED: name is empty'; END IF;
  IF (COALESCE(TRIM(P_FORM_REF), '') = '')               THEN RETURN 'REFUSED: form reference is empty'; END IF;
  IF (LENGTH(TRIM(COALESCE(P_REASON, ''))) < 10)         THEN RETURN 'REFUSED: reason under 10 characters'; END IF;
  IF (NOT COALESCE(P_SIGNED, FALSE))                     THEN RETURN 'REFUSED: signature not confirmed'; END IF;
  CALL SP_HOLDS_ROLE(:me, :prefix || '_GOVERNANCE') INTO :ok;
  IF (NOT ok) THEN RETURN 'REFUSED: you are not the governance lead on ' || P_STUDY; END IF;
  lm := prefix || '_LINE_MANAGER';
  CALL SP_HOLDS_ROLE(:usr, :lm) INTO :holds;
  IF (act = 'ADD' AND holds)        THEN RETURN 'REFUSED: ' || usr || ' is already a line manager on ' || P_STUDY; END IF;
  IF (act = 'REMOVE' AND NOT holds) THEN RETURN 'REFUSED: ' || usr || ' is not a line manager on ' || P_STUDY; END IF;
  sig := me || ' (governance lead) ' || IFF(act = 'ADD', 'appointed ', 'removed ') || TRIM(P_PERSON) || ' (' || usr || ')'
         || IFF(act = 'ADD', ' as', ' from') || ' line manager on ' || P_STUDY || ', per form ' || TRIM(P_FORM_REF)
         || ': ' || TRIM(P_REASON) || '. Electronic signature.';
  IF (act = 'ADD') THEN
    EXECUTE IMMEDIATE 'GRANT ROLE ' || lm || ' TO USER "' || usr || '"';
  ELSE
    EXECUTE IMMEDIATE 'REVOKE ROLE ' || lm || ' FROM USER "' || usr || '"';
  END IF;
  CALL SP_AUDIT(:P_STUDY, 'LINE_MANAGER_' || IFF(act = 'ADD', 'ADDED', 'REMOVED'), :usr, :sig, :me);
  RETURN 'OK: ' || usr || IFF(act = 'ADD', ' is now a line manager on ', ' is no longer a line manager on ') || P_STUDY;
EXCEPTION WHEN OTHER THEN RETURN 'FAILED: ' || SQLERRM;
END;
$$;

-- 1.6k The one list of what a study's roles may reach (called by 02b Section 2 for a new study, and by 04 after each app deploy)
--      7 working roles: the feed view. GOVERNANCE: warehouse + schema, and NO standing CREATE PROCEDURE (02b grants it
--      only while governance creates its role procedure, then takes it back). LINE_MANAGER: the schema.
--      All 9: USAGE on the app, if it is deployed (a re-deploy replaces the app and drops its grants; 04 calls this again).
DROP PROCEDURE IF EXISTS SP_GRANT_STUDY_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR);   -- replaced: now takes the app name
CREATE OR REPLACE PROCEDURE SP_GRANT_STUDY_ACCESS(P_PREFIX VARCHAR, P_DB VARCHAR, P_SCHEMA VARCHAR, P_WH VARCHAR, P_FEED VARCHAR,
                                                  P_APP VARCHAR)
RETURNS VARCHAR LANGUAGE SQL EXECUTE AS OWNER
AS $$
DECLARE sc VARCHAR; working ARRAY; all_roles ARRAY; n NUMBER DEFAULT 0;
BEGIN
  IF (NOT REGEXP_LIKE(COALESCE(P_PREFIX, ''), '^[A-Z][A-Z0-9_]*$')) THEN RETURN 'REFUSED: role prefix must be A-Z 0-9 _'; END IF;
  sc := P_DB || '.' || P_SCHEMA;
  working := ARRAY_CONSTRUCT('_STAT_BLINDED', '_STAT_UNBLINDED', '_PROG_BLINDED', '_PROG_UNBLINDED', '_DM_BLINDED', '_DM_UNBLINDED', '_ADHOC_BLINDED');
  FOR i IN 0 TO ARRAY_SIZE(working) - 1 DO
    LET r VARCHAR := P_PREFIX || GET(working, i)::VARCHAR;
    EXECUTE IMMEDIATE 'GRANT USAGE ON WAREHOUSE ' || P_WH || ' TO ROLE ' || r;
    EXECUTE IMMEDIATE 'GRANT USAGE ON DATABASE '  || P_DB || ' TO ROLE ' || r;
    EXECUTE IMMEDIATE 'GRANT USAGE ON SCHEMA '    || sc   || ' TO ROLE ' || r;
    EXECUTE IMMEDIATE 'GRANT SELECT ON VIEW '     || sc || '.' || P_FEED || ' TO ROLE ' || r;
  END FOR;
  EXECUTE IMMEDIATE 'GRANT USAGE ON DATABASE ' || P_DB || ' TO ROLE ' || P_PREFIX || '_GOVERNANCE';
  EXECUTE IMMEDIATE 'GRANT USAGE ON SCHEMA '   || sc   || ' TO ROLE ' || P_PREFIX || '_GOVERNANCE';
  EXECUTE IMMEDIATE 'GRANT USAGE ON WAREHOUSE ' || P_WH || ' TO ROLE ' || P_PREFIX || '_GOVERNANCE';
  EXECUTE IMMEDIATE 'REVOKE CREATE PROCEDURE ON SCHEMA ' || sc || ' FROM ROLE ' || P_PREFIX || '_GOVERNANCE';   -- only 02b, briefly
  EXECUTE IMMEDIATE 'GRANT USAGE ON DATABASE ' || P_DB || ' TO ROLE ' || P_PREFIX || '_LINE_MANAGER';
  EXECUTE IMMEDIATE 'GRANT USAGE ON SCHEMA '   || sc   || ' TO ROLE ' || P_PREFIX || '_LINE_MANAGER';
  -- the app, if deployed
  IF (NOT REGEXP_LIKE(COALESCE(P_APP, ''), '^[A-Z][A-Z0-9_]*$')) THEN RETURN 'REFUSED: app name must be A-Z 0-9 _'; END IF;
  EXECUTE IMMEDIATE 'SHOW STREAMLITS LIKE ''' || P_APP || ''' IN SCHEMA ' || sc;
  SELECT COUNT(*) INTO :n FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
  IF (n = 0) THEN RETURN 'OK: grants applied to ' || P_PREFIX || '_* (app ' || P_APP || ' not deployed yet: 04 grants it)'; END IF;
  all_roles := ARRAY_CAT(working, ARRAY_CONSTRUCT('_GOVERNANCE', '_LINE_MANAGER'));
  FOR i IN 0 TO ARRAY_SIZE(all_roles) - 1 DO
    EXECUTE IMMEDIATE 'GRANT USAGE ON STREAMLIT ' || sc || '.' || P_APP || ' TO ROLE ' || P_PREFIX || GET(all_roles, i)::VARCHAR;
  END FOR;
  RETURN 'OK: grants applied to ' || P_PREFIX || '_*, including USAGE on ' || P_APP;
END;
$$;

-- 1.7 What MASKING_ADMIN needs here: create its policies in this schema; read the two tables they look up
GRANT USAGE ON DATABASE IDENTIFIER($DB)                   TO ROLE IDENTIFIER($MASKING_ROLE);
GRANT USAGE ON SCHEMA   IDENTIFIER($FQ_SCHEMA)            TO ROLE IDENTIFIER($MASKING_ROLE);
GRANT USAGE ON WAREHOUSE IDENTIFIER($WH)                  TO ROLE IDENTIFIER($MASKING_ROLE);
GRANT CREATE MASKING POLICY    ON SCHEMA IDENTIFIER($FQ_SCHEMA) TO ROLE IDENTIFIER($MASKING_ROLE);
GRANT CREATE ROW ACCESS POLICY ON SCHEMA IDENTIFIER($FQ_SCHEMA) TO ROLE IDENTIFIER($MASKING_ROLE);
GRANT SELECT ON TABLE ACCESS_ACTIVE  TO ROLE IDENTIFIER($MASKING_ROLE);
GRANT SELECT ON TABLE ITEM_KEY_STATE TO ROLE IDENTIFIER($MASKING_ROLE);


-- Section 2 MASKING_ADMIN: the two policies, and APPLY on them to SYSADMIN ------------------------
--   Created once with a fail-closed body, then the real body is set on every run (attachments survive).
USE ROLE IDENTIFIER($MASKING_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);

CREATE MASKING POLICY IF NOT EXISTS MASK_ITEM_VALUE AS (VAL VARCHAR, P_STUDY VARCHAR, P_FORM VARCHAR, P_ITEM VARCHAR)
  RETURNS VARCHAR -> 'BLINDED';
CREATE ROW ACCESS POLICY IF NOT EXISTS RAP_STUDY_ACCESS AS (P_STUDY VARCHAR) RETURNS BOOLEAN -> FALSE;

-- 2.1 Mask. Every branch needs the person's register row for this study, today (London date), AND the role
--     they are using to be the working role that row names. Tested in order:
--     ADHOC -> 'BLINDED' always · UNBLINDED -> value · BLINDED and key CLEAR -> value · otherwise 'BLINDED'
ALTER MASKING POLICY MASK_ITEM_VALUE SET BODY ->
  CASE
    WHEN EXISTS (SELECT 1 FROM ACCESS_ACTIVE a WHERE a.USER_NAME = CURRENT_USER() AND a.ROLE_NAME = CURRENT_ROLE()
                    AND a.STUDY_OID = P_STUDY AND a.ROLE_FUNCTION = 'ADHOC'
                    AND CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE BETWEEN a.EFFECTIVE_FROM AND a.EFFECTIVE_TO) THEN 'BLINDED'
    WHEN EXISTS (SELECT 1 FROM ACCESS_ACTIVE a WHERE a.USER_NAME = CURRENT_USER() AND a.ROLE_NAME = CURRENT_ROLE()
                    AND a.STUDY_OID = P_STUDY AND a.SIGHT = 'UNBLINDED'
                    AND CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE BETWEEN a.EFFECTIVE_FROM AND a.EFFECTIVE_TO) THEN VAL
    WHEN EXISTS (SELECT 1 FROM ACCESS_ACTIVE a WHERE a.USER_NAME = CURRENT_USER() AND a.ROLE_NAME = CURRENT_ROLE()
                    AND a.STUDY_OID = P_STUDY AND a.SIGHT = 'BLINDED'
                    AND CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE BETWEEN a.EFFECTIVE_FROM AND a.EFFECTIVE_TO)
     AND EXISTS (SELECT 1 FROM ITEM_KEY_STATE k WHERE k.STUDY_OID = P_STUDY AND k.FORM_OID = P_FORM
                    AND EQUAL_NULL(k.ITEM_OID, P_ITEM) AND k.STATE = 'CLEAR') THEN VAL
    ELSE 'BLINDED'
  END;

-- 2.2 Row gate: a row is visible only to a person with a register row for its study today, using that row's working role
ALTER ROW ACCESS POLICY RAP_STUDY_ACCESS SET BODY ->
  EXISTS (SELECT 1 FROM ACCESS_ACTIVE a WHERE a.USER_NAME = CURRENT_USER() AND a.ROLE_NAME = CURRENT_ROLE() AND a.STUDY_OID = P_STUDY
             AND CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE BETWEEN a.EFFECTIVE_FROM AND a.EFFECTIVE_TO);

-- 2.3 SYSADMIN owns the feed layers, so it attaches the policies (Section 3). Kept: not taken back later.
GRANT APPLY ON MASKING POLICY    MASK_ITEM_VALUE  TO ROLE IDENTIFIER($BUILD_ROLE);
GRANT APPLY ON ROW ACCESS POLICY RAP_STUDY_ACCESS TO ROLE IDENTIFIER($BUILD_ROLE);


-- Section 3 SYSADMIN: attach the policies (already attached = left as it is) ---------------------
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);

BEGIN
  LET feed STRING := (SELECT $FEED_VIEW);
  LET cols ARRAY  := (SELECT SPLIT($VALUE_COLUMNS, ','));
  -- 3.1 mask on every value column of the feed view
  FOR i IN 0 TO ARRAY_SIZE(:cols) - 1 DO
    LET c STRING := GET(:cols, :i)::STRING;
    BEGIN
      EXECUTE IMMEDIATE 'ALTER VIEW ' || :feed || ' MODIFY COLUMN ' || :c
                        || ' SET MASKING POLICY MASK_ITEM_VALUE USING (' || :c || ', STUDY_OID, FORM_OID, ITEM_OID)';
    EXCEPTION WHEN OTHER THEN NULL;     -- already attached
    END;
  END FOR;
  -- 3.2 row gate on the row layer
  BEGIN
    EXECUTE IMMEDIATE 'ALTER VIEW ' || :feed || '_ROWS ADD ROW ACCESS POLICY RAP_STUDY_ACCESS ON (STUDY_OID)';
  EXCEPTION WHEN OTHER THEN NULL;       -- already attached
  END;
  -- 3.3 prove it: an attach error above is only ignored if the policy really is on (e.g. "already attached")
  LET masked NUMBER := 0;  LET gated NUMBER := 0;
  SELECT COUNT(DISTINCT REF_COLUMN_NAME) INTO :masked
    FROM TABLE(INFORMATION_SCHEMA.POLICY_REFERENCES(REF_ENTITY_NAME => $FQ_SCHEMA || '.' || $FEED_VIEW, REF_ENTITY_DOMAIN => 'VIEW'))
   WHERE POLICY_NAME = 'MASK_ITEM_VALUE' AND ARRAY_CONTAINS(REF_COLUMN_NAME::VARIANT, SPLIT($VALUE_COLUMNS, ','));
  SELECT COUNT(*) INTO :gated
    FROM TABLE(INFORMATION_SCHEMA.POLICY_REFERENCES(REF_ENTITY_NAME => $FQ_SCHEMA || '.' || $FEED_VIEW || '_ROWS', REF_ENTITY_DOMAIN => 'VIEW'))
   WHERE POLICY_NAME = 'RAP_STUDY_ACCESS';
  IF (:masked <> ARRAY_SIZE(:cols) OR :gated <> 1) THEN
    RETURN 'FAILED: masked ' || :masked || ' of ' || ARRAY_SIZE(:cols) || ' value columns, row gate on: ' || :gated || ' — fix before use';
  END IF;
  RETURN 'policies attached and confirmed: ' || :masked || ' value columns masked on ' || :feed || ', row gate on ' || :feed || '_ROWS';
END;

-- END. Next: 02b_study_onboard.sql
