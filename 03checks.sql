-- =============================================================================
-- 03_checks.sql
-- WHAT   Every check on 01, 02a and 02b, one row each, into BLINDING_CHECK_RESULT, then one text report
--        @BLINDING_REPORTS/checks_<run>.txt  ( CHECK | RESULT | EXPECTED | ACTUAL | WHAT ), summary first.
--        Changes nothing that was built. Run as often as wanted (after a build, daily, before an audit).
-- ROLES  Section 1 SYSADMIN (report table and stage; platform, objects, data checks)
--        Section 2 MASKING_ADMIN (policy checks) · Section 3 <PREFIX>_GOVERNANCE (study role checks) · Section 4 SYSADMIN (report)
-- RUN    Set Section 0, Run All. Read the summary at the end; open the file for the detail.
-- RESULT PASS · FAIL (must be fixed) · WARN (expected at times, read the WHAT)
-- =============================================================================


-- Section 0 PARAMETERS -----------------------------------------------------------------
SET BUILD_ROLE    = 'SYSADMIN';
SET MASKING_ROLE  = 'MASKING_ADMIN';
SET WH            = 'ODM_BLINDING_WH';
SET DB            = 'DEV_MEDIDATA_ODM_DATA_PRODUCT';
SET SCHEMA        = 'RAW_ODM';
SET LANDING_TABLE = 'POC_PATIENT_ITEM_DATA';
SET FEED_VIEW     = 'SV_PATIENT_ITEM_DATA';
SET STUDY_OID     = 'IMC-F106C-101';
SET ROLE_PREFIX   = 'CT_IMC_F106C_101';
SET VALUE_COLUMNS = 'ITEM_VALUE,CODELIST_ITEM_UUID,CODELIST_ITEM_DECODE,MEAS_UNIT,MEAS_UNIT_UUID';   -- exactly as in 02a

SET FQ_SCHEMA = $DB || '.' || $SCHEMA;
SET ROWS_VIEW = $FEED_VIEW || '_ROWS';
SET GOV_ROLE  = $ROLE_PREFIX || '_GOVERNANCE';
SET LM_ROLE   = $ROLE_PREFIX || '_LINE_MANAGER';
SET RUN_ID    = TO_VARCHAR(CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP()), 'YYYYMMDD_HH24MISS');


-- Section 1 SYSADMIN ---------------------------------------------------------------------
USE ROLE IDENTIFIER($BUILD_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);

-- 1.0 Where results go (check infrastructure, not part of the build)
CREATE TABLE IF NOT EXISTS BLINDING_CHECK_RESULT (RUN_ID VARCHAR, CHECK_ID VARCHAR, WHAT VARCHAR, EXPECTED VARCHAR,
                                                  ACTUAL VARCHAR, RESULT VARCHAR, RUN_ROLE VARCHAR, RUN_AT TIMESTAMP_TZ);
CREATE STAGE IF NOT EXISTS BLINDING_REPORTS COMMENT = 'Check reports from 03_checks.sql.';
GRANT INSERT ON TABLE BLINDING_CHECK_RESULT TO ROLE IDENTIFIER($MASKING_ROLE);
GRANT INSERT ON TABLE BLINDING_CHECK_RESULT TO ROLE IDENTIFIER($GOV_ROLE);
GRANT SELECT ON TABLE ACCESS_ACTIVE         TO ROLE IDENTIFIER($GOV_ROLE);   -- G2 compares role holders with the register

-- ---- ENVIRONMENT (01) ----
SHOW WAREHOUSES;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'E01', 'warehouse exists, owned by SYSADMIN', 'SYSADMIN', COALESCE(MAX("owner"), '(missing)'),
       IFF(MAX("owner") = 'SYSADMIN', 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "name" = $WH;

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'E02', 'landing table exists, owned by SYSADMIN, has rows', 'SYSADMIN, > 0 rows',
       COALESCE(MAX(TABLE_OWNER), '(missing)') || ', ' || COALESCE(MAX(ROW_COUNT), 0) || ' rows',
       IFF(MAX(TABLE_OWNER) = 'SYSADMIN' AND MAX(ROW_COUNT) > 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = $SCHEMA AND TABLE_NAME = $LANDING_TABLE;

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'E03', 'row layer and feed view exist, owned by SYSADMIN', '2', COUNT(*)::VARCHAR,
       IFF(COUNT(*) = 2, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = $SCHEMA AND TABLE_NAME IN ($FEED_VIEW, $ROWS_VIEW) AND TABLE_TYPE = 'VIEW' AND TABLE_OWNER = 'SYSADMIN';

SHOW GRANTS ON TABLE IDENTIFIER($LANDING_TABLE);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'E04', 'landing table granted to nobody (one door: the feed view)', '0 grants', COUNT(*)::VARCHAR || ' grants',
       IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "privilege" <> 'OWNERSHIP';

SHOW GRANTS ON VIEW IDENTIFIER($ROWS_VIEW);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'E05', 'row layer granted to nobody', '0 grants', COUNT(*)::VARCHAR || ' grants',
       IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "privilege" <> 'OWNERSHIP';

SHOW GRANTS ON VIEW IDENTIFIER($FEED_VIEW);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'E06', 'feed view: SELECT only to working roles (no other grant)', '0 other grants', COUNT(*)::VARCHAR || ' other grants',
       IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
WHERE "privilege" <> 'OWNERSHIP'
  AND NOT ("privilege" = 'SELECT' AND REGEXP_LIKE("grantee_name", '.*_(STAT|PROG|DM)_(BLINDED|UNBLINDED)|.*_ADHOC_BLINDED'));

-- ---- OBJECTS (02a) ----
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'O01', 'the 10 control tables exist, owned by SYSADMIN', '10', COUNT(*)::VARCHAR,
       IFF(COUNT(*) = 10, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = $SCHEMA AND TABLE_OWNER = 'SYSADMIN' AND TABLE_TYPE = 'BASE TABLE'
  AND TABLE_NAME IN ('STUDY_REGISTRY', 'ACCESS_REQUEST', 'ACCESS_DECISION', 'ACCESS_ACTIVE', 'RULE_REQUEST', 'RULE_REQUEST_ROW',
                     'RULE_DECISION', 'BLINDING_RULE', 'ITEM_KEY_STATE', 'AUDIT_LOG');

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'O02', 'the 4 helper views exist, owned by SYSADMIN', '4', COUNT(*)::VARCHAR,
       IFF(COUNT(*) = 4, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = $SCHEMA AND TABLE_OWNER = 'SYSADMIN' AND TABLE_TYPE = 'VIEW'
  AND TABLE_NAME IN ('V_ACCESS_REQUEST_STATUS', 'V_RULE_REQUEST_STATUS', 'V_BLINDING_RULE_EFFECTIVE', 'V_ITEM_KEYS');

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'O03', 'the 12 procedures exist, owned by SYSADMIN', '12', COUNT(DISTINCT PROCEDURE_NAME)::VARCHAR,
       IFF(COUNT(DISTINCT PROCEDURE_NAME) = 12, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM INFORMATION_SCHEMA.PROCEDURES
WHERE PROCEDURE_SCHEMA = $SCHEMA AND PROCEDURE_OWNER = 'SYSADMIN'
  AND PROCEDURE_NAME IN ('SP_ACTOR', 'SP_AUDIT', 'SP_HOLDS_ROLE', 'SP_REBUILD_KEY_STATE', 'SP_SET_ROLE', 'SP_REQUEST_ACCESS',
                         'SP_DECIDE_ACCESS', 'SP_SUSPEND_ACCESS', 'SP_END_EXPIRED', 'SP_APPLY_RULES', 'SP_SET_LINE_MANAGER',
                         'SP_GRANT_STUDY_ACCESS');

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'O05', 'each procedure exists in exactly one version (old signatures dropped)', '0 extra versions',
       (COUNT(*) - COUNT(DISTINCT PROCEDURE_NAME))::VARCHAR || ' extra versions',
       IFF(COUNT(*) = COUNT(DISTINCT PROCEDURE_NAME), 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM INFORMATION_SCHEMA.PROCEDURES
WHERE PROCEDURE_SCHEMA = $SCHEMA
  AND PROCEDURE_NAME IN ('SP_ACTOR', 'SP_AUDIT', 'SP_HOLDS_ROLE', 'SP_REBUILD_KEY_STATE', 'SP_SET_ROLE', 'SP_REQUEST_ACCESS',
                         'SP_DECIDE_ACCESS', 'SP_SUSPEND_ACCESS', 'SP_END_EXPIRED', 'SP_APPLY_RULES', 'SP_SET_LINE_MANAGER',
                         'SP_GRANT_STUDY_ACCESS');

-- O06: no role but the owner may call them (the deployed app passes the viewer's name; only SYSADMIN-owned code can)
BEGIN
  LET sc STRING := (SELECT $FQ_SCHEMA);  LET v_run STRING := (SELECT $RUN_ID);
  LET v_total NUMBER := 0;  LET n NUMBER := 0;  LET v_who STRING := '';  LET v_found STRING := '';
  EXECUTE IMMEDIATE 'SHOW PROCEDURES IN SCHEMA ' || :sc;
  LET rs RESULTSET := (SELECT SPLIT_PART("arguments", ' RETURN ', 1) AS SIG FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
                        WHERE "name" IN ('SP_ACTOR', 'SP_AUDIT', 'SP_HOLDS_ROLE', 'SP_REBUILD_KEY_STATE', 'SP_SET_ROLE', 'SP_REQUEST_ACCESS',
                         'SP_DECIDE_ACCESS', 'SP_SUSPEND_ACCESS', 'SP_END_EXPIRED', 'SP_APPLY_RULES', 'SP_SET_LINE_MANAGER',
                         'SP_GRANT_STUDY_ACCESS'));
  LET c CURSOR FOR rs;
  FOR x IN c DO
    LET sig STRING := x.SIG;
    EXECUTE IMMEDIATE 'SHOW GRANTS ON PROCEDURE ' || :sig;
    SELECT COUNT(*), COALESCE(LISTAGG(DISTINCT "grantee_name", ','), '') INTO :n, :v_who
      FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "privilege" <> 'OWNERSHIP';
    IF (:n > 0) THEN v_total := :v_total + :n; v_found := :v_found || ' ' || :sig || '->' || :v_who; END IF;
  END FOR;
  INSERT INTO BLINDING_CHECK_RESULT
  SELECT :v_run, 'O06', 'procedures granted to no role (callable by SYSADMIN-owned code only)', '0 grants',
         :v_total || ' grants' || :v_found, IFF(:v_total = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP();
  RETURN 'O06: ' || :v_total || ' grants';
END;

-- O07: SYSADMIN-owned apps. Any of them could pass a viewer name to the procedures, so BLINDING_APP should be the only one.
SHOW STREAMLITS IN ACCOUNT;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'O07', 'Streamlit apps owned by SYSADMIN/ACCOUNTADMIN (visible here): only BLINDING_APP (any other could pass a viewer name)', 'BLINDING_APP',
       COALESCE(LISTAGG("database_name" || '.' || "schema_name" || '.' || "name", ', ') WITHIN GROUP (ORDER BY "name"), '(none)'),
       IFF(COUNT(*) = 1 AND MAX("name") = 'BLINDING_APP', 'PASS', 'WARN'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "owner" IN ('SYSADMIN', 'ACCOUNTADMIN');

-- I01 / I02: the identity rule (SP_ACTOR), proven from this worksheet
CALL SP_ACTOR(NULL);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'I01', 'inside a procedure, a worksheet caller is identified as themselves', CURRENT_USER(), COALESCE($1, '(null)'),
       IFF($1 = CURRENT_USER(), 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
CALL SP_ACTOR('SOMEONE_ELSE_TEST');
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'I02', 'a worksheet caller cannot act as someone else (passing another name gives nobody)', '(null)', COALESCE($1, '(null)'),
       IFF($1 IS NULL, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'O04', 'stage BLINDING_FILES exists', '1', COUNT(*)::VARCHAR, IFF(COUNT(*) = 1, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM INFORMATION_SCHEMA.STAGES WHERE STAGE_SCHEMA = $SCHEMA AND STAGE_NAME = 'BLINDING_FILES';

-- ---- POLICIES ATTACHED (02a Section 3) ----
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'P01', 'MASK_ITEM_VALUE on every column in VALUE_COLUMNS', ARRAY_SIZE(SPLIT($VALUE_COLUMNS, ','))::VARCHAR,
       COUNT(DISTINCT REF_COLUMN_NAME)::VARCHAR,
       IFF(COUNT(DISTINCT REF_COLUMN_NAME) = ARRAY_SIZE(SPLIT($VALUE_COLUMNS, ',')), 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(INFORMATION_SCHEMA.POLICY_REFERENCES(REF_ENTITY_NAME => $FQ_SCHEMA || '.' || $FEED_VIEW, REF_ENTITY_DOMAIN => 'VIEW'))
WHERE POLICY_NAME = 'MASK_ITEM_VALUE'
  AND ARRAY_CONTAINS(REF_COLUMN_NAME::VARIANT, SPLIT($VALUE_COLUMNS, ','));

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'P02', 'RAP_STUDY_ACCESS on the row layer', '1', COUNT(*)::VARCHAR, IFF(COUNT(*) = 1, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(INFORMATION_SCHEMA.POLICY_REFERENCES(REF_ENTITY_NAME => $FQ_SCHEMA || '.' || $ROWS_VIEW, REF_ENTITY_DOMAIN => 'VIEW'))
WHERE POLICY_NAME = 'RAP_STUDY_ACCESS';

-- ---- BEHAVIOUR ----
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'B01', 'SYSADMIN (no register row) sees no rows through the feed view', '0', COUNT(*)::VARCHAR,
       IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM IDENTIFIER($FEED_VIEW);

-- ---- STUDY (02b) ----
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S01', 'study registered and active', '1', COUNT(*)::VARCHAR, IFF(COUNT(*) = 1, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM STUDY_REGISTRY WHERE STUDY_OID = $STUDY_OID AND ROLE_PREFIX = $ROLE_PREFIX AND ACTIVE;

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S02', 'the study is in the feed, spelt exactly as registered', '> 0 keys', COUNT(*)::VARCHAR || ' keys',
       IFF(COUNT(*) > 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM V_ITEM_KEYS WHERE STUDY_OID = $STUDY_OID;

SHOW ROLES;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S03', 'the study''s 9 roles exist', '9', COUNT(*)::VARCHAR, IFF(COUNT(*) = 9, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
WHERE "name" IN ($ROLE_PREFIX || '_STAT_BLINDED', $ROLE_PREFIX || '_STAT_UNBLINDED', $ROLE_PREFIX || '_PROG_BLINDED', $ROLE_PREFIX || '_PROG_UNBLINDED',
                 $ROLE_PREFIX || '_DM_BLINDED', $ROLE_PREFIX || '_DM_UNBLINDED', $ROLE_PREFIX || '_ADHOC_BLINDED', $GOV_ROLE, $LM_ROLE);

SHOW GRANTS TO ROLE IDENTIFIER($GOV_ROLE);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'G5', 'governance holds no CREATE PROCEDURE (cannot replace its role procedure)', '0', COUNT(*)::VARCHAR,
       IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "privilege" = 'CREATE PROCEDURE';

-- G6: SP_SET_ROLE accepts the study's role procedure (one version, owned by governance). Called for a login that
--     does not exist, so nothing changes: expect a "does not exist" failure from the role procedure, not the guard.
CALL SP_SET_ROLE($STUDY_OID, 'NO_SUCH_USER_03_CHECK', 'NONE');
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'G6', 'the role procedure passes SP_SET_ROLE''s owner check (approvals can grant roles)', 'not refused by the guard',
       LEFT($1, 120), IFF($1 ILIKE '%NO_SUCH_USER_03_CHECK%', 'PASS', 'FAIL'),   -- only the role procedure's own 'user does not exist'
       CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

SHOW ROLES;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S04', 'the 7 working roles are owned by GOVERNANCE', '7', COUNT(*)::VARCHAR, IFF(COUNT(*) = 7, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
WHERE "owner" = $GOV_ROLE AND STARTSWITH("name", $ROLE_PREFIX || '_') AND "name" NOT IN ($GOV_ROLE, $LM_ROLE);

SHOW ROLES;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S05', 'GOVERNANCE and LINE_MANAGER are owned by SYSADMIN', '2', COUNT(*)::VARCHAR, IFF(COUNT(*) = 2, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
WHERE "owner" = 'SYSADMIN' AND "name" IN ($GOV_ROLE, $LM_ROLE);

SHOW GRANTS OF ROLE IDENTIFIER($GOV_ROLE);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S06', 'GOVERNANCE is held by people only (not rolled up to SYSADMIN or any role)', '0 roles', COUNT_IF("granted_to" = 'ROLE')::VARCHAR || ' roles',
       IFF(COUNT_IF("granted_to" = 'ROLE') = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
SHOW GRANTS OF ROLE IDENTIFIER($GOV_ROLE);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S07', 'governance lead(s) appointed', '>= 1', COUNT_IF("granted_to" = 'USER')::VARCHAR || ': ' || COALESCE(LISTAGG(IFF("granted_to" = 'USER', "grantee_name", NULL), ','), ''),
       IFF(COUNT_IF("granted_to" = 'USER') >= 1, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

SHOW GRANTS OF ROLE IDENTIFIER($LM_ROLE);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S08', 'LINE_MANAGER is held by people only', '0 roles', COUNT_IF("granted_to" = 'ROLE')::VARCHAR || ' roles',
       IFF(COUNT_IF("granted_to" = 'ROLE') = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));
SHOW GRANTS OF ROLE IDENTIFIER($LM_ROLE);
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'S09', 'line manager(s) appointed', '>= 1', COUNT_IF("granted_to" = 'USER')::VARCHAR || ': ' || COALESCE(LISTAGG(IFF("granted_to" = 'USER', "grantee_name", NULL), ','), ''),
       IFF(COUNT_IF("granted_to" = 'USER') >= 1, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

-- ---- REGISTER AND RULES ----
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'R01', 'every register row traces to its access form, request and an APPROVED decision by a different person', '0 bad rows',
       COUNT(*)::VARCHAR || ' bad rows', IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM ACCESS_ACTIVE a
JOIN STUDY_REGISTRY s ON s.STUDY_OID = a.STUDY_OID
LEFT JOIN ACCESS_REQUEST r  ON r.REQUEST_ID = a.REQUEST_ID
LEFT JOIN ACCESS_DECISION d ON d.REQUEST_ID = a.REQUEST_ID AND d.DECISION = 'APPROVED'
WHERE r.REQUEST_ID IS NULL OR d.REQUEST_ID IS NULL
   OR r.STUDY_OID <> a.STUDY_OID OR r.USER_NAME <> a.USER_NAME OR r.ROLE_FUNCTION <> a.ROLE_FUNCTION OR r.SIGHT <> a.SIGHT
   OR r.EFFECTIVE_FROM <> a.EFFECTIVE_FROM OR r.EFFECTIVE_TO <> a.EFFECTIVE_TO
   OR d.DECIDED_BY IN (r.REQUESTED_BY, r.USER_NAME)
   OR COALESCE(TRIM(r.FORM_REF), '') = ''
   OR a.ROLE_NAME <> s.ROLE_PREFIX || '_' || a.ROLE_FUNCTION || '_' || a.SIGHT
   OR (a.ROLE_FUNCTION = 'ADHOC' AND a.SIGHT <> 'BLINDED');

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'R02', 'one register row per person per study', '0 duplicates', COUNT(*)::VARCHAR || ' duplicates',
       IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM (SELECT STUDY_OID, USER_NAME FROM ACCESS_ACTIVE GROUP BY STUDY_OID, USER_NAME HAVING COUNT(*) > 1);

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'R03', 'register rows past their end date (tidy with the app: end expired)', '0', COUNT(*)::VARCHAR,
       IFF(COUNT(*) = 0, 'PASS', 'WARN'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM ACCESS_ACTIVE WHERE EFFECTIVE_TO < CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE;

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'R04', 'item states match the rules in force', '0 mismatches', COUNT(*)::VARCHAR || ' mismatches',
       IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM (SELECT s.STUDY_OID
        FROM ITEM_KEY_STATE s
        LEFT JOIN V_BLINDING_RULE_EFFECTIVE r
               ON r.STUDY_OID = s.STUDY_OID AND r.FORM_OID = s.FORM_OID AND (r.ITEM_OID IS NULL OR r.ITEM_OID = s.ITEM_OID)
       GROUP BY s.STUDY_OID, s.FORM_OID, s.ITEM_OID, s.STATE
      HAVING s.STATE <> IFF(COUNT(r.RULE_ID) = 0, 'CLEAR', 'BLIND'));

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'R05', 'keys not yet classified by an approved rules proposal (BLINDED until then)', '0', COUNT(*)::VARCHAR,
       IFF(COUNT(*) = 0, 'PASS', 'WARN'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM V_ITEM_KEYS k
WHERE k.STUDY_OID IN (SELECT STUDY_OID FROM STUDY_REGISTRY)
  AND NOT EXISTS (SELECT 1 FROM ITEM_KEY_STATE s WHERE s.STUDY_OID = k.STUDY_OID AND s.FORM_OID = k.FORM_OID AND EQUAL_NULL(s.ITEM_OID, k.ITEM_OID));

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'R07', 'every CLEAR item was named by a signed ADD/CLEAR row (nothing visible without a signed decision)',
       '0 un-named', COUNT(*)::VARCHAR || ' un-named', IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM ITEM_KEY_STATE s
LEFT JOIN (SELECT DISTINCT q.STUDY_OID, w.FORM_OID, w.ITEM_OID                    -- names from APPROVED entries only
             FROM RULE_REQUEST_ROW w
             JOIN RULE_REQUEST  q ON q.RULE_REQUEST_ID = w.RULE_REQUEST_ID
             JOIN RULE_DECISION d ON d.RULE_REQUEST_ID = w.RULE_REQUEST_ID AND d.DECISION = 'APPROVED'
            WHERE w.ACTION IN ('ADD', 'CLEAR')) n
       ON n.STUDY_OID = s.STUDY_OID AND n.FORM_OID = s.FORM_OID AND (n.ITEM_OID IS NULL OR n.ITEM_OID = s.ITEM_OID)
WHERE s.STATE = 'CLEAR' AND n.FORM_OID IS NULL;
-- (R07 FAIL = rows left from before this rule existed: delete them from ITEM_KEY_STATE — they become unclassified = BLIND —
--  and classify them with a signed Blinding form entry.)

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'R06', 'every rule in force traces to a Blinding form and an APPROVED decision row', '0 bad rules',
       COUNT(*)::VARCHAR || ' bad rules', IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM V_BLINDING_RULE_EFFECTIVE b
LEFT JOIN RULE_REQUEST q  ON q.RULE_REQUEST_ID = b.RULE_REQUEST_ID
LEFT JOIN RULE_DECISION d ON d.RULE_REQUEST_ID = b.RULE_REQUEST_ID AND d.DECISION = 'APPROVED'
WHERE q.RULE_REQUEST_ID IS NULL OR d.RULE_REQUEST_ID IS NULL OR COALESCE(TRIM(q.FORM_REF), '') = '';

INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'A01', 'audit trail intact (hash chain per study)', '0 broken links', COUNT(*)::VARCHAR || ' broken links',
       IFF(COUNT(*) = 0, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM (SELECT a.*, LAG(a.ROW_HASH) OVER (PARTITION BY a.STUDY_OID ORDER BY a.EVENT_ID) AS LH FROM AUDIT_LOG a) x
WHERE x.PREV_HASH <> COALESCE(x.LH, 'GENESIS')
   OR x.ROW_HASH <> UF_AUDIT_HASH(x.PREV_HASH, x.EVENT_ID, x.EVENT_TS, x.STUDY_OID, x.EVENT_TYPE, x.ACTOR, x.REF, x.DETAIL);


-- Section 2 MASKING_ADMIN: the policies themselves --------------------------------------------
USE ROLE IDENTIFIER($MASKING_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);

SHOW MASKING POLICIES LIKE 'MASK_ITEM_VALUE';
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'M01', 'MASK_ITEM_VALUE exists, owned by MASKING_ADMIN', 'MASKING_ADMIN', COALESCE(MAX("owner"), '(missing)'),
       IFF(MAX("owner") = 'MASKING_ADMIN', 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

SHOW ROW ACCESS POLICIES LIKE 'RAP_STUDY_ACCESS';
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'M02', 'RAP_STUDY_ACCESS exists, owned by MASKING_ADMIN', 'MASKING_ADMIN', COALESCE(MAX("owner"), '(missing)'),
       IFF(MAX("owner") = 'MASKING_ADMIN', 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

DESCRIBE MASKING POLICY MASK_ITEM_VALUE;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'M03', 'mask checks user, role in use and London date', 'all 3',
       IFF(CONTAINS("body", 'CURRENT_USER()'), 'user ', '') || IFF(CONTAINS("body", 'CURRENT_ROLE()'), 'role ', '') || IFF(CONTAINS("body", 'Europe/London'), 'date', ''),
       IFF(CONTAINS("body", 'CURRENT_USER()') AND CONTAINS("body", 'CURRENT_ROLE()') AND CONTAINS("body", 'Europe/London'), 'PASS', 'FAIL'),
       CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

DESCRIBE ROW ACCESS POLICY RAP_STUDY_ACCESS;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'M04', 'row gate checks user, role in use and London date', 'all 3',
       IFF(CONTAINS("body", 'CURRENT_USER()'), 'user ', '') || IFF(CONTAINS("body", 'CURRENT_ROLE()'), 'role ', '') || IFF(CONTAINS("body", 'Europe/London'), 'date', ''),
       IFF(CONTAINS("body", 'CURRENT_USER()') AND CONTAINS("body", 'CURRENT_ROLE()') AND CONTAINS("body", 'Europe/London'), 'PASS', 'FAIL'),
       CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

SHOW GRANTS ON MASKING POLICY MASK_ITEM_VALUE;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'M05', 'APPLY on the mask held only by SYSADMIN', 'SYSADMIN', COALESCE(LISTAGG("grantee_name", ','), '(none)'),
       IFF(COUNT(*) = 1 AND MAX("grantee_name") = 'SYSADMIN', 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "privilege" <> 'OWNERSHIP';

SHOW GRANTS ON ROW ACCESS POLICY RAP_STUDY_ACCESS;
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'M06', 'APPLY on the row gate held only by SYSADMIN', 'SYSADMIN', COALESCE(LISTAGG("grantee_name", ','), '(none)'),
       IFF(COUNT(*) = 1 AND MAX("grantee_name") = 'SYSADMIN', 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "privilege" <> 'OWNERSHIP';


-- Section 3 GOVERNANCE: the study's working roles -------------------------------------------------
USE ROLE IDENTIFIER($GOV_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);

-- G1 each working role holds only: USAGE on warehouse/database/schema, SELECT on the feed view (and USAGE on the app)
-- G2 every holder of a working role has a register row for that role, and every register row's person holds it
BEGIN
  LET p STRING := (SELECT $ROLE_PREFIX); LET st STRING := (SELECT $STUDY_OID);
  LET run STRING := (SELECT $RUN_ID);    LET feed STRING := (SELECT $FEED_VIEW);
  LET suffixes ARRAY := ARRAY_CONSTRUCT('_STAT_BLINDED', '_STAT_UNBLINDED', '_PROG_BLINDED', '_PROG_UNBLINDED',
                                        '_DM_BLINDED', '_DM_UNBLINDED', '_ADHOC_BLINDED');
  LET extra STRING := ''; LET holders_no_row STRING := ''; LET rows_no_holder STRING := '';
  FOR i IN 0 TO ARRAY_SIZE(:suffixes) - 1 DO
    LET r STRING := :p || GET(:suffixes, :i)::STRING; LET x STRING := ''; LET h STRING := ''; LET w STRING := '';
    EXECUTE IMMEDIATE 'SHOW GRANTS TO ROLE ' || :r;
    SELECT COALESCE(LISTAGG("privilege" || ' ' || "granted_on" || ' ' || "name", '; '), '') INTO :x
      FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
     WHERE NOT ("privilege" = 'USAGE' AND "granted_on" IN ('WAREHOUSE', 'DATABASE', 'SCHEMA', 'STREAMLIT'))
       AND NOT ("privilege" = 'SELECT' AND "granted_on" = 'VIEW' AND ENDSWITH("name", :feed));
    IF (:x <> '') THEN extra := :extra || ' | ' || :r || ': ' || :x; END IF;
    EXECUTE IMMEDIATE 'SHOW GRANTS OF ROLE ' || :r;
    SELECT COALESCE(LISTAGG(g."grantee_name", ','), '') INTO :h
      FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) g
     WHERE g."granted_to" = 'USER'
       AND NOT EXISTS (SELECT 1 FROM ACCESS_ACTIVE a WHERE a.STUDY_OID = :st AND a.USER_NAME = g."grantee_name" AND a.ROLE_NAME = :r);
    IF (:h <> '') THEN holders_no_row := :holders_no_row || ' | ' || :r || ': ' || :h; END IF;
    EXECUTE IMMEDIATE 'SHOW GRANTS OF ROLE ' || :r;
    SELECT COALESCE(LISTAGG(a.USER_NAME, ','), '') INTO :w
      FROM ACCESS_ACTIVE a
     WHERE a.STUDY_OID = :st AND a.ROLE_NAME = :r
       AND NOT EXISTS (SELECT 1 FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) g WHERE g."granted_to" = 'USER' AND g."grantee_name" = a.USER_NAME);
    IF (:w <> '') THEN rows_no_holder := :rows_no_holder || ' | ' || :r || ': ' || :w; END IF;
  END FOR;
  INSERT INTO BLINDING_CHECK_RESULT VALUES
    (:run, 'G1', 'working roles hold only USAGE (warehouse, database, schema, app) and SELECT on the feed view',
     'nothing else', IFF(:extra = '', 'nothing else', :extra), IFF(:extra = '', 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()),
    (:run, 'G2', 'every holder of a working role has a register row for it (no grant outside the app)',
     'none', IFF(:holders_no_row = '', 'none', :holders_no_row), IFF(:holders_no_row = '', 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()),
    (:run, 'G3', 'every register row''s person holds its working role',
     'none missing', IFF(:rows_no_holder = '', 'none missing', :rows_no_holder), IFF(:rows_no_holder = '', 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP());
  RETURN 'governance checks written';
END;

SHOW PROCEDURES LIKE '%_SP_SET_WORKING_ROLE';
INSERT INTO BLINDING_CHECK_RESULT
SELECT $RUN_ID, 'G4', 'the study''s role procedure exists, owned by GOVERNANCE', '1', COUNT(*)::VARCHAR,
       IFF(COUNT(*) = 1, 'PASS', 'FAIL'), CURRENT_ROLE(), CURRENT_TIMESTAMP()
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE "name" = $ROLE_PREFIX || '_SP_SET_WORKING_ROLE';


-- Section 4 SYSADMIN: the final table, as a text file in the stage and on screen -----------------------------------
USE ROLE IDENTIFIER($BUILD_ROLE);
-- 4.0 First, take back what Section 1.0 lent: nobody but SYSADMIN may write check results or read the register directly
REVOKE INSERT ON TABLE BLINDING_CHECK_RESULT FROM ROLE IDENTIFIER($MASKING_ROLE);
REVOKE INSERT ON TABLE BLINDING_CHECK_RESULT FROM ROLE IDENTIFIER($GOV_ROLE);
REVOKE SELECT ON TABLE ACCESS_ACTIVE         FROM ROLE IDENTIFIER($GOV_ROLE);
USE SECONDARY ROLES NONE;
USE WAREHOUSE IDENTIFIER($WH);
USE SCHEMA IDENTIFIER($FQ_SCHEMA);

-- 4.1 The final table: SUMMARY first, then every check (FAIL, then WARN, then PASS)
CREATE OR REPLACE TEMPORARY TABLE BLINDING_REPORT AS
SELECT ORD, CHECK_ID, WHAT, EXPECTED, ACTUAL, RESULT FROM (
  SELECT 0 AS ORD, 'SUMMARY' AS CHECK_ID, COUNT(*) || ' checks' AS WHAT, COUNT_IF(RESULT = 'PASS') || ' PASS' AS EXPECTED,
         COUNT_IF(RESULT = 'FAIL') || ' FAIL' AS ACTUAL, COUNT_IF(RESULT = 'WARN') || ' WARN' AS RESULT
    FROM BLINDING_CHECK_RESULT WHERE RUN_ID = $RUN_ID
  UNION ALL
  SELECT DECODE(RESULT, 'FAIL', 1, 'WARN', 2, 3), CHECK_ID, WHAT, EXPECTED, ACTUAL, RESULT
    FROM BLINDING_CHECK_RESULT WHERE RUN_ID = $RUN_ID);

-- 4.2 The same table as a text file in the stage: @BLINDING_REPORTS/checks_<run>.txt
BEGIN
  LET run STRING := (SELECT $RUN_ID);
  EXECUTE IMMEDIATE 'COPY INTO @BLINDING_REPORTS/checks_' || :run || '.txt FROM (
       SELECT LINE FROM (
         SELECT -3 AS ORD, ''''  AS CHECK_ID, ''BLINDING CONTROL CHECKS  run ' || :run || ' (London)'' AS LINE
         UNION ALL SELECT -2, '''', ''''
         UNION ALL SELECT -1, '''', RPAD(''CHECK'', 9) || ''| '' || RPAD(''RESULT'', 7) || ''| '' || RPAD(''EXPECTED'', 22) || ''| '' || RPAD(''ACTUAL'', 32) || ''| WHAT''
         UNION ALL SELECT ORD, CHECK_ID,
                          CHECK_ID || REPEAT('' '', GREATEST(9 - LENGTH(CHECK_ID), 0)) || ''| ''
                       || RESULT   || REPEAT('' '', GREATEST(7 - LENGTH(RESULT), 0))   || ''| ''
                       || EXPECTED || REPEAT('' '', GREATEST(22 - LENGTH(EXPECTED), 0)) || ''| ''
                       || ACTUAL   || REPEAT('' '', GREATEST(32 - LENGTH(ACTUAL), 0))   || ''| '' || WHAT
             FROM BLINDING_REPORT)
       ORDER BY ORD, CHECK_ID)
     FILE_FORMAT = (TYPE = CSV FIELD_DELIMITER = NONE FIELD_OPTIONALLY_ENCLOSED_BY = NONE ESCAPE_UNENCLOSED_FIELD = NONE COMPRESSION = NONE)
     HEADER = FALSE SINGLE = TRUE OVERWRITE = TRUE MAX_FILE_SIZE = 50000000';
  RETURN 'report written: @BLINDING_REPORTS/checks_' || :run || '.txt';
END;

-- 4.4 The final table on screen
SELECT CHECK_ID, RESULT, EXPECTED, ACTUAL, WHAT FROM BLINDING_REPORT ORDER BY ORD, CHECK_ID;

-- 4.5 The report files in the stage (download from Snowsight: Data > Databases > schema > Stages > BLINDING_REPORTS)
LIST @BLINDING_REPORTS;

-- =============================================================================
-- MANUAL TESTS (need people to log in as themselves; record the result next to the report)
--   T1 Person with a BLINDED register row, using that working role: rows visible, values BLINDED except CLEAR items.
--   T2 Same person, any other role:                                     0 rows.
--   T3 Person with an UNBLINDED register row, using that working role:  real values.
--   T4 Person with an ADHOC row:                                        every value BLINDED.
--   T5 After suspension in the app:                                     0 rows (run ALTER SESSION SET USE_CACHED_RESULT = FALSE first).
--   T6 Change session timezone (ALTER SESSION SET TIMEZONE = 'Pacific/Kiritimati'), repeat T1: same result.
-- =============================================================================
