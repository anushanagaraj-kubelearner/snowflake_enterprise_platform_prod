# =============================================================================
# streamlit_app.py — Clinical Data Access Manager (blinding control v6)
# WHAT   Five views. The app shows screens and calls procedures; it writes nothing itself.
#          1 Request access   everyone with BLINDING_USER: my access, my requests, request / withdraw / give up
#          2 Approve access   approvers: the queue of REQUESTED requests, approve or reject
#          3 Apply access     the data owner: the queue of APPROVED requests, apply or decline; the register;
#                             end access; end expired; appoint approvers
#          4 Blinding rules   everyone sees the state; the data owner enters a signed Blinding form
#                             (typed, or bulk loaded from the pre-filled template)
#          5 Audit trail      approvers and the data owner: audit log, every request with its steps,
#                             Blinding forms applied (with the stored file), the latest checks
# WHO    The viewer is the Snowflake login Streamlit reports. Every procedure receives it last (P_VIEWER) and
#        re-checks the person's roles itself; the app only decides what to show.
#        Identity guard: if Snowflake's CURRENT_USER() is set and differs from the viewer, the app stops.
# DATA   No patient value is read or shown anywhere in this app. Keys (form, item) and counts only.
# SPEED  Who you are, your roles and the study list are read once per session. Data reads are kept until you act
#        or press Refresh, and an action drops only the data reads. Nothing runs on a timer.
# DEPLOY 04_app_deploy.sql (warehouse runtime). Theme: .streamlit/config.toml on the stage.
# =============================================================================
import csv
import datetime as dt
import html
import io
import json
import re

import pandas as pd
import streamlit as st

try:
    from snowflake.snowpark.context import get_active_session
except Exception:            # local tests inject a session through st.session_state["_test_session"]
    get_active_session = None

APP_VERSION = "v6"
LOGIN_RE = re.compile(r"^[A-Z0-9_.@-]{1,255}$")
FUNCTIONS = {"STAT": "Statistician", "PROG": "Programmer", "DM": "Data manager", "ADHOC": "Ad hoc reviewer (blinded only)"}
SIGHTS = ["BLINDED", "UNBLINDED"]
SET_TO = ["Blinded", "Visible"]
TEMPLATE_HEADERS = ["FORM_OID", "ITEM_OID", "TODAY", "SET_TO", "REASON"]
CONFIRM_TEXT = "I confirm the details above match the signed paper form. My Snowflake login and the time are recorded."

st.set_page_config(page_title="Clinical Data Access Manager", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
.bc-brand { font-size:13px; font-weight:800; letter-spacing:.06em; text-transform:uppercase; color:#0055A4; margin-bottom:2px; }
.bc-eyebrow { font-size:11px; font-weight:700; letter-spacing:.09em; text-transform:uppercase; color:#5B6B82; }
.bc-h1 { font-size:26px; font-weight:700; margin:0 0 2px 0; color:#0F2440; }
.bc-sub { font-size:14px; color:#5B6B82; margin:0 0 14px 0; }
.bc-pill { display:inline-block; font-size:11px; font-weight:700; padding:3px 9px; border-radius:999px; margin-right:4px; }
.bc-pill.blind { background:#E2EDF5; color:#1F5F8B; } .bc-pill.unbl { background:#FBEADB; color:#97440F; }
.bc-pill.ok { background:#E3F3EC; color:#1E6B45; } .bc-pill.bad { background:#FBE6E4; color:#A8231B; }
.bc-pill.mute { background:#EEF3FA; color:#5B6B82; } .bc-pill.new { background:#FFF4D6; color:#7A5300; }
.bc-card { border:1px solid #D5DFEC; border-radius:10px; padding:12px 16px; margin-bottom:10px; background:#FFFFFF; }
.bc-meta { font-size:13px; color:#3C4A5E; margin:2px 0; }
.bc-kpis { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:14px; }
.bc-kpi { border:1px solid #D5DFEC; border-radius:12px; padding:12px 18px; min-width:150px; background:#FFFFFF; }
.bc-kpi p { font-size:12px; margin:0 0 2px 0; color:#5B6B82; } .bc-kpi b { font-size:26px; color:#0F2440; }
.bc-note { border-radius:8px; padding:10px 14px; font-size:14px; margin-bottom:12px; background:#EEF3FA; color:#0F2440; border:1px solid #C9D7EA; }
.bc-empty { border:1px dashed #B9C7D9; border-radius:12px; padding:22px; text-align:center; color:#5B6B82; margin:10px 0; }
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------------------------------------
# 1. Session, identity, schema
# ------------------------------------------------------------------------------------------------
def get_session():
    if "_test_session" in st.session_state:
        return st.session_state["_test_session"]
    if get_active_session is None:
        return None
    return get_active_session()


session = get_session()
if session is None:
    st.error("No Snowflake session. This app runs inside Snowflake (deployed by 04_app_deploy.sql).")
    st.stop()


def q(sql, params=None):
    """Read-only query -> pandas DataFrame. Column names upper case as Snowflake returns them."""
    return session.sql(sql, params=params or []).to_pandas()


def one(sql, params=None):
    df = q(sql, params)
    return None if df.empty else df.iloc[0, 0]


def call(proc, *args):
    """Call a procedure; returns its text ('OK: …', 'REFUSED: …', 'FAILED: …')."""
    try:
        res = session.call(proc, *args)
        return str(res) if res is not None else "FAILED: no result"
    except Exception as e:
        return "FAILED: " + str(e)


def viewer_login():
    """The login Streamlit reports for the person viewing (st.user, or st.experimental_user on older releases)."""
    for attr in ("user", "experimental_user"):
        u = getattr(st, attr, None)
        if u is None:
            continue
        try:   # the Snowflake user name only: login name and email are not what CURRENT_USER() returns
            v = u.get("user_name") if hasattr(u, "get") else getattr(u, "user_name", None)
        except Exception:
            v = None
        if v:
            return str(v)
    return None


def identify():
    row = q("SELECT CURRENT_USER() AS U, CURRENT_DATABASE() AS D, CURRENT_SCHEMA() AS S").iloc[0]
    cu = row["U"] if pd.notna(row["U"]) else None
    viewer = viewer_login()
    if cu and viewer and cu != viewer:
        st.error(f"Identity guard: Snowflake reports {cu} but Streamlit reports {viewer}. The app has stopped. "
                 "Close the tab, sign in again, and tell the data owner if it happens twice.")
        st.stop()
    viewer = viewer or cu
    if not viewer or not LOGIN_RE.match(viewer):
        st.error("You could not be identified (logins must be upper case A-Z 0-9 _ . @ -). The app has stopped.")
        st.stop()
    db, sc = row["D"], row["S"]
    if not db or not sc or pd.isna(db) or pd.isna(sc):
        st.error("The app has no database/schema context. Deploy it with 04_app_deploy.sql.")
        st.stop()
    return viewer, f"{db}.{sc}"


if "_who" not in st.session_state:          # once per browser session: who is viewing, and where the app lives
    st.session_state["_who"] = identify()
VIEWER, SC = st.session_state["_who"]


# ------------------------------------------------------------------------------------------------
# 2. Cache, flash messages, helpers
#    "session" reads (study list, today's date) are kept until Refresh.
#    "data" reads (requests, register, fields, roles held, audit) are kept until an action or Refresh.
# ------------------------------------------------------------------------------------------------
def london_now():
    try:
        from zoneinfo import ZoneInfo
        return dt.datetime.now(ZoneInfo("Europe/London"))
    except Exception:
        return dt.datetime.now(dt.timezone.utc)


def kept(key, fn, tier="data"):
    cache = st.session_state.setdefault("_kept_" + tier, {})
    if key not in cache:
        if tier == "data" and not cache:
            st.session_state["_read_at"] = london_now().strftime("%H:%M")
        cache[key] = fn()
    return cache[key]


def forget(tier="data"):
    st.session_state["_kept_" + tier] = {}


def flash(result):
    st.session_state["_flash"] = result
    forget("data")
    st.rerun()


def show_flash():
    msg = st.session_state.pop("_flash", None)
    if not msg:
        return
    if msg.startswith("OK"):
        st.success(msg)
    elif msg.startswith("REFUSED"):
        st.warning(msg + "  \nIf the screen may be out of date, press Refresh and try again.")
    else:
        st.error(msg)


def esc(v):
    """Any value from the database, made safe to place inside HTML (people type names, comments, references)."""
    return html.escape("" if v is None else str(v), quote=True)


def esc_row(r):
    """A row with every text value escaped; dates and numbers kept as they are for formatting."""
    return {k: (esc(v) if isinstance(v, str) else v) for k, v in dict(r).items()}


def pill(text, cls):
    return f'<span class="bc-pill {cls}">{esc(text)}</span>'


def status_pill(status):
    cls = {"APPLIED": "ok", "APPROVED": "unbl", "REQUESTED": "new", "REJECTED": "bad", "WITHDRAWN": "mute",
           "ENDED": "mute", "EXPIRED": "mute"}.get(status, "mute")
    return pill(status, cls)


def d(v):
    """Date or timestamp -> 'DD Mon YYYY' (dates) or 'DD Mon YYYY HH:MM' (timestamps); blank for NULL."""
    if v is None or (isinstance(v, float) and pd.isna(v)) or pd.isna(v):
        return ""
    if isinstance(v, (pd.Timestamp, dt.datetime)):
        return v.strftime("%d %b %Y %H:%M")
    if isinstance(v, dt.date):
        return v.strftime("%d %b %Y")
    return str(v)


def today_london():
    return one("SELECT CONVERT_TIMEZONE('Europe/London', CURRENT_TIMESTAMP())::DATE")


def empty(text):
    st.markdown(f'<div class="bc-empty">{text}</div>', unsafe_allow_html=True)


def head(title, sub):
    st.markdown(f'<div class="bc-h1">{esc(title)}</div><div class="bc-sub">{esc(sub)}</div>', unsafe_allow_html=True)


# ------------------------------------------------------------------------------------------------
# 3. Reads (every one is metadata: keys, names, dates, statuses; never a patient value)
# ------------------------------------------------------------------------------------------------
def studies():
    return kept("studies", lambda: q(f"SELECT STUDY_OID, ROLE_PREFIX, BLIND_PLAN FROM {SC}.STUDY_REGISTRY WHERE ACTIVE ORDER BY STUDY_OID"), "session")


def my_register_row(study):
    return kept(("reg", study, VIEWER), lambda: q(
        f"SELECT * FROM {SC}.ACCESS_ACTIVE WHERE STUDY_OID = ? AND USER_NAME = ?", [study, VIEWER]))


def requests(study, statuses=None, user=None):
    sql = f"SELECT * FROM {SC}.V_ACCESS_REQUEST_STATUS WHERE STUDY_OID = ?"
    params = [study]
    if statuses:
        sql += " AND STATUS IN (" + ",".join("?" * len(statuses)) + ")"
        params += list(statuses)
    if user:
        sql += " AND USER_NAME = ?"
        params.append(user)
    sql += " ORDER BY REQUESTED_AT DESC"
    return kept(("req", study, tuple(statuses or ()), user), lambda: q(sql, params))


def register(study):
    return kept(("register", study), lambda: q(
        f"SELECT * FROM {SC}.ACCESS_ACTIVE WHERE STUDY_OID = ? ORDER BY USER_NAME", [study]))


def key_status(study):
    return kept(("keys", study), lambda: q(
        f"SELECT FORM_OID, ITEM_OID, STATE, ROWS_TOTAL, RULE_REQUEST_ID, UPDATED_AT FROM {SC}.V_KEY_STATUS "
        f"WHERE STUDY_OID = ? ORDER BY FORM_OID, ITEM_OID", [study]))


def rules_in_force(study):
    return kept(("rules", study), lambda: q(
        f"SELECT FORM_OID, ITEM_OID, REASON, RULE_REQUEST_ID, CREATED_BY, CREATED_AT FROM {SC}.V_BLINDING_RULE_EFFECTIVE "
        f"WHERE STUDY_OID = ? ORDER BY FORM_OID, ITEM_OID", [study]))


def forms_applied(study):
    return kept(("forms", study), lambda: q(
        f"SELECT r.RULE_REQUEST_ID, r.FORM_REF, r.FORM_SIGNED_DATE, r.ENTERED_BY_NAME, r.ENTERED_BY, r.ENTERED_AT, r.SOURCE, "
        f"r.FILE_NAME, r.FILE_MD5, r.ROW_COUNT, d.NEW_KEYS_CLASSIFIED FROM {SC}.RULE_REQUEST r "
        f"LEFT JOIN {SC}.RULE_DECISION d ON d.RULE_REQUEST_ID = r.RULE_REQUEST_ID WHERE r.STUDY_OID = ? ORDER BY r.ENTERED_AT DESC", [study]))


def form_rows(rid):
    return q(f"SELECT ROW_NO, FORM_OID, ITEM_OID, ACTION, REASON FROM {SC}.RULE_REQUEST_ROW WHERE RULE_REQUEST_ID = ? ORDER BY ROW_NO", [rid])


def snapshot_fields(study):
    """Every field with its state, the Blinding form that set it, and the reason (metadata only)."""
    return kept(("snap_fields", study), lambda: q(
        f"""SELECT k.FORM_OID, k.ITEM_OID, k.STATE, k.UPDATED_AT, q.RULE_REQUEST_ID, q.FORM_REF, q.FORM_SIGNED_DATE,
                   q.ENTERED_BY_NAME, q.ENTERED_BY, COALESCE(ri.REASON, rf.REASON) AS REASON
              FROM {SC}.V_KEY_STATUS k
              LEFT JOIN {SC}.RULE_REQUEST q      ON q.RULE_REQUEST_ID = k.RULE_REQUEST_ID
              LEFT JOIN {SC}.RULE_REQUEST_ROW ri ON ri.RULE_REQUEST_ID = k.RULE_REQUEST_ID AND ri.FORM_OID = k.FORM_OID AND ri.ITEM_OID = k.ITEM_OID
              LEFT JOIN {SC}.RULE_REQUEST_ROW rf ON rf.RULE_REQUEST_ID = k.RULE_REQUEST_ID AND rf.FORM_OID = k.FORM_OID AND rf.ITEM_OID IS NULL
             WHERE k.STUDY_OID = ? ORDER BY k.FORM_OID, k.ITEM_OID""", [study]))


def rules_history(study):
    """Every Blinded / Visible change ever recorded on the study, oldest first."""
    return kept(("history", study), lambda: q(
        f"""SELECT q.ENTERED_AT, q.RULE_REQUEST_ID, q.FORM_REF, q.FORM_SIGNED_DATE, q.ENTERED_BY_NAME, q.ENTERED_BY,
                   r.ROW_NO, r.FORM_OID, r.ITEM_OID, r.ACTION, r.REASON
              FROM {SC}.RULE_REQUEST_ROW r JOIN {SC}.RULE_REQUEST q ON q.RULE_REQUEST_ID = r.RULE_REQUEST_ID
             WHERE q.STUDY_OID = ? ORDER BY q.ENTERED_AT, r.ROW_NO""", [study]))


def audit(study):
    return kept(("audit", study), lambda: q(
        f"SELECT EVENT_ID, EVENT_TS, EVENT_TYPE, ACTOR, REF, DETAIL FROM {SC}.AUDIT_LOG WHERE STUDY_OID = ? ORDER BY EVENT_ID DESC LIMIT 500", [study]))


def latest_checks():
    return kept("checks", lambda: q(
        f"SELECT CHECK_ID, WHAT, EXPECTED, ACTUAL, RESULT, RUN_AT FROM {SC}.BLINDING_CHECK_RESULT "
        f"WHERE RUN_ID = (SELECT MAX(RUN_ID) FROM {SC}.BLINDING_CHECK_RESULT) "
        f"ORDER BY DECODE(RESULT, 'FAIL', 0, 'WARN', 1, 2), CHECK_ID"))


def role_holders(role):
    def _read():
        try:
            session.sql(f"SHOW GRANTS OF ROLE {role}").collect()
            return q('SELECT "grantee_name" AS LOGIN, "created_on" AS SINCE FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) '
                     'WHERE "granted_to" = \'USER\' ORDER BY 1')
        except Exception:
            return pd.DataFrame(columns=["LOGIN", "SINCE"])
    return kept(("holders", role), _read)


# ------------------------------------------------------------------------------------------------
# 4. Blinding form helpers (pure functions; tested in tests/test_app_functions.py)
# ------------------------------------------------------------------------------------------------
def cell(v):
    """Any grid or file cell as clean text: None, NaN and pandas NA become ''."""
    if v is None:
        return ""
    try:
        if pd.isna(v):
            return ""
    except (TypeError, ValueError):
        pass
    return str(v).strip()


def fields_frame(keys, rules):
    """One row per field in the feed: what it is today, and the choice (Blinded / Visible), starting as today."""
    whole = {cell(f) for f, i in zip(rules["FORM_OID"], rules["ITEM_OID"]) if not cell(i)} if not rules.empty else set()
    out = {"FORM_OID": [], "ITEM_OID": [], "TODAY": [], "SET_TO": [], "REASON": []}
    for f, i, state in zip(keys["FORM_OID"], keys["ITEM_OID"], keys["STATE"]) if not keys.empty else []:
        f, i = cell(f), cell(i)
        if not i:
            continue                           # no item id: never classified, always BLINDED for blinded staff
        if state == "NEW":
            today, choice = "Blinded (new)", "Blinded"
        elif state == "BLIND":
            today, choice = ("Blinded (whole form)" if f in whole else "Blinded"), "Blinded"
        else:
            today, choice = "Visible", "Visible"
        for k, v in (("FORM_OID", f), ("ITEM_OID", i), ("TODAY", today), ("SET_TO", choice), ("REASON", "")):
            out[k].append(v)
    return pd.DataFrame({k: pd.Series(v, dtype="string") for k, v in out.items()})


def to_actions(choices, keys, rules, default_reason=""):
    """Blinded / Visible choices -> the rule rows the procedure records (ADD / CLEAR / REMOVE), and any problems.
       new field   + Blinded -> ADD     new field   + Visible -> CLEAR
       visible     + Blinded -> ADD     blinded     + Visible -> REMOVE      unchanged -> nothing
       A form blinded as a whole: making any of its fields Visible lifts the form blind (REMOVE form) and, in the
       same entry, keeps every field still chosen Blinded blinded (ADD item), so nothing else becomes visible.
       Every row sent names one item: the app never sends a whole-form ADD or CLEAR."""
    status = {(cell(f), cell(i)): st_ for f, i, st_ in zip(keys["FORM_OID"], keys["ITEM_OID"], keys["STATE"])
              if cell(i)} if not keys.empty else {}
    whole = {cell(f) for f, i in zip(rules["FORM_OID"], rules["ITEM_OID"]) if not cell(i)} if not rules.empty else set()
    item_rules = {(cell(f), cell(i)) for f, i in zip(rules["FORM_OID"], rules["ITEM_OID"]) if cell(i)} if not rules.empty else set()
    chosen, problems = {}, []
    for c in choices:
        form, item = cell(c.get("form")), cell(c.get("item"))
        if not form and not item:              # a blank line (an empty grid row, or a gap in the file)
            continue
        where = f"{form}/{item}" if item else form
        if not item:
            problems.append(f"{where}: every row needs an ITEM_OID")
            continue
        if (form, item) in chosen:
            problems.append(f"{where}: listed twice")
            continue
        if (form, item) not in status:
            problems.append(f"{where}: not in the data (press Refresh if the screen is out of date)")
            continue
        choice = cell(c.get("set_to")).capitalize()
        if choice not in SET_TO:
            problems.append(f"{where}: choose Blinded or Visible")
            continue
        chosen[(form, item)] = (choice, cell(c.get("reason")) or cell(default_reason))

    actions = []

    def add(form, item, action, reason, auto=None):
        if len(reason) < 10:
            if auto:
                reason = auto
            else:
                problems.append(f"{form}/{item}: give a reason of 10 characters or more (or fill in the reason for all rows)")
                return
        actions.append({"form": form, "item": item, "action": action, "reason": reason})

    lifted = {f for (f, i), (ch, _) in chosen.items() if f in whole and ch == "Visible"}
    for (form, item), (choice, reason) in chosen.items():
        state = status[(form, item)]
        if form in lifted:
            continue                           # handled below, form by form
        if state == "NEW":
            add(form, item, "ADD" if choice == "Blinded" else "CLEAR", reason)
        elif state == "BLIND" and choice == "Visible":
            add(form, item, "REMOVE", reason)
        elif state == "CLEAR" and choice == "Blinded":
            add(form, item, "ADD", reason)
    for form in sorted(lifted):
        form_items = [k for k in status if k[0] == form]
        missing = [i for f, i in form_items if (f, i) not in chosen]
        if missing:
            problems.append(f"{form}: to lift the whole-form blind, every field of the form must be listed ({len(missing)} missing)")
            continue
        why = next((r for (f, i), (ch, r) in chosen.items() if f == form and ch == "Visible" and len(r) >= 10), "")
        add(form, None, "REMOVE", why)
        for f, i in form_items:
            choice, reason = chosen[(f, i)]
            if choice == "Blinded" and (f, i) not in item_rules:
                add(f, i, "ADD", reason, auto=f"Stays blinded after the whole-form blind on {f} was lifted")
            elif choice == "Visible" and (f, i) in item_rules:
                add(f, i, "REMOVE", reason)
    missing_new = [k for k, st_ in status.items() if st_ == "NEW" and k not in chosen]
    if missing_new:
        problems.append(f"{len(missing_new)} new field(s) are not in the list (press Refresh): "
                        + ", ".join(f"{f}/{i}" for f, i in missing_new[:10]))
    if not actions and not problems:
        problems.append("Nothing to change: every field is already as chosen")
    if len(actions) > 500:
        problems.append("more than 500 changes in one form")
    return actions, problems


def build_template(study, keys, rules):
    """The pre-filled .xlsx: sheet RULES (every field, today's state, SET_TO to choose) and a sheet HOW TO FILL IN."""
    import openpyxl
    from openpyxl.styles import Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "RULES"
    ws.append(TEMPLATE_HEADERS)
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="0055A4")
    grid = fields_frame(keys, rules)
    for _, r in grid.iterrows():
        ws.append([cell(r["FORM_OID"]), cell(r["ITEM_OID"]), cell(r["TODAY"]), cell(r["SET_TO"]), ""])
    if len(grid):
        dv = DataValidation(type="list", formula1='"Blinded,Visible"', allow_blank=False)
        ws.add_data_validation(dv)
        dv.add(f"D2:D{len(grid) + 1}")
    for col, w in zip("ABCDE", (24, 24, 22, 12, 60)):
        ws.column_dimensions[col].width = w
    ws.freeze_panes = "A2"
    how = wb.create_sheet("HOW TO FILL IN")
    for ln in [
        f"Blinding form template for study {study}",
        "",
        "Sheet RULES lists every field in the Medidata feed. TODAY shows what a blinded person sees now.",
        "1. In SET_TO choose Blinded or Visible for each field, as the signed Blinding form says.",
        "   New fields start as Blinded. Change one to Visible only if the signed form says it stays visible.",
        "2. Give a REASON (10 characters or more) for every field you change, and for every new field.",
        "   A row left blank uses the reason typed in the app for all rows.",
        "3. Do not delete rows, change the headers, merge cells or use formulas.",
        "4. Save as .xlsx (or .csv with the same columns) and upload it in the app: Blinding rules > Enter a Blinding form.",
        "",
        "The app shows what will change before you confirm. The file is kept with its fingerprint (md5) as evidence.",
    ]:
        how.append([ln])
    how.column_dimensions["A"].width = 120
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def parse_rules_file(name, data):
    """Rows from an uploaded .xlsx (sheet RULES) or .csv -> (choices, errors). Choices: dicts form/item/set_to/reason."""
    grid = []
    lname = (name or "").lower()
    try:
        if lname.endswith(".xlsx"):
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(data), data_only=False)
            if "RULES" not in wb.sheetnames:
                return [], ["the workbook has no RULES sheet"]
            ws = wb["RULES"]
            if ws.merged_cells.ranges:
                return [], ["the RULES sheet has merged cells"]
            for r in ws.iter_rows():
                cells = list(r[:5])
                if any(c.data_type == "f" for c in cells):
                    return [], [f"row {cells[0].row} holds a formula; type the values"]
                grid.append([cell(c.value) for c in cells] + [""] * (5 - len(cells)))
        elif lname.endswith(".csv"):
            for row in csv.reader(io.StringIO(data.decode("utf-8-sig"))):
                grid.append([cell(v) for v in row[:5]] + [""] * (5 - len(row)))
        else:
            return [], ["upload an .xlsx (sheet RULES) or a .csv"]
    except Exception as e:
        return [], ["the file could not be read: " + str(e)]
    if not grid:
        return [], ["the file is empty"]
    if [h.upper() for h in grid[0]] != TEMPLATE_HEADERS:
        return [], ["headers must be " + ", ".join(TEMPLATE_HEADERS) + " (download the template)"]
    choices = [{"form": g[0], "item": g[1], "set_to": g[3], "reason": g[4]} for g in grid[1:] if any(g)]
    return choices, ([] if choices else ["no rows under the header"])


XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
STATE_WORDS = {"BLIND": "Blinded", "CLEAR": "Visible", "NEW": "Blinded – not yet reviewed"}
CHANGE_WORDS = {"ADD": "Blinded", "CLEAR": "Visible (new field)", "REMOVE": "Visible (blind lifted)"}


def plain(v):
    """A value Excel can hold: dates and times as text (London), blanks as ''."""
    if v is None:
        return ""
    try:
        if pd.isna(v):
            return ""
    except (TypeError, ValueError):
        pass
    if isinstance(v, (pd.Timestamp, dt.datetime)):
        return d(v)
    if isinstance(v, dt.date):
        return d(v)
    return v


def workbook(sheets):
    """sheets: list of (name, list of rows, list of headers or None). Returns .xlsx bytes."""
    import openpyxl
    from openpyxl.styles import Font, PatternFill
    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    for name, rows, headers in sheets:
        ws = wb.create_sheet(name[:31])
        if headers:
            ws.append(headers)
            for c in ws[1]:
                c.font = Font(bold=True, color="FFFFFF")
                c.fill = PatternFill("solid", fgColor="0055A4")
            ws.freeze_panes = "A2"
        for r in rows:
            ws.append([plain(v) for v in r])
        for col in ws.columns:
            width = max((len(str(c.value)) for c in col if c.value is not None), default=8)
            ws.column_dimensions[col[0].column_letter].width = min(max(width + 2, 10), 60)
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def build_snapshot(study, plan, fields, forms, history, who, when):
    """Blinding snapshot: Summary, Fields, Blinding forms, History. Field names and decisions only, no patient values."""
    states = [STATE_WORDS.get(s, s) for s in fields["STATE"]] if not fields.empty else []
    summary = [["Study", study], ["Blind plan", plan], ["Snapshot taken (London)", when], ["Downloaded by", who],
               ["Fields in the feed", len(states)], ["Blinded", sum(1 for s in states if s == "Blinded")],
               ["Visible", sum(1 for s in states if s == "Visible")],
               ["Blinded – not yet reviewed", sum(1 for s in states if s.startswith("Blinded –"))], [],
               ["What this is", "Which fields a BLINDED person sees as BLINDED and which they see, at the time above."],
               ["", "Unblinded staff see every field; ad hoc staff see none. No patient values are in this file."]]
    f_rows = []
    for (_, r), state in zip(fields.iterrows(), states):
        since_form = cell(r["FORM_REF"])
        if r["STATE"] == "BLIND" and not since_form:
            note = "Blinded by a whole-form rule (field arrived after the form was blinded)"
        elif r["STATE"] == "NEW":
            note = "Not yet named by a Blinding form: blinded until one does"
        else:
            note = ""
        f_rows.append([r["FORM_OID"], r["ITEM_OID"], state, r["UPDATED_AT"], since_form, r["FORM_SIGNED_DATE"],
                       cell(r["ENTERED_BY_NAME"]) + (f" ({cell(r['ENTERED_BY'])})" if cell(r["ENTERED_BY"]) else ""),
                       cell(r["REASON"]), note])
    form_rows_ = [[f["RULE_REQUEST_ID"], f["FORM_REF"], f["FORM_SIGNED_DATE"], f["ENTERED_BY_NAME"], f["ENTERED_BY"], f["ENTERED_AT"],
                   "File" if f["SOURCE"] == "FILE" else "On screen", f["FILE_NAME"], f["ROW_COUNT"]] for _, f in forms.iterrows()]
    h_rows = [[h["ENTERED_AT"], h["FORM_REF"], h["FORM_SIGNED_DATE"], h["FORM_OID"], h["ITEM_OID"] if cell(h["ITEM_OID"]) else "(whole form)",
               CHANGE_WORDS.get(h["ACTION"], h["ACTION"]), h["REASON"], h["ENTERED_BY_NAME"], h["ENTERED_BY"], h["RULE_REQUEST_ID"]]
              for _, h in history.iterrows()]
    return workbook([
        ("Summary", summary, None),
        ("Fields", f_rows, ["FORM_OID", "ITEM_OID", "STATE", "SINCE", "SET BY BLINDING FORM", "FORM SIGNED", "ENTERED BY", "REASON", "NOTE"]),
        ("Blinding forms", form_rows_, ["ID", "BLINDING FORM", "SIGNED", "ENTERED BY", "LOGIN", "ENTERED AT", "HOW", "FILE", "ROWS"]),
        ("History", h_rows, ["WHEN", "BLINDING FORM", "SIGNED", "FORM_OID", "ITEM_OID", "CHANGED TO", "REASON", "ENTERED BY", "LOGIN", "ID"]),
    ])


def build_register(study, plan, reg, reqs, who, when, today):
    """Access register: Summary, Current access, All requests. People, roles and dates only."""
    live = reg[(reg["EFFECTIVE_FROM"] <= today) & (reg["EFFECTIVE_TO"] >= today)] if not reg.empty else reg
    summary = [["Study", study], ["Blind plan", plan], ["Register taken (London)", when], ["Downloaded by", who],
               ["People in the register", len(reg)], ["In date today", len(live)],
               ["Blinded", int((reg["SIGHT"] == "BLINDED").sum()) if not reg.empty else 0],
               ["Unblinded", int((reg["SIGHT"] == "UNBLINDED").sum()) if not reg.empty else 0], [],
               ["What this is", "Who may query the study's data, with which sight, for which dates, and who approved and applied it."]]
    r_rows = [[r["USER_NAME"], r["PERSON_NAME"], FUNCTIONS.get(r["ROLE_FUNCTION"], r["ROLE_FUNCTION"]), r["SIGHT"], r["ROLE_NAME"],
               r["EFFECTIVE_FROM"], r["EFFECTIVE_TO"], "Yes" if r["EFFECTIVE_FROM"] <= today <= r["EFFECTIVE_TO"] else "No",
               r["REQUEST_ID"], r["APPROVED_BY"], r["APPLIED_BY"], r["APPLIED_AT"]] for _, r in reg.iterrows()]
    q_rows = [[r["REQUEST_ID"], r["STATUS"], r["USER_NAME"], r["PERSON_NAME"], r["ROLE_FUNCTION"], r["SIGHT"], r["EFFECTIVE_FROM"],
               r["EFFECTIVE_TO"], r["FORM_REF"], r["REQUESTED_AT"], r["APPROVED_BY"], r["APPROVED_AT"], r["APPLIED_BY"], r["APPLIED_AT"],
               r["REJECTED_BY"], r["REJECT_COMMENT"], r["ENDED_BY"], r["ENDED_AT"], r["END_COMMENT"]] for _, r in reqs.iterrows()]
    return workbook([
        ("Summary", summary, None),
        ("Current access", r_rows, ["LOGIN", "NAME", "FUNCTION", "SIGHT", "ROLE", "FROM", "TO", "IN DATE TODAY", "REQUEST",
                                    "APPROVED BY", "APPLIED BY", "APPLIED AT"]),
        ("All requests", q_rows, ["REQUEST", "STATUS", "LOGIN", "NAME", "FUNCTION", "SIGHT", "FROM", "TO", "ACCESS FORM", "REQUESTED AT",
                                  "APPROVED BY", "APPROVED AT", "APPLIED BY", "APPLIED AT", "REJECTED BY", "REJECT COMMENT",
                                  "ENDED BY", "ENDED AT", "END COMMENT"]),
    ])


def stamp():
    t = london_now()
    return t.strftime("%d %b %Y %H:%M"), t.strftime("%Y%m%d_%H%M")


def register_download(key):
    when, tag = stamp()
    st.download_button("⬇ Download access register (Excel)", key=key, mime=XLSX,
                       file_name=f"Access_register_{safe_name(study)}_{tag}.xlsx",
                       data=kept(("register_xlsx", study), lambda: build_register(study, plan, register(study), requests(study),
                                                                                VIEWER, when, TODAY)))


def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "")[:80]


# ------------------------------------------------------------------------------------------------
# 5. Sidebar: who, which study, what they may do
# ------------------------------------------------------------------------------------------------
st.sidebar.markdown('<div class="bc-brand">Immunocore Ltd</div><div class="bc-eyebrow">Clinical Data Access Manager</div>', unsafe_allow_html=True)
studies_df = studies()
if studies_df.empty:
    st.error("No study is under blinding yet (02b_study_onboard.sql).")
    st.stop()
study = st.sidebar.selectbox("Study", studies_df["STUDY_OID"].tolist())
prefix = studies_df.loc[studies_df["STUDY_OID"] == study, "ROLE_PREFIX"].iloc[0]
plan = studies_df.loc[studies_df["STUDY_OID"] == study, "BLIND_PLAN"].iloc[0]
# what the screens offer; every procedure checks the roles again itself
IS_APPROVER = VIEWER in set(role_holders(f"{prefix}_APPROVER")["LOGIN"])
IS_OWNER = VIEWER in set(role_holders(f"{prefix}_DATA_OWNER")["LOGIN"])
TODAY = kept("today", today_london, "session")

roles = ["Requestor"] + (["Approver"] if IS_APPROVER else []) + (["Data owner"] if IS_OWNER else [])
st.sidebar.markdown(f"**{VIEWER}**  \n" + " · ".join(roles))
st.sidebar.caption(f"Blind plan {plan} · London date {d(TODAY)} · {APP_VERSION}")
st.sidebar.caption(f"Data read at {st.session_state.get('_read_at', '')}. Press Refresh to see changes made by others.")
if st.sidebar.button("Refresh", help="Read everything again"):
    forget("data")
    forget("session")
    st.rerun()
view = st.sidebar.radio("View", ["1 Request access", "2 Approve access", "3 Apply access", "4 Blinding rules", "5 Audit trail"],
                        label_visibility="collapsed")
st.sidebar.caption("Nothing here shows patient data. Every action is recorded with your login and the time.")


# ------------------------------------------------------------------------------------------------
# 6. View 1 · Request access (everyone)
# ------------------------------------------------------------------------------------------------
def request_card(r, show_steps=True):
    r = esc_row(r)
    steps = []
    if show_steps:
        steps.append(f"Requested {d(r['REQUESTED_AT'])}")
        if pd.notna(r.get("APPROVED_AT")):
            steps.append(f"Approved by {r['APPROVED_BY']} {d(r['APPROVED_AT'])}")
        if pd.notna(r.get("APPLIED_AT")):
            steps.append(f"Applied by {r['APPLIED_BY']} {d(r['APPLIED_AT'])}")
        if pd.notna(r.get("REJECTED_AT")):
            steps.append(f"Rejected by {r['REJECTED_BY']} ({str(r['REJECTED_AS']).replace('_', ' ').lower()}) {d(r['REJECTED_AT'])}: {r['REJECT_COMMENT']}")
        if pd.notna(r.get("WITHDRAWN_AT")):
            steps.append(f"Withdrawn {d(r['WITHDRAWN_AT'])}")
        if pd.notna(r.get("ENDED_AT")):
            steps.append(f"Ended by {r['ENDED_BY']} {d(r['ENDED_AT'])}: {r['END_COMMENT']}")
    sight_cls = "unbl" if r["SIGHT"] == "UNBLINDED" else "blind"
    st.markdown(
        f'<div class="bc-card"><b>{r["REQUEST_ID"]}</b> &nbsp;{status_pill(r["STATUS"])}{pill(r["SIGHT"], sight_cls)}'
        f'<div class="bc-meta">{r["PERSON_NAME"]} ({r["USER_NAME"]}) · {FUNCTIONS.get(r["ROLE_FUNCTION"], r["ROLE_FUNCTION"])} · '
        f'{d(r["EFFECTIVE_FROM"])} to {d(r["EFFECTIVE_TO"])} · access form {r["FORM_REF"]} signed {d(r["FORM_DATE"])}</div>'
        f'<div class="bc-meta">Justification: {r["JUSTIFICATION"]}</div>'
        + (f'<div class="bc-meta">Sent to approver: {r["SENT_TO"]}</div>' if cell(r.get("SENT_TO")) else '')
        + "".join(f'<div class="bc-meta">{s}</div>' for s in steps) + "</div>", unsafe_allow_html=True)


def view_request():
    head("Request access", f"Your access to {study}, your requests, and a new request for yourself.")
    show_flash()
    reg = my_register_row(study)
    c1, c2 = st.columns([1, 1])
    with c1:
        st.subheader("My access today")
        if reg.empty:
            empty("You have no access on this study.")
        else:
            r = esc_row(reg.iloc[0])
            live = r["EFFECTIVE_FROM"] <= TODAY <= r["EFFECTIVE_TO"]
            st.markdown(
                f'<div class="bc-card">{pill(r["SIGHT"], "unbl" if r["SIGHT"] == "UNBLINDED" else "blind")}'
                f'{pill("active" if live else "not in date", "ok" if live else "mute")}'
                f'<div class="bc-meta">{FUNCTIONS.get(r["ROLE_FUNCTION"], r["ROLE_FUNCTION"])} · role {r["ROLE_NAME"]} · '
                f'{d(r["EFFECTIVE_FROM"])} to {d(r["EFFECTIVE_TO"])}</div>'
                f'<div class="bc-meta">Request {r["REQUEST_ID"]} · approved by {r["APPROVED_BY"]} · applied by {r["APPLIED_BY"]} {d(r["APPLIED_AT"])}</div></div>',
                unsafe_allow_html=True)
            with st.expander("Give up my access"):
                reason = st.text_input("Reason", key="giveup_reason")
                ok = st.checkbox("I confirm I no longer need this access. My Snowflake login and the time are recorded.", key="giveup_ok")
                if st.button("Confirm: end my access", key="giveup_btn", disabled=not ok):
                    flash(call("SP_END_ACCESS", study, VIEWER, reason, True, VIEWER))
    with c2:
        st.subheader("What I see today")
        keys = key_status(study)
        if keys.empty:
            empty("No forms or items for this study in the feed.")
        else:
            if reg.empty or not (reg.iloc[0]["EFFECTIVE_FROM"] <= TODAY <= reg.iloc[0]["EFFECTIVE_TO"]):
                visible = pd.Series([False] * len(keys))
                note = "No access in date: no rows, no values."
            elif reg.iloc[0]["ROLE_FUNCTION"] == "ADHOC":
                visible = pd.Series([False] * len(keys))
                note = "Ad hoc access: every value shows as BLINDED."
            elif reg.iloc[0]["SIGHT"] == "UNBLINDED":
                visible = pd.Series([True] * len(keys))
                note = "Unblinded access: every value is visible."
            else:
                visible = (keys["STATE"] == "CLEAR").reset_index(drop=True)
                note = "Blinded access: a value is visible only where the item is CLEAR."
            n_vis = int(visible.sum())
            st.markdown(f'<div class="bc-kpis"><div class="bc-kpi"><p>Forms and items</p><b>{len(keys)}</b></div>'
                        f'<div class="bc-kpi"><p>Visible to me</p><b>{n_vis}</b></div>'
                        f'<div class="bc-kpi"><p>BLINDED for me</p><b>{len(keys) - n_vis}</b></div></div>', unsafe_allow_html=True)
            st.caption(note + " This is metadata: which fields, never their values.")
            with st.expander("Field by field"):
                t = keys[["FORM_OID", "ITEM_OID", "STATE"]].copy()
                t["FOR ME"] = ["visible" if v else "BLINDED" for v in visible]
                st.dataframe(t, width="stretch", hide_index=True)

    st.subheader("My requests")
    mine = requests(study, user=VIEWER)
    if mine.empty:
        empty("No requests yet.")
    for _, r in mine.iterrows():
        request_card(r)
        if r["STATUS"] in ("REQUESTED", "APPROVED"):
            with st.expander(f"Withdraw {r['REQUEST_ID']}"):
                why = st.text_input("Comment (optional)", key=f"wd_c_{r['REQUEST_ID']}")
                if st.button("Confirm: withdraw this request", key=f"wd_b_{r['REQUEST_ID']}"):
                    flash(call("SP_WITHDRAW_REQUEST", r["REQUEST_ID"], why, VIEWER))

    st.subheader("Request access for myself")
    open_req = mine[mine["STATUS"].isin(["REQUESTED", "APPROVED"])] if not mine.empty else mine
    if not open_req.empty:
        st.markdown('<div class="bc-note">You already have a request open on this study. Withdraw it before making another.</div>', unsafe_allow_html=True)
    with st.form("request_form"):
        a, b, c = st.columns(3)
        person = a.text_input("Your name (as on the access form)")
        fn = b.selectbox("Function", list(FUNCTIONS.keys()), format_func=lambda k: f"{k} — {FUNCTIONS[k]}")
        sight = c.selectbox("Sight", SIGHTS)
        a, b, c = st.columns(3)
        d_from = a.date_input("From", value=TODAY)
        d_to = b.date_input("To", value=TODAY + dt.timedelta(days=180))
        c.caption("At most 366 days. Access stops the day after the end date.")
        a, b = st.columns(2)
        form_ref = a.text_input("Access form reference")
        form_date = b.date_input("Access form signed on", value=TODAY)
        just = st.text_area("Justification (10 characters or more)", height=80)
        approvers = [u for u in role_holders(f"{prefix}_APPROVER")["LOGIN"] if u != VIEWER]
        approver = st.selectbox("Send to approver", approvers, index=None, placeholder="Choose the approver",
                                help="Only this person can approve or reject your request.")
        if not approvers:
            st.caption("There is no approver on this study yet: the data owner appoints approvers.")
        ok = st.checkbox(CONFIRM_TEXT, key="req_ok")
        if st.form_submit_button("Confirm: send my request", disabled=not open_req.empty or not approvers):
            if not ok:
                st.warning("Tick the confirmation first.")
            elif not approver:
                st.warning("Choose the approver.")
            else:
                flash(call("SP_REQUEST_ACCESS", study, person, fn, sight, d_from, d_to, just, form_ref, form_date, approver, True, VIEWER))


# ------------------------------------------------------------------------------------------------
# 7. View 2 · Approve access (approvers)
# ------------------------------------------------------------------------------------------------
def view_approve():
    head("Approve access", f"Requests on {study} waiting for an approver. Approving writes a decision only; the data owner applies it.")
    show_flash()
    if not IS_APPROVER:
        empty("You are not an approver on this study. Approvers are appointed by the data owner.")
        return
    queue = requests(study, ["REQUESTED"])
    if not queue.empty:      # only requests sent to me (older requests with no approver chosen: any approver)
        queue = queue[queue["SENT_TO"].isna() | (queue["SENT_TO"] == VIEWER)]
    st.markdown(f'<div class="bc-kpis"><div class="bc-kpi"><p>Sent to you, waiting</p><b>{len(queue)}</b></div>'
                f'<div class="bc-kpi"><p>Oldest (days)</p><b>{int(queue["DAYS_WAITING"].max()) if not queue.empty else 0}</b></div></div>',
                unsafe_allow_html=True)
    if queue.empty:
        empty("Nothing waiting.")
    for _, r in queue.iterrows():
        request_card(r, show_steps=False)
        st.caption(f"Waiting {int(r['DAYS_WAITING'])} day(s)")
        if r["USER_NAME"] == VIEWER:
            st.info("This is your own request: another approver must decide it.")
            continue
        with st.expander(f"Decide {r['REQUEST_ID']}"):
            comment = st.text_input("Comment (required for a rejection)", key=f"ap_c_{r['REQUEST_ID']}")
            ok = st.checkbox(CONFIRM_TEXT, key=f"ap_ok_{r['REQUEST_ID']}")
            a, b = st.columns(2)
            if a.button("Confirm: approve", key=f"ap_y_{r['REQUEST_ID']}", disabled=not ok):
                flash(call("SP_DECIDE_ACCESS", r["REQUEST_ID"], "APPROVED", comment, True, VIEWER))
            if b.button("Confirm: reject", key=f"ap_n_{r['REQUEST_ID']}", disabled=not ok):
                flash(call("SP_DECIDE_ACCESS", r["REQUEST_ID"], "REJECTED", comment, True, VIEWER))
    with st.expander("Approved by me, waiting for the data owner"):
        mine = requests(study, ["APPROVED"])
        mine = mine[mine["APPROVED_BY"] == VIEWER] if not mine.empty else mine
        if mine.empty:
            empty("None.")
        else:
            st.dataframe(mine[["REQUEST_ID", "USER_NAME", "ROLE_FUNCTION", "SIGHT", "EFFECTIVE_FROM", "EFFECTIVE_TO", "APPROVED_AT", "DAYS_WAITING"]],
                         width="stretch", hide_index=True)


# ------------------------------------------------------------------------------------------------
# 8. View 3 · Apply access (data owner)
# ------------------------------------------------------------------------------------------------
def view_apply():
    head("Apply access", f"The data owner's desk for {study}: apply approved requests, keep the register, appoint approvers.")
    show_flash()
    if not IS_OWNER:
        empty("You are not the data owner of this study.")
        return
    t1, t2, t3 = st.tabs(["Access to apply", "Study team register", "Approvers"])
    with t1:
        queue = requests(study, ["APPROVED"])
        st.markdown(f'<div class="bc-kpis"><div class="bc-kpi"><p>Approved, waiting to apply</p><b>{len(queue)}</b></div>'
                    f'<div class="bc-kpi"><p>Oldest (days)</p><b>{int(queue["DAYS_WAITING"].max()) if not queue.empty else 0}</b></div></div>',
                    unsafe_allow_html=True)
        if queue.empty:
            empty("Nothing waiting.")
        for _, r in queue.iterrows():
            request_card(r)
            if r["USER_NAME"] == VIEWER:
                st.info("This is your own request: another data owner must apply it.")
                continue
            if r["APPROVED_BY"] == VIEWER:
                st.info("You approved this request: a different person must apply it.")
                continue
            existing = register(study)
            existing = existing[existing["USER_NAME"] == r["USER_NAME"]]
            if not existing.empty:
                e = existing.iloc[0]
                st.caption(f"{r['USER_NAME']} already holds {e['ROLE_NAME']} until {d(e['EFFECTIVE_TO'])} ({e['REQUEST_ID']}): applying replaces it.")
            with st.expander(f"Apply or decline {r['REQUEST_ID']}"):
                comment = st.text_input("Comment (required for a decline)", key=f"dp_c_{r['REQUEST_ID']}")
                ok = st.checkbox(CONFIRM_TEXT, key=f"dp_ok_{r['REQUEST_ID']}")
                a, b = st.columns(2)
                if a.button("Confirm: apply (grant the role, write the register)", key=f"dp_y_{r['REQUEST_ID']}", disabled=not ok):
                    flash(call("SP_APPLY_ACCESS", r["REQUEST_ID"], "APPLIED", comment, True, VIEWER))
                if b.button("Confirm: decline", key=f"dp_n_{r['REQUEST_ID']}", disabled=not ok):
                    flash(call("SP_APPLY_ACCESS", r["REQUEST_ID"], "REJECTED", comment, True, VIEWER))
    with t2:
        reg = register(study)
        expired = reg[reg["EFFECTIVE_TO"] < TODAY] if not reg.empty else reg
        register_download("reg_dl_owner")
        st.markdown(f'<div class="bc-kpis"><div class="bc-kpi"><p>People with access</p><b>{len(reg)}</b></div>'
                    f'<div class="bc-kpi"><p>Past end date</p><b>{len(expired)}</b></div></div>', unsafe_allow_html=True)
        if reg.empty:
            empty("Nobody has access on this study.")
        else:
            show = reg[["USER_NAME", "PERSON_NAME", "ROLE_FUNCTION", "SIGHT", "ROLE_NAME", "EFFECTIVE_FROM", "EFFECTIVE_TO", "REQUEST_ID", "APPROVED_BY", "APPLIED_BY", "APPLIED_AT"]]
            st.dataframe(show, width="stretch", hide_index=True)
        a, b = st.columns(2)
        with a:
            with st.expander("End someone's access now"):
                who = st.selectbox("Person", [""] + (reg["USER_NAME"].tolist() if not reg.empty else []), key="end_who")
                why = st.text_input("Reason (5 characters or more)", key="end_why")
                ok = st.checkbox("I confirm this access is to end now. My Snowflake login and the time are recorded.", key="end_ok")
                if st.button("Confirm: end access", key="end_btn", disabled=not ok or not who):
                    flash(call("SP_END_ACCESS", study, who, why, True, VIEWER))
        with b:
            with st.expander("End expired access"):
                st.caption("Removes every register row past its end date and revokes its role. The data stopped on the end date anyway.")
                if st.button(f"Confirm: end {len(expired)} expired row(s)", key="exp_btn", disabled=expired.empty):
                    flash(call("SP_END_EXPIRED", study, VIEWER))
    with t3:
        appr = role_holders(f"{prefix}_APPROVER")
        owners = role_holders(f"{prefix}_DATA_OWNER")
        a, b = st.columns(2)
        with a:
            st.markdown("**Approvers**")
            if appr.empty:
                empty("No approver yet. Appoint one below.")
            else:
                st.dataframe(appr, width="stretch", hide_index=True)
        with b:
            st.markdown("**Data owners** (appointed by IT in a worksheet: SP_SET_DATA_OWNER)")
            st.dataframe(owners, width="stretch", hide_index=True)
        with st.form("approver_form"):
            st.markdown("**Appoint or remove an approver**")
            a, b, c = st.columns(3)
            login = a.text_input("Snowflake login (upper case)")
            person = b.text_input("Name")
            action = c.selectbox("Action", ["ADD", "REMOVE"])
            a, b = st.columns(2)
            form_ref = a.text_input("Appointment form reference")
            reason = b.text_input("Reason (10 characters or more)")
            ok = st.checkbox(CONFIRM_TEXT, key="appr_ok")
            if st.form_submit_button("Confirm: " + ("appoint" if action == "ADD" else "remove")):
                if not ok:
                    st.warning("Tick the confirmation first.")
                else:
                    flash(call("SP_SET_APPROVER", study, login.strip().upper(), person, action, form_ref, reason, True, VIEWER))


# ------------------------------------------------------------------------------------------------
# 9. View 4 · Blinding rules
# ------------------------------------------------------------------------------------------------
def view_rules():
    head("Blinding rules", f"What is blinded on {study} today, and the entry of a signed Blinding form by the data owner.")
    show_flash()
    keys = key_status(study)
    n_new = int((keys["STATE"] == "NEW").sum()) if not keys.empty else 0
    n_blind = int((keys["STATE"] == "BLIND").sum()) if not keys.empty else 0
    n_clear = int((keys["STATE"] == "CLEAR").sum()) if not keys.empty else 0
    t1, t2, t3 = st.tabs(["Fields and their state", "Enter a Blinding form", "Forms applied"])
    with t1:
        st.markdown(f'<div class="bc-kpis"><div class="bc-kpi"><p>Forms and items in the feed</p><b>{len(keys)}</b></div>'
                    f'<div class="bc-kpi"><p>BLIND (by a rule)</p><b>{n_blind}</b></div>'
                    f'<div class="bc-kpi"><p>CLEAR (reviewed, visible)</p><b>{n_clear}</b></div>'
                    f'<div class="bc-kpi"><p>NEW (not yet reviewed: blinded)</p><b>{n_new}</b></div></div>', unsafe_allow_html=True)
        st.caption("A blinded person sees a value only where the item is CLEAR. NEW means no Blinding form has named it yet, so it shows as BLINDED.")
        if IS_OWNER or IS_APPROVER:
            when, tag = stamp()
            st.download_button("⬇ Download blinding snapshot (Excel)", key="snap_dl", mime=XLSX,
                               file_name=f"Blinding_snapshot_{safe_name(study)}_{tag}.xlsx",
                               data=kept(("snapshot_xlsx", study), lambda: build_snapshot(study, plan, snapshot_fields(study),
                                                                                        forms_applied(study), rules_history(study),
                                                                                        VIEWER, when)))
            st.caption("Every field with its state, the Blinding form and reason behind it, and the full history. No patient values.")
        if keys.empty:
            empty("No forms or items for this study in the feed.")
        else:
            st.dataframe(keys, width="stretch", hide_index=True)
        st.markdown("**Rules in force** (ADD rows whose blind has not been lifted)")
        rif = rules_in_force(study)
        if rif.empty:
            empty("No rule in force.")
        else:
            st.dataframe(rif, width="stretch", hide_index=True)
    with t2:
        if not IS_OWNER:
            empty("Only the data owner enters a Blinding form.")
        elif not my_register_row(study).empty:
            st.error("You hold data access on this study. A data owner with access cannot apply its Blinding rules; give up the access first (view 1).")
        else:
            entry_form(keys, rules_in_force(study))
    with t3:
        forms = forms_applied(study)
        if forms.empty:
            empty("No Blinding form applied yet. Everything new in the feed is BLINDED until one is.")
        for _, f in forms.iterrows():
            f_raw, f = f, esc_row(f)
            with st.expander(f"{f_raw['RULE_REQUEST_ID']} · form {f_raw['FORM_REF']} signed {d(f_raw['FORM_SIGNED_DATE'])} · {int(f_raw['ROW_COUNT'])} row(s) · {f_raw['SOURCE']}"):
                st.markdown(f'<div class="bc-meta">Entered by {f["ENTERED_BY_NAME"]} ({f["ENTERED_BY"]}) {d(f["ENTERED_AT"])} · '
                            f'{int(f["NEW_KEYS_CLASSIFIED"]) if pd.notna(f["NEW_KEYS_CLASSIFIED"]) else 0} new form/item(s) classified'
                            + (f' · file {f["FILE_NAME"]} md5 {f["FILE_MD5"]}' if f["SOURCE"] == "FILE" else "") + "</div>", unsafe_allow_html=True)
                st.dataframe(form_rows(f_raw["RULE_REQUEST_ID"]), width="stretch", hide_index=True)


def entry_form(keys, rules):
    pending = st.session_state.get("_pending_rules")
    if pending and pending["study"] == study:
        review_and_apply(pending, keys, rules)
        return
    draft = st.session_state.get("_rules_draft") or {}
    st.markdown('<div class="bc-note">The signed paper form is the approval. For each field choose <b>Blinded</b> or <b>Visible</b>, '
                'as the form says. New fields start as Blinded. Next you see exactly what will change, then you confirm.</div>',
                unsafe_allow_html=True)
    mode = st.radio("How", ["On screen", "Bulk load from a file"], horizontal=True, key="rules_mode")
    choices, file_blob, file_name = [], None, None
    if mode == "Bulk load from a file":
        a, b = st.columns([1, 2])
        with a:
            st.download_button("⬇ Download the template", data=kept(("template", study), lambda: build_template(study, keys, rules)),
                               file_name=f"Blinding_form_template_{safe_name(study)}.xlsx", mime=XLSX, key="tpl_dl")
            st.caption("Every field, with today's state. Choose Blinded or Visible in SET_TO and give reasons.")
        with b:
            up = st.file_uploader("Upload the filled-in file (.xlsx or .csv)", type=["xlsx", "csv"], key="rules_file")
        if up is None:
            return
        file_blob, file_name = up.getvalue(), up.name
        choices, errs = parse_rules_file(up.name, file_blob)
        for e in errs:
            st.error(e)
        if errs:
            return
        st.caption(f"{len(choices)} row(s) read from {up.name}.")
    # everything entered together sits in one form: editing does not reload the page
    with st.form("rules_form"):
        grid = None
        if mode == "On screen":
            frame = fields_frame(keys, rules)
            for k, (choice, reason) in (draft.get("grid") or {}).items():       # coming back from the review: keep the edits
                m = (frame["FORM_OID"] == k[0]) & (frame["ITEM_OID"] == k[1])
                frame.loc[m, "SET_TO"], frame.loc[m, "REASON"] = choice, reason
            grid = st.data_editor(frame, num_rows="fixed", width="stretch", key="rules_grid", hide_index=True,
                                  disabled=["FORM_OID", "ITEM_OID", "TODAY"],
                                  column_config={"SET_TO": st.column_config.SelectboxColumn("SET TO", options=SET_TO, required=True),
                                                 "REASON": st.column_config.TextColumn("REASON (for a change)")})
        default_reason = st.text_input("Reason for every row where you leave REASON blank (10 characters or more)",
                                       value=draft.get("default_reason", ""))
        a, b, c = st.columns(3)
        name = a.text_input("Your name (as on the Blinding form)", value=draft.get("name", ""))
        form_ref = b.text_input("Blinding form reference", value=draft.get("form_ref", ""))
        form_date = c.date_input("Blinding form signed on", value=draft.get("form_date", TODAY))
        if not st.form_submit_button("Review the changes"):
            return
    if grid is not None:
        choices = [{"form": r["FORM_OID"], "item": r["ITEM_OID"], "set_to": r["SET_TO"], "reason": r["REASON"]} for _, r in grid.iterrows()]
    actions, problems = to_actions(choices, keys, rules, default_reason)
    if not cell(name):
        problems.insert(0, "Your name is empty")
    if not cell(form_ref):
        problems.insert(0, "Blinding form reference is empty")
    if problems:
        for p in problems[:15]:
            st.warning(p)
        return
    st.session_state["_rules_draft"] = {"grid": {(cell(c["form"]), cell(c["item"])): (cell(c["set_to"]), cell(c["reason"])) for c in choices}
                                        if grid is not None else {}, "default_reason": default_reason, "name": name,
                                        "form_ref": form_ref, "form_date": form_date}
    st.session_state["_pending_rules"] = {"study": study, "actions": actions, "name": name, "form_ref": form_ref,
                                          "form_date": form_date, "file_blob": file_blob, "file_name": file_name}
    st.rerun()


def review_and_apply(p, keys, rules):
    """Step 2: exactly what will change, then confirm (or go back and edit)."""
    today = {(cell(r["FORM_OID"]), cell(r["ITEM_OID"])): cell(r["TODAY"]) for _, r in fields_frame(keys, rules).iterrows()}
    st.markdown(f'<div class="bc-note">Blinding form <b>{esc(p["form_ref"])}</b> signed {d(p["form_date"])}, entered by '
                f'{esc(p["name"])} ({esc(VIEWER)}). <b>{len(p["actions"])}</b> change(s). Nothing has changed yet.</div>',
                unsafe_allow_html=True)
    st.dataframe(pd.DataFrame([{"FORM_OID": a["form"], "ITEM_OID": a["item"] or "(whole form)",
                                "TODAY": today.get((a["form"], cell(a["item"])), "Blinded (whole form)"),
                                "CHANGES TO": CHANGE_WORDS[a["action"]], "REASON": a["reason"]} for a in p["actions"]]),
                 width="stretch", hide_index=True)
    ok = st.checkbox(CONFIRM_TEXT, key="rules_ok")
    a, b = st.columns(2)
    if b.button("Back to edit", key="rules_back"):
        st.session_state.pop("_pending_rules", None)
        st.rerun()
    if not a.button("Confirm: apply the Blinding form", key="rules_apply", disabled=not ok):
        return
    st.session_state.pop("_pending_rules", None)
    stage_path = None
    if p["file_blob"] is not None:
        stage_path = f"{safe_name(study)}/{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{safe_name(p['file_name'])}"
        try:
            session.file.put_stream(io.BytesIO(p["file_blob"]), f"@{SC}.BLINDING_FILES/{stage_path}", auto_compress=False, overwrite=False)
        except Exception as e:
            flash("FAILED: the file could not be stored on BLINDING_FILES - " + str(e))
    res = call("SP_APPLY_RULES", study, p["name"], p["form_ref"], p["form_date"], stage_path, json.dumps(p["actions"]), True, VIEWER)
    if stage_path and res.startswith("REFUSED"):
        # a refused entry keeps nothing, not even its file. Only on REFUSED: after FAILED the procedure
        # may have committed, and its file is then evidence. Exact file only (REMOVE matches by prefix).
        folder, base = stage_path.rsplit("/", 1)
        try:
            session.sql(f"REMOVE @{SC}.BLINDING_FILES/{folder}/ PATTERN = '.*/{base.replace('.', '[.]')}'").collect()
        except Exception as e:
            res += " (the uploaded file could not be removed: " + str(e) + ")"
    if res.startswith("OK"):
        st.session_state.pop("_rules_draft", None)
    flash(res)


# ------------------------------------------------------------------------------------------------
# 10. View 5 · Audit trail (approvers and the data owner)
# ------------------------------------------------------------------------------------------------
def view_audit():
    head("Audit trail", f"Everything recorded on {study}: who did what, when, and the evidence behind it.")
    if not (IS_APPROVER or IS_OWNER):
        empty("The audit trail is open to approvers and the data owner.")
        return
    t1, t2, t3, t4 = st.tabs(["Audit log", "Access requests", "Blinding forms", "Latest checks"])
    with t1:
        a = audit(study)
        if a.empty:
            empty("No events yet.")
        else:
            st.caption("Hash-chained per study: check A01 in 03_checks.sql proves no row was changed or removed. Latest 500 shown.")
            st.dataframe(a, width="stretch", hide_index=True)
    with t2:
        register_download("reg_dl_audit")
        allr = requests(study)
        if allr.empty:
            empty("No requests yet.")
        else:
            cols = ["REQUEST_ID", "STATUS", "USER_NAME", "PERSON_NAME", "ROLE_FUNCTION", "SIGHT", "EFFECTIVE_FROM", "EFFECTIVE_TO", "FORM_REF",
                    "REQUESTED_AT", "APPROVED_BY", "APPROVED_AT", "APPLIED_BY", "APPLIED_AT", "REJECTED_BY", "REJECTED_AS", "REJECT_COMMENT",
                    "WITHDRAWN_AT", "ENDED_BY", "ENDED_AT", "END_COMMENT", "DAYS_WAITING"]
            st.dataframe(allr[cols], width="stretch", hide_index=True)
    with t3:
        forms = forms_applied(study)
        if forms.empty:
            empty("No Blinding form applied yet.")
        for _, f in forms.iterrows():
            with st.expander(f"{f['RULE_REQUEST_ID']} · form {f['FORM_REF']} · {f['SOURCE']} · entered by {f['ENTERED_BY']} {d(f['ENTERED_AT'])}"):
                st.dataframe(form_rows(f["RULE_REQUEST_ID"]), width="stretch", hide_index=True)
                if f["SOURCE"] == "FILE" and f["FILE_NAME"]:
                    st.caption(f"Stored file {f['FILE_NAME']} · md5 {f['FILE_MD5']}")
                    if st.button("Fetch the stored file", key=f"get_{f['RULE_REQUEST_ID']}"):
                        try:
                            blob = session.file.get_stream(f"@{SC}.BLINDING_FILES/{f['FILE_NAME']}").read()
                            st.download_button("⬇ Download", data=blob, file_name=str(f["FILE_NAME"]).split("/")[-1], key=f"dl_{f['RULE_REQUEST_ID']}")
                        except Exception as e:
                            st.error("The file could not be read from the stage: " + str(e))
    with t4:
        chk = latest_checks()
        if chk.empty:
            empty("03_checks.sql has not been run yet.")
        else:
            n_fail = int((chk["RESULT"] == "FAIL").sum())
            n_warn = int((chk["RESULT"] == "WARN").sum())
            st.markdown(f'<div class="bc-kpis"><div class="bc-kpi"><p>Checks</p><b>{len(chk)}</b></div>'
                        f'<div class="bc-kpi"><p>FAIL</p><b>{n_fail}</b></div><div class="bc-kpi"><p>WARN</p><b>{n_warn}</b></div>'
                        f'<div class="bc-kpi"><p>Run at</p><b style="font-size:16px">{d(chk["RUN_AT"].max())}</b></div></div>', unsafe_allow_html=True)
            st.dataframe(chk, width="stretch", hide_index=True)


# ------------------------------------------------------------------------------------------------
# 11. Route
# ------------------------------------------------------------------------------------------------
{"1": view_request, "2": view_approve, "3": view_apply, "4": view_rules, "5": view_audit}[view[0]]()
