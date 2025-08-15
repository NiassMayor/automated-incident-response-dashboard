# src/app.py
from dash import Dash, html, dcc, ctx, no_update
from dash.dash_table import DataTable
from dash.dependencies import Input, Output, State
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional
import random, io, base64, os, sqlite3, requests
import plotly.graph_objects as go

print("Starting dashboard (Playbooks + Risk + Slack + Analytics + MITRE) …")

# ---------------- SQLite persistence ----------------
DB_PATH = os.path.join("data", "app.db")

def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    try:
        con.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass
    return con

def init_db():
    con = _connect()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            ID INTEGER PRIMARY KEY,
            Type TEXT, Severity TEXT, Status TEXT, Time TEXT,
            Risk INTEGER,
            Tactic TEXT, Technique TEXT, TechniqueID TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            "When" TEXT, Action TEXT, IDs TEXT, Count INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            "When" TEXT, ID INTEGER, Type TEXT, Severity TEXT, Risk INTEGER,
            Tactic TEXT, Technique TEXT, TechniqueID TEXT
        )
    """)
    con.commit()
    con.close()
    ensure_columns()

def ensure_columns():
    con = _connect()
    try:
        cols = pd.read_sql_query("PRAGMA table_info(incidents);", con)
        names = cols["name"].tolist()
        if "Risk" not in names:
            con.execute("ALTER TABLE incidents ADD COLUMN Risk INTEGER;")
        if "Tactic" not in names:
            con.execute("ALTER TABLE incidents ADD COLUMN Tactic TEXT;")
        if "Technique" not in names:
            con.execute("ALTER TABLE incidents ADD COLUMN Technique TEXT;")
        if "TechniqueID" not in names:
            con.execute("ALTER TABLE incidents ADD COLUMN TechniqueID TEXT;")
        con.commit()

        cols2 = pd.read_sql_query("PRAGMA table_info(events);", con)
        names2 = cols2["name"].tolist()
        to_add = []
        if "Tactic" not in names2:      to_add.append("ALTER TABLE events ADD COLUMN Tactic TEXT;")
        if "Technique" not in names2:   to_add.append("ALTER TABLE events ADD COLUMN Technique TEXT;")
        if "TechniqueID" not in names2: to_add.append("ALTER TABLE events ADD COLUMN TechniqueID TEXT;")
        for q in to_add:
            con.execute(q)
        if to_add:
            con.commit()
    except Exception:
        pass
    finally:
        con.close()

def load_tables():
    init_db()
    con = _connect()
    try:
        inc = pd.read_sql_query(
            "SELECT ID, Type, Severity, Status, Time, Risk, Tactic, Technique, TechniqueID FROM incidents ORDER BY ID DESC",
            con
        )
        aud = pd.read_sql_query(
            'SELECT "When", Action, IDs, Count FROM audit ORDER BY "When" DESC',
            con
        )
    except Exception:
        inc, aud = pd.DataFrame(), pd.DataFrame()
    finally:
        con.close()
    # Backfill Risk & MITRE if needed
    if inc is not None and not inc.empty:
        if "Risk" not in inc.columns:
            inc["Risk"] = compute_risk_df(inc)
        else:
            inc["Risk"] = inc["Risk"].fillna(compute_risk_df(inc))
        for col in ["Tactic","Technique","TechniqueID"]:
            if col not in inc.columns:
                inc[col] = None
        missing = inc["TechniqueID"].isna() | (inc["TechniqueID"] == "")
        if missing.any():
            enr = inc.loc[missing, "Type"].apply(enrich_mitre).apply(pd.Series)
            for c in ["Tactic","Technique","TechniqueID"]:
                inc.loc[missing, c] = enr[c].values
    return inc, aud

def save_incidents(df):
    want_cols = ["ID","Type","Severity","Status","Time","Risk","Tactic","Technique","TechniqueID"]
    if df is None:
        df = pd.DataFrame(columns=want_cols)
    df = df.copy()

    # Risk backfill
    if "Risk" not in df.columns:
        df["Risk"] = compute_risk_df(df)
    else:
        df["Risk"] = df["Risk"].fillna(compute_risk_df(df))

    # MITRE backfill
    for col in ["Tactic","Technique","TechniqueID"]:
        if col not in df.columns:
            df[col] = None
    missing_mask = df["TechniqueID"].isna() | (df["TechniqueID"] == "")
    if missing_mask.any():
        enriched = df.loc[missing_mask, "Type"].apply(enrich_mitre).apply(pd.Series)
        for col in ["Tactic","Technique","TechniqueID"]:
            df.loc[missing_mask, col] = enriched[col].values

    df = df.reindex(columns=want_cols)

    con = _connect()
    cur = con.cursor()
    cur.execute("DELETE FROM incidents")
    if not df.empty:
        cur.executemany(
            "INSERT INTO incidents (ID, Type, Severity, Status, Time, Risk, Tactic, Technique, TechniqueID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            df[want_cols].itertuples(index=False, name=None)
        )
    con.commit(); con.close()

def save_audit(records):
    con = _connect()
    cur = con.cursor()
    cur.execute("DELETE FROM audit")
    for r in (records or []):
        cur.execute(
            'INSERT INTO audit ("When", Action, IDs, Count) VALUES (?, ?, ?, ?)',
            (r.get("When",""), r.get("Action",""), r.get("IDs","-"), int(r.get("Count",0)))
        )
    con.commit(); con.close()

def append_events(df_rows: pd.DataFrame):
    """Append new 'creation' events for incidents (with MITRE)."""
    if df_rows is None or df_rows.empty:
        return
    cols = ["Time","ID","Type","Severity","Risk","Tactic","Technique","TechniqueID"]
    df = df_rows.copy()
    for col in ["Tactic","Technique","TechniqueID"]:
        if col not in df.columns:
            df[col] = df["Type"].apply(lambda t: enrich_mitre(t)[col])
    con = _connect()
    cur = con.cursor()
    cur.executemany(
        'INSERT INTO events ("When", ID, Type, Severity, Risk, Tactic, Technique, TechniqueID) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        df[cols].itertuples(index=False, name=None)
    )
    con.commit(); con.close()

def load_events_since(since_dt: Optional[datetime]):
    con = _connect()
    try:
        if since_dt is None:
            q = 'SELECT "When", ID, Type, Severity, Risk, Tactic, Technique, TechniqueID FROM events ORDER BY "When" ASC'
            ev = pd.read_sql_query(q, con)
        else:
            q = 'SELECT "When", ID, Type, Severity, Risk, Tactic, Technique, TechniqueID FROM events WHERE datetime("When") >= ? ORDER BY "When" ASC'
            ev = pd.read_sql_query(q, con, params=(since_dt.strftime("%Y-%m-%d %H:%M:%S"),))
    except Exception:
        ev = pd.DataFrame()
    finally:
        con.close()
    if ev is not None and not ev.empty:
        ev["When"] = pd.to_datetime(ev["When"], errors="coerce")
    return ev

def load_audit_since(since_dt: Optional[datetime]):
    con = _connect()
    try:
        if since_dt is None:
            q = 'SELECT "When", Action, IDs FROM audit ORDER BY "When" ASC'
            au = pd.read_sql_query(q, con)
        else:
            q = 'SELECT "When", Action, IDs FROM audit WHERE datetime("When") >= ? ORDER BY "When" ASC'
            au = pd.read_sql_query(q, con, params=(since_dt.strftime("%Y-%m-%d %H:%M:%S"),))
    except Exception:
        au = pd.DataFrame()
    finally:
        con.close()
    if au is not None and not au.empty:
        au["When"] = pd.to_datetime(au["When"], errors="coerce")
    return au

def wipe_db():
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
    except Exception:
        pass
    init_db()

# ---------------- Seed data & helpers ----------------
SEVERITIES = ["Low", "Medium", "High", "Critical"]
SEVERITY_WEIGHTS = [0.2, 0.35, 0.3, 0.15]
TYPES = [
    "Phishing Email", "Malware Detected", "Unauthorized Login",
    "Brute-force Attempt", "Suspicious DNS", "Data Exfiltration", "Rogue Device",
]
STATUSES = ["Open", "Investigating", "Containment", "Escalated", "Resolved"]

# ---- Simple playbook rules ----
PLAYBOOKS = {
    "Phishing Email": "Containment",
    "Malware Detected": "Escalated",
    "Unauthorized Login": "Investigating",
    "Data Exfiltration": "Escalated",
}

# ---- MITRE ATT&CK enrichment ----
MITRE_MAP = {
    "Phishing Email": {
        "Tactic": "TA0001 Initial Access",
        "Technique": "T1566 Phishing",
        "TechniqueID": "T1566",
    },
    "Malware Detected": {
        "Tactic": "TA0002 Execution",
        "Technique": "T1204 User Execution",
        "TechniqueID": "T1204",
    },
    "Unauthorized Login": {
        "Tactic": "TA0006 Credential Access",
        "Technique": "T1110 Brute Force",
        "TechniqueID": "T1110",
    },
    "Brute-force Attempt": {
        "Tactic": "TA0006 Credential Access",
        "Technique": "T1110 Brute Force",
        "TechniqueID": "T1110",
    },
    "Suspicious DNS": {
        "Tactic": "TA0011 Command and Control",
        "Technique": "T1071 Application Layer Protocol",
        "TechniqueID": "T1071",
    },
    "Data Exfiltration": {
        "Tactic": "TA0010 Exfiltration",
        "Technique": "T1041 Exfiltration Over C2 Channel",
        "TechniqueID": "T1041",
    },
    "Rogue Device": {
        "Tactic": "TA0008 Lateral Movement",
        "Technique": "T1021 Remote Services",
        "TechniqueID": "T1021",
    },
}

def enrich_mitre(typ: str) -> dict:
    meta = MITRE_MAP.get(typ, {})
    return {
        "Tactic": meta.get("Tactic", "Unknown"),
        "Technique": meta.get("Technique", "Unknown"),
        "TechniqueID": meta.get("TechniqueID", "TXXXX"),
    }

INITIAL = [
    {"ID": 1, "Type": "Phishing Email",     "Severity": "High",     "Status": "Open",          "Time": "2025-08-14 21:30"},
    {"ID": 2, "Type": "Malware Detected",   "Severity": "Critical", "Status": "Investigating", "Time": "2025-08-14 21:31"},
    {"ID": 3, "Type": "Unauthorized Login", "Severity": "Medium",   "Status": "Resolved",      "Time": "2025-08-14 21:33"},
    {"ID": 4, "Type": "Data Exfiltration",  "Severity": "Critical", "Status": "Open",          "Time": "2025-08-14 21:35"},
]

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def severity_base(sev: str) -> int:
    return {"Low": 25, "Medium": 50, "High": 75, "Critical": 90}.get(str(sev), 50)

def type_adjust(t: str) -> int:
    t = str(t)
    if t == "Data Exfiltration": return 8
    if t == "Malware Detected":  return 5
    if t == "Rogue Device":      return 4
    if t == "Unauthorized Login":return 3
    if t == "Phishing Email":    return 2
    return 0

def compute_risk_row(typ: str, sev: str) -> int:
    s = severity_base(sev) + type_adjust(typ)
    return max(0, min(100, int(round(s))))

def compute_risk_df(df: pd.DataFrame) -> pd.Series:
    typ = df.get("Type", pd.Series(["Unknown"]*len(df)))
    sev = df.get("Severity", pd.Series(["Medium"]*len(df)))
    return pd.Series([compute_risk_row(t, s) for t, s in zip(typ, sev)], index=df.index)

def generate_incident(next_id: int) -> dict:
    typ = random.choice(TYPES)
    sev = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]
    status = random.choice(STATUSES[:-1]) if random.random() < 0.85 else "Open"
    row = {
        "ID": next_id, "Type": typ, "Severity": sev, "Status": status,
        "Time": now_str(), "Risk": compute_risk_row(typ, sev)
    }
    row.update(enrich_mitre(typ))
    return row

# ---------------- CSV normalization helpers ----------------
COLUMN_ALIASES = {
    "id": "ID", "alert_id": "ID", "incident_id": "ID",
    "name": "Type", "alertname": "Type", "title": "Type", "category": "Type", "type": "Type",
    "severity": "Severity", "level": "Severity", "priority": "Severity",
    "status": "Status", "state": "Status",
    "time": "Time", "timestamp": "Time", "event_time": "Time", "@timestamp": "Time",
    "risk": "Risk", "score": "Risk",
}

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    cols = {c: COLUMN_ALIASES.get(c.strip().lower(), c) for c in df.columns}
    df = df.rename(columns=cols)
    out = pd.DataFrame()
    out["Type"] = df.get("Type", "Unknown")
    sev = df.get("Severity", "Medium").astype(str).str.title().replace({
        "Informational":"Low", "Info":"Low", "Warn":"High", "Warning":"High"
    })
    out["Severity"] = sev.where(sev.isin(SEVERITIES), "Medium")
    out["Status"] = df.get("Status", "Open").astype(str).str.title().replace({"New":"Open"})
    time_col = df.get("Time")
    if time_col is not None:
        try:
            out["Time"] = pd.to_datetime(time_col, errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            out["Time"] = time_col.astype(str)
        out["Time"] = out["Time"].fillna(now_str())
    else:
        out["Time"] = now_str()
    # Risk
    if "Risk" in df.columns:
        try:
            r = pd.to_numeric(df["Risk"], errors="coerce").fillna(-1).astype(int)
            r = r.where(r.between(0, 100), -1)
        except Exception:
            r = pd.Series([-1]*len(df))
        out["Risk"] = r
        mask = out["Risk"] < 0
        if mask.any():
            out.loc[mask, "Risk"] = compute_risk_df(out.loc[mask, ["Type","Severity"]])
    else:
        out["Risk"] = compute_risk_df(out)

    # Optional MITRE passthrough (if CSV provides)
    out["Tactic"] = df.get("Tactic")
    out["Technique"] = df.get("Technique")
    out["TechniqueID"] = df.get("TechniqueID")

    return out[["Type", "Severity", "Status", "Time", "Risk", "Tactic", "Technique", "TechniqueID"]]

def parse_csv_contents(contents: str) -> pd.DataFrame:
    if not contents:
        return pd.DataFrame()
    try:
        _, b64 = contents.split(",", 1)
        text = base64.b64decode(b64).decode("utf-8", errors="ignore")
        df = pd.read_csv(io.StringIO(text))
        return normalize_columns(df) if not df.empty else pd.DataFrame()
    except Exception:
        return pd.DataFrame()

def merge_and_reassign_ids(current: pd.DataFrame, incoming: pd.DataFrame, cap: int = 200) -> pd.DataFrame:
    if current is None or len(current) == 0:
        current = pd.DataFrame(columns=["ID", "Type", "Severity", "Status", "Time", "Risk", "Tactic", "Technique", "TechniqueID"])
    base = current[["Type","Severity","Status","Time","Risk","Tactic","Technique","TechniqueID"]].copy()
    merged = pd.concat([incoming, base], ignore_index=True).drop_duplicates(
        subset=["Type","Severity","Status","Time"], keep="first"
    )
    merged.insert(0, "ID", range(len(merged), 0, -1))
    merged = merged.sort_values("ID", ascending=False).reset_index(drop=True)
    return merged.head(cap)

# Slack optional
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")

def send_slack(text: str):
    if not SLACK_WEBHOOK:
        return
    try:
        requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=3)
    except Exception:
        pass

# ---------------- Load persisted data (or seed) ----------------
init_db()
db_incidents, db_audit = load_tables()
if db_incidents.empty:
    seed_df = pd.DataFrame(INITIAL)
    seed_df["Risk"] = compute_risk_df(seed_df)
    enr = seed_df["Type"].apply(enrich_mitre).apply(pd.Series)
    seed_df = pd.concat([seed_df, enr], axis=1)
    save_incidents(seed_df)
    incidents_init = seed_df.to_dict("records")
    append_events(seed_df.assign(ID=[1,2,3,4]))
else:
    incidents_init = db_incidents.to_dict("records")
audit_init = db_audit.to_dict("records") if not db_audit.empty else []

# ---------------- Create Dash app (allow dynamic components) ----------------
app = Dash(__name__, suppress_callback_exceptions=True)

# ---------------- Layout ----------------
app.layout = html.Div(
    [
        html.H1("Automated Incident Response Dashboard"),

        # Controls
        html.Div(
            [
                dcc.Checklist(
                    id="auto",
                    options=[{"label": " Auto-refresh", "value": "on"}],
                    value=["on"],
                    style={"marginRight": "12px"},
                ),
                dcc.Checklist(
                    id="notify",
                    options=[{"label": " Notify on Critical", "value": "on"}],
                    value=["on"],
                    style={"marginRight": "12px"},
                ),
                dcc.Dropdown(
                    id="mitre-filter",
                    options=[{"label":"All Techniques","value":"*"}] + [
                        {"label": f'{v["Technique"]} ({v["Tactic"]})', "value": k}
                        for k, v in MITRE_MAP.items()
                    ],
                    value="*",
                    placeholder="Filter by Technique",
                    style={"minWidth":"260px"}
                ),
                html.Button("Resolve Selected", id="resolve", n_clicks=0, style={"padding": "8px 12px"}),
                html.Button("Contain Selected", id="contain", n_clicks=0, style={"padding": "8px 12px"}),
                html.Button("Escalate Selected", id="escalate", n_clicks=0, style={"padding": "8px 12px"}),
                html.Button("➕ Add Test Incident", id="add-test", n_clicks=0, style={"padding": "8px 12px"}),
                html.Button("Download CSV", id="download-btn", n_clicks=0, style={"padding": "8px 12px"}),
                dcc.Download(id="download"),
                dcc.Upload(
                    id="uploader",
                    children=html.Div(["📄 Drag & drop CSV here, or ", html.A("click to upload")]),
                    multiple=False,
                    accept=".csv,text/csv",
                    style={"border": "1px dashed #aaa","borderRadius": "10px","padding": "8px 12px","cursor": "pointer"},
                ),
                # Reset (with confirm)
                html.Button("Reset Data", id="reset", n_clicks=0,
                            style={"padding": "8px 12px", "background": "#e74c3c", "color": "#fff",
                                   "border": "none", "borderRadius": "6px"}),
                dcc.ConfirmDialog(
                    id="confirm-reset",
                    message="This will delete all incidents & audit logs from local storage and reload seed data. Continue?"
                ),
            ],
            style={"display": "flex", "alignItems": "center", "gap": "10px", "marginBottom": "8px", "flexWrap": "wrap"},
        ),

        # Hidden dismiss to ensure callback wiring
        html.Button("Dismiss", id="dismiss-alert", n_clicks=0, style={"display": "none"}),

        # Heartbeat (shows timer activity)
        html.Div(id="heartbeat", style={"opacity":0.7, "fontSize":"12px", "marginBottom":"6px"}),

        # Notification banner (renders its own visible Dismiss button)
        html.Div(id="alert-banner", style={"marginBottom": "8px"}),

        # KPIs
        html.Div(id="kpis", style={"display": "flex", "gap": "12px", "flexWrap": "wrap", "marginBottom": "12px"}),

        # Main grid
        html.Div(
            [
                html.Div(
                    DataTable(
                        id="incidents",
                        columns=[{"name": c, "id": c} for c in ["ID","Type","Severity","Status","Time","Risk","TechniqueID","Technique"]],
                        data=incidents_init,
                        page_size=10,
                        sort_action="native",
                        filter_action="native",
                        row_selectable="multi",
                        style_cell={"textAlign": "left", "padding": "6px", "fontFamily": "sans-serif"},
                        style_header={"fontWeight": "bold"},
                        style_data_conditional=[
                            {"if": {"filter_query": '{Severity} = "Critical"'}, "backgroundColor": "#ffcccc"},
                            {"if": {"filter_query": '{Severity} = "High"'},     "backgroundColor": "#ffe5cc"},
                            {"if": {"filter_query": '{Risk} >= 85'},             "fontWeight": "700"},
                        ],
                    ),
                    style={"flex": 2, "minWidth": "620px"},
                ),
                html.Div(
                    dcc.Graph(id="severity-pie"),
                    style={"flex": 1, "minWidth": "280px"},
                ),
            ],
            style={"display": "flex", "gap": "16px", "alignItems": "stretch", "marginBottom": "16px"},
        ),

        # ----- Analytics -----
        html.Div(
            [
                html.Div("Analytics Window:", style={"fontWeight":"600"}),
                dcc.RadioItems(
                    id="time-range",
                    options=[
                        {"label":"Last 24h","value":"24h"},
                        {"label":"Last 7d","value":"7d"},
                        {"label":"Last 30d","value":"30d"},
                        {"label":"All","value":"all"},
                    ],
                    value="7d",
                    inline=True,
                    style={"marginBottom":"8px"}
                ),
                dcc.Graph(id="trend-incidents"),
                dcc.Graph(id="trend-mttr"),
                dcc.Graph(id="trend-risk"),
            ],
            style={"marginBottom":"24px"}
        ),

        # Audit log (read-only)
        html.H3("Audit Log"),
        DataTable(
            id="audit",
            columns=[{"name": c, "id": c} for c in ["When", "Action", "IDs", "Count"]],
            data=audit_init,
            page_size=8,
            style_cell={"textAlign": "left", "padding": "6px", "fontFamily": "sans-serif"},
            style_header={"fontWeight": "bold"},
        ),

        # State stores & timer
        dcc.Store(id="incident-store", data=incidents_init),
        dcc.Store(id="upload-buffer", data=None),
        dcc.Store(id="audit-log", data=audit_init),
        dcc.Store(id="alert-queue", data=[]),  # queue of pending alerts
        dcc.Interval(id="tick", interval=5_000, n_intervals=0, max_intervals=-1),
    ],
    style={"maxWidth": "1220px", "margin": "40px auto", "fontFamily": "sans-serif"},
)

# ---------------- Callbacks ----------------

@app.callback(Output("tick", "disabled"), Input("auto", "value"))
def toggle_auto(value):
    return "on" not in (value or [])

@app.callback(Output("upload-buffer", "data"), Input("uploader", "contents"), prevent_initial_call=True)
def parse_upload(contents):
    df = parse_csv_contents(contents)
    return None if df.empty else df.to_dict("records")

@app.callback(Output("confirm-reset", "displayed"),
              Input("reset", "n_clicks"), prevent_initial_call=True)
def open_reset_dialog(n):
    return True

# Heartbeat display
@app.callback(Output("heartbeat", "children"), Input("tick", "n_intervals"))
def show_heartbeat(n):
    return f"⏱️ ticks: {n} · last: {datetime.now().strftime('%H:%M:%S')}"

# ---------- SINGLE WRITER (playbooks + notifications + risk + events) ----------
@app.callback(
    Output("incident-store", "data"),
    Output("incidents", "selected_rows"),
    Output("audit-log", "data"),
    Output("alert-queue", "data"),
    Input("tick", "n_intervals"),
    Input("add-test", "n_clicks"),
    Input("resolve", "n_clicks"),
    Input("contain", "n_clicks"),
    Input("escalate", "n_clicks"),
    Input("upload-buffer", "data"),
    Input("confirm-reset", "submit_n_clicks"),
    Input("dismiss-alert", "n_clicks"),
    State("incidents", "derived_virtual_data"),
    State("incidents", "derived_virtual_selected_rows"),
    State("incident-store", "data"),
    State("audit-log", "data"),
    State("alert-queue", "data"),
    State("notify", "value"),
    prevent_initial_call=True,
)
def single_writer(_n, add_test_clicks, _resolve, _contain, _escalate, upload_rows, reset_submit, dismiss_clicks,
                  derived, selected_rows, store_data, audit_data, alert_data, notify_value):
    trigger = ctx.triggered_id
    df_store = pd.DataFrame(store_data or [])
    audit = list(audit_data or [])
    alerts = list(alert_data or [])
    notify_on = "on" in (notify_value or [])

    def log(action, ids):
        audit.insert(0, {
            "When": now_str(),
            "Action": action,
            "IDs": ",".join(map(str, sorted(ids))) if ids else "-",
            "Count": len(ids)
        })

    # Dismiss alert
    if trigger == "dismiss-alert":
        if alerts:
            alerts.pop(0)
        return df_store.to_dict("records"), no_update, audit, alerts

    # RESET
    if trigger == "confirm-reset":
        wipe_db()
        seed_df = pd.DataFrame(INITIAL)
        seed_df["Risk"] = compute_risk_df(seed_df)
        enr = seed_df["Type"].apply(enrich_mitre).apply(pd.Series)
        seed_df = pd.concat([seed_df, enr], axis=1)
        save_incidents(seed_df)
        save_audit([])
        append_events(seed_df.assign(ID=[1,2,3,4]))
        return seed_df.to_dict("records"), [], [], []

    # MANUAL ADD: behaves like a tick
    if trigger == "add-test":
        next_id = int(df_store["ID"].max()) + 1 if not df_store.empty else 1
        new_row = generate_incident(next_id)
        if new_row["Type"] in PLAYBOOKS:
            new_status = PLAYBOOKS[new_row["Type"]]
            new_row["Status"] = new_status
            log(f"Auto {new_status} (Playbook)", [new_row["ID"]])
        df_store = pd.concat([pd.DataFrame([new_row]), df_store], ignore_index=True).head(200)
        save_incidents(df_store)
        append_events(pd.DataFrame([new_row]))
        if notify_on and new_row["Severity"] == "Critical":
            msg = f'CRITICAL: {new_row["Type"]} (ID {new_row["ID"]}) at {new_row["Time"]}'
            alerts.append({"ts": now_str(), "msg": msg})
            send_slack(msg)
        return df_store.to_dict("records"), no_update, audit, alerts

    # TICK: auto-add new incident, apply playbook, notify if Critical, append event
    if trigger == "tick":
        next_id = int(df_store["ID"].max()) + 1 if not df_store.empty else 1
        new_row = generate_incident(next_id)

        # Playbook
        if new_row["Type"] in PLAYBOOKS:
            new_status = PLAYBOOKS[new_row["Type"]]
            new_row["Status"] = new_status
            log(f"Auto {new_status} (Playbook)", [new_row["ID"]])

        df_store = pd.concat([pd.DataFrame([new_row]), df_store], ignore_index=True).head(200)
        save_incidents(df_store)

        # Event (creation)
        append_events(pd.DataFrame([new_row]))

        # Notify if critical
        if notify_on and new_row["Severity"] == "Critical":
            msg = f'CRITICAL: {new_row["Type"]} (ID {new_row["ID"]}) at {new_row["Time"]}'
            alerts.append({"ts": now_str(), "msg": msg})
            send_slack(msg)

        return df_store.to_dict("records"), no_update, audit, alerts

    # ACTIONS
    if trigger in ("resolve", "contain", "escalate"):
        if derived and selected_rows:
            view_df = pd.DataFrame(derived)
            ids = [view_df.iloc[i]["ID"] for i in selected_rows if 0 <= i < len(view_df)]
            if ids and not df_store.empty:
                if trigger == "resolve":
                    df_store.loc[df_store["ID"].isin(ids), "Status"] = "Resolved"
                elif trigger == "contain":
                    df_store.loc[df_store["ID"].isin(ids), "Status"] = "Containment"
                elif trigger == "escalate":
                    df_store.loc[df_store["ID"].isin(ids), "Status"] = "Escalated"
                log(trigger.capitalize(), ids)
                save_incidents(df_store)
                save_audit(audit)
            return df_store.to_dict("records"), [], audit, alerts
        return df_store.to_dict("records"), [], audit, alerts

    # CSV IMPORT: normalize → ensure risk/MITRE → merge → events/alerts for truly new rows
    if trigger == "upload-buffer" and upload_rows:
        incoming = pd.DataFrame(upload_rows).copy()
        if not incoming.empty:
            # Ensure Risk
            if "Risk" not in incoming.columns:
                incoming["Risk"] = compute_risk_df(incoming)
            else:
                incoming["Risk"] = incoming["Risk"].fillna(compute_risk_df(incoming))
            # Apply playbooks
            incoming["Status"] = [
                PLAYBOOKS.get(t, s)
                for t, s in zip(incoming["Type"], incoming.get("Status", pd.Series(["Open"]*len(incoming))))
            ]
            # Ensure MITRE enrichment
            for col in ["Tactic","Technique","TechniqueID"]:
                if col not in incoming.columns:
                    incoming[col] = None
            missing = incoming["TechniqueID"].isna() | (incoming["TechniqueID"] == "")
            if missing.any():
                enr = incoming.loc[missing, "Type"].apply(enrich_mitre).apply(pd.Series)
                for col in ["Tactic","Technique","TechniqueID"]:
                    incoming.loc[missing, col] = enr[col].values

        # signatures present before merge
        base = df_store[["Type","Severity","Status","Time"]] if not df_store.empty else pd.DataFrame(columns=["Type","Severity","Status","Time"])
        base_keys = set(map(tuple, base.to_records(index=False))) if not base.empty else set()

        merged = merge_and_reassign_ids(df_store, incoming, cap=200)
        save_incidents(merged)
        log("Import CSV", [])
        save_audit(audit)

        # find newly added rows by signature (post-merge)
        merged_keys = merged[["Type","Severity","Status","Time"]]
        new_mask = ~merged_keys.apply(tuple, axis=1).isin(base_keys)
        new_rows = merged.loc[new_mask, ["Time","ID","Type","Severity","Risk","Tactic","Technique","TechniqueID"]]

        if not new_rows.empty:
            append_events(new_rows)
            if notify_on:
                for _, r in new_rows.iterrows():
                    if r["Severity"] == "Critical":
                        msg = f'CRITICAL (import): {r["Type"]} at {r["Time"]}'
                        alerts.append({"ts": now_str(), "msg": msg})
                        send_slack(msg)

        return merged.to_dict("records"), no_update, audit, alerts

    # No change
    return df_store.to_dict("records"), no_update, audit, alerts

# Reflect store into table with MITRE filter (single callback output for incidents.data)
@app.callback(Output("incidents", "data"),
              Input("incident-store", "data"),
              Input("mitre-filter", "value"))
def table_with_mitre_filter(data, filt):
    df = pd.DataFrame(data or [])
    if df.empty:
        return []
    if not filt or filt == "*":
        return df.to_dict("records")
    return df[df["Type"] == filt].to_dict("records")

# KPIs + MTTR + Risk + Top Technique (7d)
@app.callback(Output("kpis", "children"),
              Input("incident-store", "data"),
              Input("audit-log", "data"))
def update_kpis(data, audit):
    df = pd.DataFrame(data or [])
    counts = df["Severity"].value_counts().reindex(SEVERITIES, fill_value=0).to_dict() if not df.empty else {s:0 for s in SEVERITIES}
    total = int(sum(counts.values()))

    # MTTR
    mttr = "-"
    try:
        audit_df = pd.DataFrame(audit or [])
        if not audit_df.empty:
            resolved_ids = []
            for _, row in audit_df[audit_df["Action"] == "Resolve"].iterrows():
                if isinstance(row.get("IDs"), str) and row["IDs"].strip() != "-":
                    resolved_ids.extend([int(x) for x in row["IDs"].split(",") if x.strip().isdigit()])
            if resolved_ids:
                created = df[df["ID"].isin(resolved_ids)][["ID","Time"]].copy()
                created["Time"] = pd.to_datetime(created["Time"], errors="coerce")
                res_when = audit_df[audit_df["Action"] == "Resolve"][["When","IDs"]].copy()
                res_when["When"] = pd.to_datetime(res_when["When"], errors="coerce")
                expanded = []
                for _, r in res_when.iterrows():
                    if isinstance(r.get("IDs"), str):
                        for x in r["IDs"].split(","):
                            x = x.strip()
                            if x.isdigit():
                                expanded.append({"ID": int(x), "ResolvedAt": r["When"]})
                res_df = pd.DataFrame(expanded)
                if not created.empty and not res_df.empty:
                    m = pd.merge(created, res_df, on="ID", how="inner")
                    m["mins"] = (m["ResolvedAt"] - m["Time"]).dt.total_seconds() / 60.0
                    m = m[m["mins"] >= 0]
                    if not m.empty:
                        mttr = f"{m['mins'].mean():.1f} min"
    except Exception:
        mttr = "-"

    avg_risk = "-"
    max_risk = "-"
    if not df.empty and "Risk" in df.columns:
        try:
            avg_risk = f"{pd.to_numeric(df['Risk'], errors='coerce').mean():.0f}"
            max_risk = f"{pd.to_numeric(df['Risk'], errors='coerce').max():.0f}"
        except Exception:
            pass

    def pill(label, value):
        return html.Div(
            [html.Div(label, style={"fontSize": "12px", "opacity": 0.7}),
             html.Div(str(value), style={"fontSize": "22px", "fontWeight": 700})],
            style={"border":"1px solid #eee","borderRadius":"10px","padding":"10px 14px",
                   "minWidth":"120px","boxShadow":"0 2px 8px rgba(0,0,0,0.06)","background":"#fff"},
        )

    pills = [
        pill("Critical", counts.get("Critical",0)),
        pill("High", counts.get("High",0)),
        pill("Medium", counts.get("Medium",0)),
        pill("Low", counts.get("Low",0)),
        pill("Total", total),
        pill("MTTR", mttr),
        pill("Avg Risk", avg_risk),
        pill("Max Risk", max_risk),
    ]

    # Top Technique (7d)
    try:
        ev7 = load_events_since(datetime.now() - timedelta(days=7))
        toptech = "-"
        if ev7 is not None and not ev7.empty:
            cnt = ev7["TechniqueID"].value_counts()
            if not cnt.empty:
                tid = cnt.index[0]
                name = ev7[ev7["TechniqueID"]==tid]["Technique"].iloc[0]
                toptech = f"{tid} ({name})"
        pills.append(pill("Top Technique (7d)", toptech))
    except Exception:
        pass

    return pills

# Pie chart
@app.callback(Output("severity-pie", "figure"), Input("incident-store", "data"))
def severity_pie(data):
    df = pd.DataFrame(data or [])
    order = ["Low", "Medium", "High", "Critical"]
    values = [0,0,0,0] if df.empty else df["Severity"].value_counts().reindex(order, fill_value=0).values.tolist()
    fig = go.Figure(data=[go.Pie(labels=order, values=values, hole=0.5)])
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10))
    return fig

# ----- Analytics charts -----
def range_to_since(value: str):
    if value == "24h":
        return datetime.now() - timedelta(hours=24)
    if value == "7d":
        return datetime.now() - timedelta(days=7)
    if value == "30d":
        return datetime.now() - timedelta(days=30)
    return None  # all

@app.callback(
    Output("trend-incidents", "figure"),
    Output("trend-mttr", "figure"),
    Output("trend-risk", "figure"),
    Input("time-range", "value"),
    Input("incident-store", "data"),
    Input("audit-log", "data"),
)
def render_analytics(range_value, _incidents, _audit):
    since = range_to_since(range_value)

    # Events for counts & risk
    ev = load_events_since(since)
    if ev is None or ev.empty:
        incidents_fig = go.Figure(); incidents_fig.update_layout(title="Incidents per Day (by Severity)")
        mttr_fig = go.Figure(); mttr_fig.update_layout(title="MTTR Trend (min)")
        risk_fig = go.Figure(); risk_fig.update_layout(title="Average Risk per Day")
        return incidents_fig, mttr_fig, risk_fig

    ev["Day"] = ev["When"].dt.date
    # Incidents per day by severity
    counts = ev.groupby(["Day","Severity"]).size().unstack(fill_value=0).reindex(columns=SEVERITIES, fill_value=0)
    incidents_fig = go.Figure()
    for sev in SEVERITIES:
        incidents_fig.add_trace(go.Bar(name=sev, x=counts.index, y=counts[sev]))
    incidents_fig.update_layout(barmode="stack", title="Incidents per Day (by Severity)", xaxis_title="Day", yaxis_title="Count")

    # Avg Risk per day
    risk = ev.groupby("Day")["Risk"].mean()
    risk_fig = go.Figure()
    risk_fig.add_trace(go.Scatter(x=risk.index, y=risk.values, mode="lines+markers", name="Avg Risk"))
    risk_fig.update_layout(title="Average Risk per Day", xaxis_title="Day", yaxis_title="Avg Risk (0–100)")

    # MTTR per day based on Resolve actions
    au = load_audit_since(since)
    con = _connect()
    inc_table = pd.read_sql_query("SELECT ID, Time FROM incidents", con)
    con.close()
    mttr_series = pd.Series(dtype=float)
    if au is not None and not au.empty and not inc_table.empty:
        inc_table["Time"] = pd.to_datetime(inc_table["Time"], errors="coerce")
        res_rows = []
        for _, row in au[au["Action"]=="Resolve"].iterrows():
            when = pd.to_datetime(row["When"], errors="coerce")
            ids = []
            if isinstance(row["IDs"], str) and row["IDs"].strip() != "-":
                for x in row["IDs"].split(","):
                    x = x.strip()
                    if x.isdigit():
                        ids.append(int(x))
            for rid in ids:
                created = inc_table.loc[inc_table["ID"]==rid, "Time"]
                if not created.empty and pd.notna(when):
                    minutes = (when - created.iloc[0]).total_seconds() / 60.0
                    if minutes >= 0:
                        res_rows.append({"Day": when.date(), "mins": minutes})
        if res_rows:
            mttr_df = pd.DataFrame(res_rows)
            mttr_series = mttr_df.groupby("Day")["mins"].mean()
    mttr_fig = go.Figure()
    if not mttr_series.empty:
        mttr_fig.add_trace(go.Scatter(x=mttr_series.index, y=mttr_series.values, mode="lines+markers", name="MTTR"))
    mttr_fig.update_layout(title="MTTR Trend (min)", xaxis_title="Day", yaxis_title="Avg Minutes")

    return incidents_fig, mttr_fig, risk_fig

# Notification banner renderer (renders its own visible Dismiss button)
@app.callback(Output("alert-banner", "children"), Input("alert-queue", "data"))
def render_banner(alerts):
    alerts = alerts or []
    if not alerts:
        return ""
    top = alerts[0]
    return html.Div(
        [
            html.Span("🔔 ", style={"marginRight":"6px"}),
            html.Span(top.get("msg","")),
            html.Button("Dismiss", id="dismiss-alert", n_clicks=0, style={"marginLeft":"12px", "padding":"4px 8px"})
        ],
        style={
           "background": "#fff4f4",
"border": "1px solid #f5c2c2",
"color": "#7a1f1f",
"padding": "8px 10px",
"borderRadius": "8px",
        }
    )

# Download current view (respects sort/filter)
@app.callback(
    Output("download", "data"),
    Input("download-btn", "n_clicks"),
    State("incidents", "derived_virtual_data"),
    prevent_initial_call=True,
)
def download_csv(n, derived):
    df = pd.DataFrame(derived or [])
    if df.empty:
        df = pd.DataFrame(columns=["ID","Type","Severity","Status","Time","Risk","Tactic","Technique","TechniqueID"])
    cols = ["ID","Type","Severity","Status","Time","Risk","Tactic","Technique","TechniqueID"]
    present = [c for c in cols if c in df.columns]
    return dcc.send_data_frame(df[present].to_csv, "incidents_export.csv", index=False)

# Reflect audit store into audit table
@app.callback(Output("audit", "data"), Input("audit-log", "data"))
def audit_to_table(data):
    return data or []

if __name__ == "__main__":
    app.run(debug=False, port=8060, host="127.0.0.1", dev_tools_hot_reload=False) 
