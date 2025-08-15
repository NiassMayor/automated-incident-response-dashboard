# src/app.py
from dash import Dash, html, dcc, ctx, no_update
from dash.dash_table import DataTable
from dash.dependencies import Input, Output, State
import pandas as pd
from datetime import datetime
import random, io, base64, os, sqlite3
import plotly.graph_objects as go

print("Starting dashboard (stable: single-writer + SQLite + reset)…")

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
            Type TEXT, Severity TEXT, Status TEXT, Time TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            "When" TEXT, Action TEXT, IDs TEXT, Count INTEGER
        )
    """)
    con.commit()
    con.close()

def load_tables():
    init_db()
    con = _connect()
    try:
        inc = pd.read_sql_query(
            "SELECT ID, Type, Severity, Status, Time FROM incidents ORDER BY ID DESC",
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
    return inc, aud

def save_incidents(df):
    con = _connect()
    cur = con.cursor()
    cur.execute("DELETE FROM incidents")
    if df is not None and not df.empty:
        cur.executemany(
            "INSERT INTO incidents (ID, Type, Severity, Status, Time) VALUES (?, ?, ?, ?, ?)",
            df[["ID","Type","Severity","Status","Time"]].itertuples(index=False, name=None)
        )
    con.commit()
    con.close()

def save_audit(records):
    con = _connect()
    cur = con.cursor()
    cur.execute("DELETE FROM audit")
    for r in (records or []):
        cur.execute(
            'INSERT INTO audit ("When", Action, IDs, Count) VALUES (?, ?, ?, ?)',
            (r.get("When",""), r.get("Action",""), r.get("IDs","-"), int(r.get("Count",0)))
        )
    con.commit()
    con.close()

def wipe_db():
    """Delete the SQLite file and recreate empty tables."""
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

INITIAL = [
    {"ID": 1, "Type": "Phishing Email",     "Severity": "High",     "Status": "Open",          "Time": "2025-08-14 21:30"},
    {"ID": 2, "Type": "Malware Detected",   "Severity": "Critical", "Status": "Investigating", "Time": "2025-08-14 21:31"},
    {"ID": 3, "Type": "Unauthorized Login", "Severity": "Medium",   "Status": "Resolved",      "Time": "2025-08-14 21:33"},
    {"ID": 4, "Type": "Data Exfiltration",  "Severity": "Critical", "Status": "Open",          "Time": "2025-08-14 21:35"},
]

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def generate_incident(next_id: int) -> dict:
    return {
        "ID": next_id,
        "Type": random.choice(TYPES),
        "Severity": random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0],
        "Status": random.choice(STATUSES[:-1]) if random.random() < 0.85 else "Open",
        "Time": now_str(),
    }

# ---------------- CSV normalization helpers ----------------
COLUMN_ALIASES = {
    "id": "ID", "alert_id": "ID", "incident_id": "ID",
    "name": "Type", "alertname": "Type", "title": "Type", "category": "Type", "type": "Type",
    "severity": "Severity", "level": "Severity", "priority": "Severity",
    "status": "Status", "state": "Status",
    "time": "Time", "timestamp": "Time", "event_time": "Time", "@timestamp": "Time",
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
    return out[["Type", "Severity", "Status", "Time"]]

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
        current = pd.DataFrame(columns=["ID", "Type", "Severity", "Status", "Time"])
    base = current[["Type","Severity","Status","Time"]].copy()
    merged = pd.concat([incoming, base], ignore_index=True).drop_duplicates(
        subset=["Type","Severity","Status","Time"], keep="first"
    )
    merged.insert(0, "ID", range(len(merged), 0, -1))
    merged = merged.sort_values("ID", ascending=False).reset_index(drop=True)
    return merged.head(cap)

# ---------------- Load persisted data (or seed) ----------------
init_db()
db_incidents, db_audit = load_tables()
if db_incidents.empty:
    save_incidents(pd.DataFrame(INITIAL))
    incidents_init = INITIAL
else:
    incidents_init = db_incidents.to_dict("records")

audit_init = db_audit.to_dict("records") if not db_audit.empty else []

# ---------------- Create Dash app ----------------
app = Dash(__name__)

# ---------------- Layout ----------------
app.layout = html.Div(
    [
        html.H1("Automated Incident Response Dashboard"),
        html.Div(
            [
                dcc.Checklist(
                    id="auto",
                    options=[{"label": " Auto-refresh", "value": "on"}],
                    value=["on"],
                    style={"marginRight": "12px"},
                ),
                html.Button("Resolve Selected", id="resolve", n_clicks=0, style={"padding": "8px 12px"}),
                html.Button("Contain Selected", id="contain", n_clicks=0, style={"padding": "8px 12px"}),
                html.Button("Escalate Selected", id="escalate", n_clicks=0, style={"padding": "8px 12px"}),
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
            style={"display": "flex", "alignItems": "center", "gap": "10px", "marginBottom": "12px", "flexWrap": "wrap"},
        ),

        # KPIs
        html.Div(id="kpis", style={"display": "flex", "gap": "12px", "flexWrap": "wrap", "marginBottom": "12px"}),

        # Main grid
        html.Div(
            [
                html.Div(
                    DataTable(
                        id="incidents",
                        columns=[{"name": c, "id": c} for c in ["ID", "Type", "Severity", "Status", "Time"]],
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
                        ],
                    ),
                    style={"flex": 2, "minWidth": "480px"},
                ),
                html.Div(
                    dcc.Graph(id="severity-pie"),
                    style={"flex": 1, "minWidth": "280px"},
                ),
            ],
            style={"display": "flex", "gap": "16px", "alignItems": "stretch", "marginBottom": "16px"},
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
        dcc.Interval(id="tick", interval=5_000, n_intervals=0),
    ],
    style={"maxWidth": "1100px", "margin": "40px auto", "fontFamily": "sans-serif"},
)

# ---------------- Callbacks ----------------

# Toggle auto-refresh
@app.callback(Output("tick", "disabled"), Input("auto", "value"))
def toggle_auto(value):
    return "on" not in (value or [])

# Parse upload to buffer
@app.callback(Output("upload-buffer", "data"), Input("uploader", "contents"), prevent_initial_call=True)
def parse_upload(contents):
    df = parse_csv_contents(contents)
    return None if df.empty else df.to_dict("records")

# Open confirm dialog
@app.callback(
    Output("confirm-reset", "displayed"),
    Input("reset", "n_clicks"),
    prevent_initial_call=True,
)
def open_reset_dialog(n):
    return True

# ---------- SINGLE WRITER for all mutations ----------
@app.callback(
    Output("incident-store", "data"),
    Output("incidents", "selected_rows"),
    Output("audit-log", "data"),
    Input("tick", "n_intervals"),
    Input("resolve", "n_clicks"),
    Input("contain", "n_clicks"),
    Input("escalate", "n_clicks"),
    Input("upload-buffer", "data"),
    Input("confirm-reset", "submit_n_clicks"),
    State("incidents", "derived_virtual_data"),
    State("incidents", "derived_virtual_selected_rows"),
    State("incident-store", "data"),
    State("audit-log", "data"),
    prevent_initial_call=True,
)
def single_writer(_n, _resolve, _contain, _escalate, upload_rows, reset_submit,
                  derived, selected_rows, store_data, audit_data):
    trigger = ctx.triggered_id
    df_store = pd.DataFrame(store_data or [])
    audit = list(audit_data or [])

    def log(action, ids):
        audit.insert(0, {
            "When": now_str(),
            "Action": action,
            "IDs": ",".join(map(str, sorted(ids))) if ids else "-",
            "Count": len(ids)
        })

    # Handle RESET first
    if trigger == "confirm-reset":
        wipe_db()
        seed_df = pd.DataFrame(INITIAL)
        save_incidents(seed_df)
        save_audit([])
        return seed_df.to_dict("records"), [], []

    # Auto-add incident on tick
    if trigger == "tick":
        next_id = (df_store["ID"].max() + 1) if not df_store.empty else 1
        df_store = pd.concat([pd.DataFrame([generate_incident(next_id)]), df_store],
                             ignore_index=True).head(200)
        save_incidents(df_store)
        return df_store.to_dict("records"), no_update, audit

    # Actions
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
            return df_store.to_dict("records"), [], audit
        return df_store.to_dict("records"), [], audit

    # CSV import
    if trigger == "upload-buffer" and upload_rows:
        incoming = pd.DataFrame(upload_rows)
        merged = merge_and_reassign_ids(df_store, incoming, cap=200)
        log("Import CSV", [])
        save_incidents(merged)
        save_audit(audit)
        return merged.to_dict("records"), no_update, audit

    # Fallback (no change)
    return df_store.to_dict("records"), no_update, audit

# Reflect store into table
@app.callback(Output("incidents", "data"), Input("incident-store", "data"))
def table_from_store(data):
    return data

# KPIs + MTTR
@app.callback(Output("kpis", "children"), Input("incident-store", "data"), Input("audit-log", "data"))
def update_kpis(data, audit):
    df = pd.DataFrame(data or [])
    counts = df["Severity"].value_counts().reindex(SEVERITIES, fill_value=0).to_dict() if not df.empty else {s:0 for s in SEVERITIES}
    total = int(sum(counts.values()))

    # MTTR from audit "Resolve" actions
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

    def pill(label, value):
        return html.Div(
            [html.Div(label, style={"fontSize": "12px", "opacity": 0.7}),
             html.Div(str(value), style={"fontSize": "22px", "fontWeight": 700})],
            style={"border":"1px solid #eee","borderRadius":"10px","padding":"10px 14px",
                   "minWidth":"120px","boxShadow":"0 2px 8px rgba(0,0,0,0.06)","background":"#fff"},
        )

    return [
        pill("Critical", counts.get("Critical",0)),
        pill("High", counts.get("High",0)),
        pill("Medium", counts.get("Medium",0)),
        pill("Low", counts.get("Low",0)),
        pill("Total", total),
        pill("MTTR", mttr),
    ]

# Pie chart (fixed order, safe on empty)
@app.callback(Output("severity-pie", "figure"), Input("incident-store", "data"))
def severity_pie(data):
    df = pd.DataFrame(data or [])
    order = ["Low", "Medium", "High", "Critical"]
    values = [0,0,0,0] if df.empty else df["Severity"].value_counts().reindex(order, fill_value=0).values.tolist()
    fig = go.Figure(data=[go.Pie(labels=order, values=values, hole=0.5)])
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10))
    return fig

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
        df = pd.DataFrame(columns=["ID", "Type", "Severity", "Status", "Time"])
    return dcc.send_data_frame(df.to_csv, "incidents_export.csv", index=False)

# Reflect audit store into audit table
@app.callback(Output("audit", "data"), Input("audit-log", "data"))
def audit_to_table(data):
    return data or []

if __name__ == "__main__":
    app.run(debug=False, port=8060, host="127.0.0.1", dev_tools_hot_reload=False) 