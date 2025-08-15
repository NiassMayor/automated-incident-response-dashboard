from dash import Dash, html, dcc, ctx, no_update
from dash.dash_table import DataTable
from dash.dependencies import Input, Output, State
import pandas as pd
from datetime import datetime
import random, io, base64
import plotly.graph_objects as go

print("Starting dashboard (auto-refresh, resolve, pie, CSV import + download)…")

app = Dash(__name__)

# ---- Seed data & helpers ----
SEVERITIES = ["Low", "Medium", "High", "Critical"]
SEVERITY_WEIGHTS = [0.2, 0.35, 0.3, 0.15]
TYPES = [
    "Phishing Email", "Malware Detected", "Unauthorized Login",
    "Brute-force Attempt", "Suspicious DNS", "Data Exfiltration", "Rogue Device",
]
STATUSES = ["Open", "Investigating", "Containment", "Resolved"]

INITIAL = [
    {"ID": 1, "Type": "Phishing Email",     "Severity": "High",     "Status": "Open",          "Time": "2025-08-14 21:30"},
    {"ID": 2, "Type": "Malware Detected",   "Severity": "Critical", "Status": "Investigating", "Time": "2025-08-14 21:31"},
    {"ID": 3, "Type": "Unauthorized Login", "Severity": "Medium",   "Status": "Resolved",      "Time": "2025-08-14 21:33"},
    {"ID": 4, "Type": "Data Exfiltration",  "Severity": "Critical", "Status": "Open",          "Time": "2025-08-14 21:35"},
]

def generate_incident(next_id: int) -> dict:
    return {
        "ID": next_id,
        "Type": random.choice(TYPES),
        "Severity": random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0],
        "Status": random.choice(STATUSES[:-1]) if random.random() < 0.85 else "Open",
        "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

# Normalize uploaded CSV columns to our schema
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
    sev = df.get("Severity", "Medium").astype(str).str.title()
    sev = sev.replace({"Informational":"Low", "Info":"Low", "Warn":"High", "Warning":"High"})
    out["Severity"] = sev.where(sev.isin(SEVERITIES), "Medium")
    out["Status"] = df.get("Status", "Open").astype(str).str.title().replace({"New":"Open"})
    time_col = df.get("Time")
    if time_col is not None:
        try:
            out["Time"] = pd.to_datetime(time_col, errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            out["Time"] = time_col.astype(str)
        out["Time"] = out["Time"].fillna(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    else:
        out["Time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return out[["Type", "Severity", "Status", "Time"]]

def parse_csv_contents(contents: str) -> pd.DataFrame:
    if not contents:
        return pd.DataFrame()
    try:
        _, b64 = contents.split(",", 1)
        decoded = base64.b64decode(b64)
        text = decoded.decode("utf-8", errors="ignore")
        df = pd.read_csv(io.StringIO(text))
        if df.empty:
            return pd.DataFrame()
        return normalize_columns(df)
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

# ---- Layout ----
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
                html.Button("Download CSV", id="download-btn", n_clicks=0, style={"padding": "8px 12px"}),  # NEW
                dcc.Download(id="download"),  # NEW
                dcc.Upload(
                    id="uploader",
                    children=html.Div(["📄 Drag & drop CSV here, or ", html.A("click to upload")]),
                    multiple=False,
                    accept=".csv,text/csv",
                    style={"border": "1px dashed #aaa","borderRadius": "10px","padding": "8px 12px","cursor": "pointer"},
                ),
            ],
            style={"display": "flex", "alignItems": "center", "gap": "12px", "marginBottom": "12px", "flexWrap": "wrap"},
        ),
        html.Div(id="kpis", style={"display": "flex", "gap": "12px", "flexWrap": "wrap", "marginBottom": "12px"}),
        html.Div(
            [
                html.Div(
                    DataTable(
                        id="incidents",
                        columns=[{"name": c, "id": c} for c in ["ID", "Type", "Severity", "Status", "Time"]],
                        data=INITIAL,
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
            style={"display": "flex", "gap": "16px", "alignItems": "stretch"},
        ),

        dcc.Store(id="incident-store", data=INITIAL),
        dcc.Store(id="upload-buffer", data=None),
        dcc.Interval(id="tick", interval=5_000, n_intervals=0),
    ],
    style={"maxWidth": "1100px", "margin": "40px auto", "fontFamily": "sans-serif"},
)

# ---- Callbacks ----

@app.callback(Output("tick", "disabled"), Input("auto", "value"))
def toggle_auto(value):
    return "on" not in (value or [])

@app.callback(Output("upload-buffer", "data"), Input("uploader", "contents"), prevent_initial_call=True)
def parse_upload(contents):
    df = parse_csv_contents(contents)
    return None if df.empty else df.to_dict("records")

# Single writer: auto-add, resolve, or merge upload
@app.callback(
    Output("incident-store", "data"),
    Output("incidents", "selected_rows"),
    Input("tick", "n_intervals"),
    Input("resolve", "n_clicks"),
    Input("upload-buffer", "data"),
    State("incidents", "derived_virtual_data"),
    State("incidents", "derived_virtual_selected_rows"),
    State("incident-store", "data"),
    prevent_initial_call=True,
)
def update_store(_n, _clicks, upload_rows, derived, selected_rows, store_data):
    trigger = ctx.triggered_id
    df_store = pd.DataFrame(store_data or [])

    if trigger == "tick":
        next_id = (df_store["ID"].max() + 1) if not df_store.empty else 1
        df_store = pd.concat([pd.DataFrame([generate_incident(next_id)]), df_store], ignore_index=True).head(200)
        return df_store.to_dict("records"), no_update

    if trigger == "resolve":
        if derived and selected_rows:
            view_df = pd.DataFrame(derived)
            selected_ids = set(view_df.iloc[i]["ID"] for i in selected_rows if 0 <= i < len(view_df))
            if selected_ids and not df_store.empty:
                df_store.loc[df_store["ID"].isin(selected_ids), "Status"] = "Resolved"
            return df_store.to_dict("records"), []
        return df_store.to_dict("records"), []

    if trigger == "upload-buffer" and upload_rows:
        incoming = pd.DataFrame(upload_rows)
        merged = merge_and_reassign_ids(df_store, incoming, cap=200)
        return merged.to_dict("records"), no_update

    return df_store.to_dict("records"), no_update

@app.callback(Output("incidents", "data"), Input("incident-store", "data"))
def table_from_store(data):
    return data

@app.callback(Output("kpis", "children"), Input("incident-store", "data"))
def update_kpis(data):
    df = pd.DataFrame(data or [])
    counts = df["Severity"].value_counts().reindex(SEVERITIES, fill_value=0).to_dict() if not df.empty else {s:0 for s in SEVERITIES}
    total = int(sum(counts.values()))
    def pill(label, value):
        return html.Div(
            [html.Div(label, style={"fontSize": "12px", "opacity": 0.7}),
             html.Div(str(value), style={"fontSize": "22px", "fontWeight": 700})],
            style={"border":"1px solid #eee","borderRadius":"10px","padding":"10px 14px",
                   "minWidth":"120px","boxShadow":"0 2px 8px rgba(0,0,0,0.06)","background":"#fff"},
        )
    return [pill("Critical", counts.get("Critical",0)), pill("High", counts.get("High",0)),
            pill("Medium", counts.get("Medium",0)), pill("Low", counts.get("Low",0)), pill("Total", total)]

@app.callback(Output("severity-pie", "figure"), Input("incident-store", "data"))
def severity_pie(data):
    df = pd.DataFrame(data or [])
    values = [0,0,0,0] if df.empty else df["Severity"].value_counts().reindex(SEVERITIES, fill_value=0).values.tolist()
    fig = go.Figure(data=[go.Pie(labels=SEVERITIES, values=values, hole=0.5)])
    fig.update_layout(margin=dict(l=10,r=10,t=10,b=10))
    return fig

# NEW: Download current view (respects sort/filter)
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

if __name__ == "__main__":
    app.run_server(debug=False, port=8060, host="127.0.0.1", dev_tools_hot_reload=False)

