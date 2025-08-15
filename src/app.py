from dash import Dash, html, dcc, ctx, no_update
from dash.dash_table import DataTable
from dash.dependencies import Input, Output, State
import pandas as pd
from datetime import datetime
import random
import plotly.graph_objects as go

print("Starting dashboard (auto-refresh, resolve, pie)…")

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
            ],
            style={"display": "flex", "alignItems": "center", "gap": "12px", "marginBottom": "12px"},
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

        # State store & timer
        dcc.Store(id="incident-store", data=INITIAL),
        dcc.Interval(id="tick", interval=5_000, n_intervals=0),
    ],
    style={"maxWidth": "1100px", "margin": "40px auto", "fontFamily": "sans-serif"},
)

# ---- Callbacks ----

# Enable/disable auto-refresh
@app.callback(
    Output("tick", "disabled"),
    Input("auto", "value"),
)
def toggle_auto(value):
    return "on" not in (value or [])

# SINGLE writer to the store + also clears selection after resolve
@app.callback(
    Output("incident-store", "data"),
    Output("incidents", "selected_rows"),     # NEW: clear selection
    Input("tick", "n_intervals"),
    Input("resolve", "n_clicks"),
    State("incident-store", "data"),
    State("incidents", "derived_virtual_data"),
    State("incidents", "derived_virtual_selected_rows"),
    prevent_initial_call=True,
)
def update_store(_n, _clicks, store_data, derived_data, selected_rows):
    trigger = ctx.triggered_id
    data = list(store_data or [])

    if trigger == "tick":
        next_id = (max([r["ID"] for r in data]) + 1) if data else 1
        data.insert(0, generate_incident(next_id))
        return data[:200], no_update  # don’t touch selection on auto-add

    if trigger == "resolve":
        if not derived_data or not selected_rows:
            return data, []  # nothing selected → also ensure selection cleared
        store_df = pd.DataFrame(data)
        view_df = pd.DataFrame(derived_data)
        selected_ids = set(view_df.iloc[i]["ID"] for i in selected_rows if 0 <= i < len(view_df))
        if selected_ids and not store_df.empty:
            store_df.loc[store_df["ID"].isin(selected_ids), "Status"] = "Resolved"
        return store_df.to_dict("records"), []  # clear selection

    return data, no_update

# Push store into table
@app.callback(
    Output("incidents", "data"),
    Input("incident-store", "data"),
)
def table_from_store(data):
    return data

# KPI pills
@app.callback(
    Output("kpis", "children"),
    Input("incident-store", "data"),
)
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

# Severity pie chart
@app.callback(
    Output("severity-pie", "figure"),
    Input("incident-store", "data"),
)
def severity_pie(data):
    df = pd.DataFrame(data or [])
    if df.empty:
        values = [0,0,0,0]
    else:
        vc = df["Severity"].value_counts().reindex(SEVERITIES, fill_value=0)
        values = vc.values.tolist()
    fig = go.Figure(data=[go.Pie(labels=SEVERITIES, values=values, hole=0.5)])
    fig.update_layout(margin=dict(l=10,r=10,t=10,b=10))
    return fig

if __name__ == "__main__":
    app.run_server(debug=False, port=8060, host="127.0.0.1", dev_tools_hot_reload=False)

