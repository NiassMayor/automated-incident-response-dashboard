from dash import Dash, html, dcc
from dash.dash_table import DataTable
from dash.dependencies import Input, Output, State
import pandas as pd
from datetime import datetime
import random

print("Starting dashboard with auto-refresh...")

app = Dash(__name__)

# --- Seed data ---
INITIAL = [
    {"ID": 1, "Type": "Phishing Email",      "Severity": "High",     "Status": "Open",          "Time": "2025-08-14 21:30"},
    {"ID": 2, "Type": "Malware Detected",    "Severity": "Critical", "Status": "Investigating", "Time": "2025-08-14 21:31"},
    {"ID": 3, "Type": "Unauthorized Login",  "Severity": "Medium",   "Status": "Resolved",      "Time": "2025-08-14 21:33"},
    {"ID": 4, "Type": "Data Exfiltration",   "Severity": "Critical", "Status": "Open",          "Time": "2025-08-14 21:35"},
]

TYPES = [
    "Phishing Email",
    "Malware Detected",
    "Unauthorized Login",
    "Brute-force Attempt",
    "Suspicious DNS",
    "Data Exfiltration",
    "Rogue Device",
]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
SEVERITY_WEIGHTS = [0.2, 0.35, 0.3, 0.15]  # tweak to taste
STATUSES = ["Open", "Investigating", "Containment", "Resolved"]

def generate_incident(next_id: int) -> dict:
    return {
        "ID": next_id,
        "Type": random.choice(TYPES),
        "Severity": random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0],
        "Status": random.choice(STATUSES[:-1]) if random.random() < 0.85 else "Open",
        "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

# --- Layout ---
app.layout = html.Div(
    [
        html.H1("Automated Incident Response Dashboard"),
        html.Div(
            id="kpis",
            style={"display": "flex", "gap": "12px", "marginBottom": "12px", "flexWrap": "wrap"},
        ),
        DataTable(
            id="incidents",
            columns=[{"name": c, "id": c} for c in ["ID", "Type", "Severity", "Status", "Time"]],
            data=INITIAL,
            page_size=10,
            sort_action="native",
            filter_action="native",
            style_cell={"textAlign": "left", "padding": "6px", "fontFamily": "sans-serif"},
            style_header={"fontWeight": "bold"},
            style_data_conditional=[
                {"if": {"filter_query": '{Severity} = "Critical"'}, "backgroundColor": "#ffcccc"},
                {"if": {"filter_query": '{Severity} = "High"'},     "backgroundColor": "#ffe5cc"},
            ],
        ),
        # Store + timer
        dcc.Store(id="incident-store", data=INITIAL),
        dcc.Interval(id="tick", interval=5_000, n_intervals=0),  # every 5s
    ],
    style={"maxWidth": "1000px", "margin": "40px auto", "fontFamily": "sans-serif"},
)

# --- Callbacks ---

# Add a new incident every tick (cap list length for performance)
@app.callback(
    Output("incident-store", "data"),
    Input("tick", "n_intervals"),
    State("incident-store", "data"),
    prevent_initial_call=True,
)
def add_incident(_n, data):
    data = list(data or [])
    next_id = (max([r["ID"] for r in data]) + 1) if data else 1
    data.insert(0, generate_incident(next_id))         # newest first
    return data[:100]                                   # keep last 100

# Push store into table
@app.callback(
    Output("incidents", "data"),
    Input("incident-store", "data"),
)
def update_table(data):
    return data

# Tiny KPI bar (counts by severity)
@app.callback(
    Output("kpis", "children"),
    Input("incident-store", "data"),
)
def update_kpis(data):
    df = pd.DataFrame(data or [])
    if df.empty:
        counts = {s: 0 for s in SEVERITIES}
    else:
        counts = df["Severity"].value_counts().reindex(SEVERITIES, fill_value=0).to_dict()

    def pill(label, value):
        return html.Div(
            [html.Div(label, style={"fontSize": "12px", "opacity": 0.7}),
             html.Div(str(value), style={"fontSize": "22px", "fontWeight": 700})],
            style={
                "border": "1px solid #eee",
                "borderRadius": "10px",
                "padding": "10px 14px",
                "minWidth": "120px",
                "boxShadow": "0 2px 8px rgba(0,0,0,0.06)",
                "background": "#fff",
            },
        )

    return [
        pill("Critical", counts.get("Critical", 0)),
        pill("High",     counts.get("High", 0)),
        pill("Medium",   counts.get("Medium", 0)),
        pill("Low",      counts.get("Low", 0)),
        pill("Total",    int(sum(counts.values()))),
    ]

if __name__ == "__main__":
    app.run_server(debug=False, port=8060, host="127.0.0.1", dev_tools_hot_reload=False) 
