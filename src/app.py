import dash
from dash import html

print("Starting dashboard...")  # Debug message to confirm script runs

# Initialize the Dash app
app = dash.Dash(__name__)

# Define the dashboard layout
app.layout = html.Div([
    html.H1("Automated Incident Response Dashboard"),
    html.P("Welcome! This dashboard will display live incident data."),
])

# Run the app
if __name__ == "__main__":
    app.run_server(debug=True)

