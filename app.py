from dash import Dash, dcc, html, dash_table
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
import pandas as pd
import plotly.express as px
from capture import start_capture_thread, stop_capture_func
import os
import threading
from scapy.utils import rdpcap  # For PCAP file processing
import base64
import io


# Initialize the Dash app
app = Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

# Global variable to hold the current capture file and capture thread
current_capture_file = None
capture_thread = None
is_capturing = False  # To track if a capture is currently running

# Initial layout where user chooses action
app.layout = html.Div([
    html.H1("Network Traffic Tool"),
    
    dcc.Dropdown(
        id='action-choice',
        options=[
            {'label': 'Start Capture', 'value': 'capture'},
            {'label': 'Analyze File', 'value': 'analyze'}
        ],
        placeholder="Select Action",
        style={'width': '50%', 'margin': '20px'}
    ),
    
    html.Button('Proceed', id='proceed-button', n_clicks=0, style={'margin': '20px'}),
    html.Div(id='interface-container')
])

# Layout for live capture
capture_layout = html.Div([
    html.H2("Start Network Capture"),
    
    html.Button('Start Capture', id='start-button', n_clicks=0),
    html.Button('Stop Capture', id='stop-button', n_clicks=0),
    
    dcc.Dropdown(
        id='protocol-filter',
        placeholder="Select Protocol",
        style={'width': '50%', 'margin': '20px'}
    ),
    
    dash_table.DataTable(
        id='network-table',
        columns=[{"name": i, "id": i} for i in [
            "Protocol", "Source Port", "Destination Port", "Protocol Score", 
            "Port Score", "Total Score", "Risk"
        ]],
        data=[],
        style_table={'height': '400px', 'overflowY': 'auto'},
        style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
        style_cell={'textAlign': 'center'}
    ),
    
    dcc.Graph(id='risk-bar-chart'),
    dcc.Graph(id='protocol-score-bar-chart'),
    dcc.Graph(id='port-score-heatmap'),
    
    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0)
])

# Layout for file analysis
file_analysis_layout = html.Div([
    html.H2("Upload File for Analysis"),
    
    dcc.Upload(
        id='file-upload',
        children=html.Div(['Drag and Drop or ', html.A('Select a File')]),
        style={
            'width': '100%',
            'height': '60px',
            'lineHeight': '60px',
            'borderWidth': '1px',
            'borderStyle': 'dashed',
            'borderRadius': '5px',
            'textAlign': 'center',
            'margin': '20px'
        },
        multiple=False,
        accept='.csv, .pcap'  # Allow CSV and PCAP files
    ),
    
    dash_table.DataTable(
        id='file-analysis-table',
        columns=[{"name": i, "id": i} for i in [
            "Protocol", "Source Port", "Destination Port", "Protocol Score", 
            "Port Score", "Total Score", "Risk"
        ]],
        data=[],
        style_table={'height': '400px', 'overflowY': 'auto'},
        style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
        style_cell={'textAlign': 'center'}
    ),
    
    dcc.Graph(id='file-risk-bar-chart'),
    dcc.Graph(id='file-protocol-score-bar-chart'),
    dcc.Graph(id='file-port-score-heatmap')
])

# Callback to switch between layouts
@app.callback(
    Output('interface-container', 'children'),
    [Input('proceed-button', 'n_clicks')],
    [State('action-choice', 'value')]
)
def switch_interface(n_clicks, action_choice):
    if n_clicks > 0:
        if action_choice == 'capture':
            return capture_layout
        elif action_choice == 'analyze':
            return file_analysis_layout
    return ""

# Helper function to process PCAP file
def process_pcap(file_content):
    packets = rdpcap(file_content)  # Read the PCAP file
    data = []

    for packet in packets:
        # Extract relevant information from the packet
        protocol = packet.proto if hasattr(packet, 'proto') else 'Unknown'
        src_port = packet.sport if hasattr(packet, 'sport') else 'Unknown'
        dst_port = packet.dport if hasattr(packet, 'dport') else 'Unknown'
        
        # For demo purposes, assuming protocol score, port score, and risk
        protocol_score = 1  # Calculate this based on your risk metrics
        port_score = 1  # Calculate this based on your risk metrics
        total_score = protocol_score + port_score
        risk = 'Low' if total_score < 3 else 'High'  # Simplified risk scoring

        data.append({
            "Protocol": protocol,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Protocol Score": protocol_score,
            "Port Score": port_score,
            "Total Score": total_score,
            "Risk": risk
        })
    
    df = pd.DataFrame(data)
    return df

# Callback for file analysis
@app.callback(
    [Output('file-analysis-table', 'data'),
     Output('file-risk-bar-chart', 'figure'),
     Output('file-protocol-score-bar-chart', 'figure'),
     Output('file-port-score-heatmap', 'figure')],
    [Input('file-upload', 'contents')],
    [State('file-upload', 'filename')]
)
def analyze_file(contents, filename):
    if contents is not None:
        # Decode uploaded file
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        
        if filename.endswith('.csv'):
            # If it's a CSV file, load it into a DataFrame
            df = pd.read_csv(io.StringIO(decoded.decode('utf-8')))
        elif filename.endswith('.pcap'):
            # If it's a PCAP file, process it using scapy
            df = process_pcap(io.BytesIO(decoded))

        # Generate Risk Bar Chart
        risk_count = df['Risk'].value_counts().reset_index()
        risk_count.columns = ['Risk', 'Count']
        risk_fig = px.bar(risk_count, x='Risk', y='Count', title='Risk Level Distribution')

        # Generate Protocol Score Bar Chart
        protocol_avg_score = df.groupby('Protocol')['Protocol Score'].mean().reset_index()
        protocol_fig = px.bar(protocol_avg_score, x='Protocol', y='Protocol Score', title='Average Protocol Scores')

        # Generate Port Score Heatmap
        port_df = df.groupby(['Source Port', 'Destination Port'])['Port Score'].sum().reset_index()
        port_heatmap = px.density_heatmap(port_df, x='Source Port', y='Destination Port', z='Port Score',
                                          title='Source and Destination Port Score Distribution')

        return df.to_dict('records'), risk_fig, protocol_fig, port_heatmap

    return [], {}, {}, {}

# Run the app
if __name__ == "__main__":
    app.run_server(debug=True)
