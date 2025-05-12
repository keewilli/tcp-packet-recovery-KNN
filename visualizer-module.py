#!/usr/bin/env python3
"""
visualizer.py - Module for real-time visualization of packet loss and recovery

This module provides a web-based dashboard for visualizing TCP packet statistics,
including packet loss, recovery rates, and stream information.
"""

import time
import threading
import logging
from typing import Dict, List, Optional, Callable, Any
import datetime
import json

import dash
from dash import dcc, html, callback_context
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import numpy as np

from .event_logger import EventLogger

logger = logging.getLogger(__name__)

class PacketVisualizer:
    """Visualizes packet loss and recovery statistics in real-time."""
    
    def __init__(self, 
                event_logger: Optional[EventLogger] = None,
                update_interval: float = 1.0,
                host: str = '127.0.0.1',
                port: int = 8050,
                debug: bool = False):
        """
        Initialize the packet visualizer.
        
        Args:
            event_logger: EventLogger instance for retrieving statistics
            update_interval: How often to update visualizations (in seconds)
            host: Host address to bind the server to
            port: Port to bind the server to
            debug: Whether to run the Dash app in debug mode
        """
        self.event_logger = event_logger
        self.update_interval = update_interval
        self.host = host
        self.port = port
        self.debug = debug
        self.app = None
        self.server_thread = None
        self.running = False
        self.stream_stats = {}
        self.packet_loss_history = []
        self.event_history = []
        self.stream_ids = []
        self.current_stream_id = None
        self.data_callbacks = []
    
    def register_data_callback(self, callback: Callable):
        """
        Register a callback function to provide additional data.
        
        Args:
            callback: Function taking no arguments and returning a dict of data
        """
        self.data_callbacks.append(callback)
    
    def get_stream_data(self, stream_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get stream data for visualization.
        
        Args:
            stream_id: Stream identifier or None for all streams
            
        Returns:
            Dict: Stream data
        """
        data = {
            'stream_ids': self.stream_ids,
            'current_stream_id': stream_id or self.current_stream_id,
            'stream_stats': {},
            'packet_loss_history': [],
            'event_history': []
        }
        
        # If we have an event logger, get the data from it
        if self.event_logger:
            # Get stream stats
            stats = self.event_logger.get_stream_stats(stream_id=stream_id, limit=1)
            if stats:
                data['stream_stats'] = stats[0]
            
            # Get packet loss history
            history = self.event_logger.get_packet_loss_over_time(
                stream_id=stream_id, interval='minute', limit=60
            )
            data['packet_loss_history'] = history
            
            # Get event history
            events = self.event_logger.get_stream_events(
                stream_id=stream_id or self.current_stream_id, limit=100
            ) if stream_id or self.current_stream_id else []
            data['event_history'] = events
        
        # Get additional data from callbacks
        for callback in self.data_callbacks:
            try:
                callback_data = callback()
                if callback_data:
                    # Update stream IDs
                    if 'stream_ids' in callback_data and callback_data['stream_ids']:
                        data['stream_ids'] = callback_data['stream_ids']
                    
                    # Update or set current stream ID if not already set
                    if not data['current_stream_id'] and 'current_stream_id' in callback_data:
                        data['current_stream_id'] = callback_data['current_stream_id']
                    
                    # Update stream stats
                    if 'stream_stats' in callback_data and callback_data['stream_stats']:
                        if not data['stream_stats']:
                            data['stream_stats'] = callback_data['stream_stats']
                        else:
                            data['stream_stats'].update(callback_data['stream_stats'])
                    
                    # Add to packet loss history
                    if 'packet_loss_history' in callback_data and callback_data['packet_loss_history']:
                        if not data['packet_loss_history']:
                            data['packet_loss_history'] = callback_data['packet_loss_history']
                        else:
                            # Merge histories based on timestamp
                            existing_times = {item['timestamp'] for item in data['packet_loss_history']}
                            for item in callback_data['packet_loss_history']:
                                if item['timestamp'] not in existing_times:
                                    data['packet_loss_history'].append(item)
                    
                    # Add to event history
                    if 'event_history' in callback_data and callback_data['event_history']:
                        if not data['event_history']:
                            data['event_history'] = callback_data['event_history']
                        else:
                            # Merge events based on ID
                            existing_ids = {item['id'] for item in data['event_history']}
                            for item in callback_data['event_history']:
                                if 'id' in item and item['id'] not in existing_ids:
                                    data['event_history'].append(item)
            except Exception as e:
                logger.error(f"Error getting data from callback: {e}")
        
        # Update internal state
        self.stream_ids = data['stream_ids']
        self.current_stream_id = data['current_stream_id']
        if stream_id == self.current_stream_id or not stream_id:
            self.stream_stats = data['stream_stats']
            self.packet_loss_history = data['packet_loss_history']
            self.event_history = data['event_history']
        
        return data
    
    def create_app(self):
        """Create the Dash app for visualization."""
        app = dash.Dash(__name__, 
                       external_stylesheets=[dbc.themes.BOOTSTRAP],
                       suppress_callback_exceptions=True)
        
        # Define the layout
        app.layout = html.Div([
            dbc.NavbarSimple(
                children=[
                    dbc.NavItem(dbc.NavLink("Dashboard", href="#")),
                    dbc.DropdownMenu(
                        id='stream-dropdown',
                        children=[
                            dbc.DropdownMenuItem("Loading streams...", id="loading-streams")
                        ],
                        nav=True,
                        in_navbar=True,
                        label="Select Stream",
                    ),
                ],
                brand="TCP Packet Recovery Dashboard",
                brand_href="#",
                color="primary",
                dark=True,
            ),
            dbc.Container([
                html.Div(id='hidden-div', style={'display': 'none'}),
                dcc.Interval(
                    id='interval-component',
                    interval=int(self.update_interval * 1000),  # in milliseconds
                    n_intervals=0
                ),
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("Stream Statistics"),
                            dbc.CardBody([
                                html.Div(id='stream-stats')
                            ])
                        ], className="mb-4"),
                    ], width=12),
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("Packet Loss Over Time"),
                            dbc.CardBody([
                                dcc.Graph(id='packet-loss-graph')
                            ])
                        ], className="mb-4"),
                    ], width=6),
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("Recovery Rate"),
                            dbc.CardBody([
                                dcc.Graph(id='recovery-rate-graph')
                            ])
                        ], className="mb-4"),
                    ], width=6),
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader("Recent Events"),
                            dbc.CardBody([
                                html.Div(id='event-table')
                            ])
                        ], className="mb-4"),
                    ], width=12),
                ]),
            ], fluid=True),
        ])
        
        # Define callbacks
        @app.callback(
            [Output('stream-dropdown', 'children'),
             Output('stream-stats', 'children'),
             Output('packet-loss-graph', 'figure'),
             Output('recovery-rate-graph', 'figure'),
             Output('event-table', 'children')],
            [Input('interval-component', 'n_intervals'),
             Input('stream-dropdown', 'value')]
        )
        def update_visualizations(n_intervals, stream_id):
            # Get the stream ID from callback context if available
            ctx = callback_context
            if ctx.triggered:
                input_id = ctx.triggered[0]['prop_id'].split('.')[0]
                if input_id == 'stream-dropdown':
                    self.current_stream_id = stream_id
            
            # Get the data
            data = self.get_stream_data(stream_id=self.current_stream_id)
            
            # Update the stream dropdown
            dropdown_items = []
            for sid in data['stream_ids']:
                dropdown_items.append(dbc.DropdownMenuItem(sid, id=f"stream-{sid}"))
            
            # Create a table for stream statistics
            stats = data['stream_stats']
            if stats:
                stats_table = html.Table([
                    html.Tr([html.Th('Metric'), html.Th('Value')]),
                    html.Tr([html.Td('Stream ID'), html.Td(stats.get('stream_id', 'N/A'))]),
                    html.Tr([html.Td('Total Packets'), html.Td(str(stats.get('total_packets', 0)))]),
                    html.Tr([html.Td('Missing Packets'), html.Td(str(stats.get('missing_packets', 0)))]),
                    html.Tr([html.Td('Injected Packets'), html.Td(str(stats.get('injected_packets', 0)))]),
                    html.Tr([html.Td('Packet Loss Rate'), html.Td(f"{stats.get('packet_loss_rate', 0) * 100:.2f}%")]),
                    html.Tr([html.Td('Avg Payload Size'), html.Td(f"{stats.get('average_payload_size', 0):.2f} bytes")]),
                ], className='table table-striped')
            else:
                stats_table = html.Div("No statistics available for this stream")
            
            # Create packet loss graph
            history = data['packet_loss_history']
            if history:
                df = pd.DataFrame(history)
                fig_loss = px.line(
                    df, 
                    x='interval', 
                    y='avg_loss_rate',
                    title='Packet Loss Rate Over Time',
                    labels={'interval': 'Time', 'avg_loss_rate': 'Loss Rate'}
                )
                fig_loss.update_layout(
                    xaxis_title='Time',
                    yaxis_title='Loss Rate',
                    yaxis=dict(tickformat='.2%')
                )
            else:
                fig_loss = go.Figure()
                fig_loss.update_layout(
                    title='Packet Loss Rate Over Time',
                    xaxis_title='Time',
                    yaxis_title='Loss Rate'
                )
            
            # Create recovery rate graph
            if history:
                df = pd.DataFrame(history)
                df['recovery_rate'] = df['total_injected'] / df['total_missing'].replace(0, 1)
                fig_recovery = px.line(
                    df, 
                    x='interval', 
                    y='recovery_rate',
                    title='Packet Recovery Rate Over Time',
                    labels={'interval': 'Time', 'recovery_rate': 'Recovery Rate'}
                )
                fig_recovery.update_layout(
                    xaxis_title='Time',
                    yaxis_title='Recovery Rate',
                    yaxis=dict(tickformat='.2%')
                )
            else:
                fig_recovery = go.Figure()
                fig_recovery.update_layout(
                    title='Packet Recovery Rate Over Time',
                    xaxis_title='Time',
                    yaxis_title='Recovery Rate'
                )
            
            # Create event table
            events = data['event_history']
            if events:
                # Create a DataFrame for easier manipulation
                df = pd.DataFrame(events)
                df = df.sort_values('timestamp', ascending=False).head(10)
                
                # Format the table
                event_table = html.Table([
                    html.Thead(
                        html.Tr([
                            html.Th('Time'),
                            html.Th('Event Type'),
                            html.Th('Sequence'),
                            html.Th('Details')
                        ])
                    ),
                    html.Tbody([
                        html.Tr([
                            html.Td(event['timestamp']),
                            html.Td(event['event_type']),
                            html.Td(str(event['sequence_number'])),
                            html.Td(f"{event['source_ip']}:{event['source_port']} -> "
                                   f"{event['destination_ip']}:{event['destination_port']}")
                        ]) for _, event in df.iterrows()
                    ])
                ], className='table table-striped')
            else:
                event_table = html.Div("No events available for this stream")
            
            return dropdown_items, stats_table, fig_loss, fig_recovery, event_table
        
        self.app = app
        return app
    
    def _run_server(self):
        """Run the Dash server in a separate thread."""
        if not self.app:
            self.create_app()
        
        self.app.run_server(
            host=self.host,
            port=self.port,
            debug=self.debug,
            use_reloader=False
        )
    
    def start_visualization(self):
        """Start the visualization server."""
        if self.running:
            return
        
        if not self.app:
            self.create_app()
        
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        logger.info(f"Started visualization server at http://{self.host}:{self.port}")
    
    def stop_visualization(self):
        """Stop the visualization server."""
        self.running = False
        # Note: There's no clean way to stop a Dash server in a thread
        # The thread will be terminated when the main process exits
        logger.info("Stopping visualization server")
