"""
Advanced Visualization Components for PCAP Security Analysis
Provides interactive network graphs, security dashboards, and threat visualizations
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
import json
from datetime import datetime, timedelta
import logging
from dataclasses import asdict
import dash
from dash import dcc, html, Input, Output, State
import dash_cytoscape as cyto

logger = logging.getLogger(__name__)

class SecurityVisualizationEngine:
    """Advanced visualization engine for security analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.network_graph = None
        self.security_timeline = None
        self.threat_heatmap = None
        
    def create_interactive_network_graph(self, network_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Create interactive network topology graph with security overlay"""
        
        logger.info("Creating interactive network security graph...")
        
        hosts = network_entities.get('hosts', {})
        connections = network_entities.get('connections', [])
        security_events = network_entities.get('security_events', [])
        services = network_entities.get('services', {})
        
        # Create NetworkX graph
        G = nx.Graph()
        
        # Add host nodes with security attributes
        node_data = []
        for ip, host_info in hosts.items():
            # Calculate security score
            security_score = self._calculate_host_security_score(host_info, security_events)
            
            # Determine node color based on security status
            node_color = self._get_security_color(security_score)
            
            # Determine node size based on activity
            node_size = min(50, max(10, host_info.get('packet_count', 0) / 50))
            
            # Add to NetworkX
            G.add_node(ip, 
                      security_score=security_score,
                      is_internal=host_info.get('is_internal', False),
                      packet_count=host_info.get('packet_count', 0),
                      reputation=host_info.get('reputation', 'unknown'))
            
            # Prepare data for interactive graph
            node_data.append({
                'id': ip,
                'label': ip,
                'size': node_size,
                'color': node_color,
                'title': self._create_host_tooltip(ip, host_info, security_score),
                'security_score': security_score,
                'type': 'internal' if host_info.get('is_internal') else 'external',
                'x': None,  # Will be set by layout
                'y': None
            })
        
        # Add service nodes
        for service_key, service_info in services.items():
            service_id = f"svc_{service_key}"
            service_name = service_info.get('service_name', 'Unknown')
            host = service_info.get('host', 'unknown')
            port = service_info.get('port', 0)
            
            G.add_node(service_id, node_type='service')
            
            node_data.append({
                'id': service_id,
                'label': f"{service_name}:{port}",
                'size': 15,
                'color': '#2196F3',
                'title': f"Service: {service_name}<br>Host: {host}<br>Port: {port}",
                'type': 'service'
            })
            
            # Connect service to host
            if host in hosts:
                G.add_edge(host, service_id, edge_type='hosts_service')
        
        # Add edges for host communications
        edge_data = []
        edge_weights = {}
        
        for conn in connections:
            if conn.get('type') == 'ip_communication':
                source = conn.get('source_ip')
                target = conn.get('dest_ip')
                
                if source in hosts and target in hosts:
                    edge_key = (source, target)
                    edge_weights[edge_key] = edge_weights.get(edge_key, 0) + 1
        
        # Add weighted edges
        for (source, target), weight in edge_weights.items():
            G.add_edge(source, target, weight=weight, edge_type='communication')
            
            # Determine edge security status
            edge_security = self._assess_edge_security(source, target, security_events)
            edge_color = '#FF5722' if edge_security == 'high_risk' else '#4CAF50' if edge_security == 'secure' else '#FF9800'
            
            edge_data.append({
                'source': source,
                'target': target,
                'weight': weight,
                'color': edge_color,
                'title': f"Communications: {weight}<br>Security: {edge_security}",
                'security_status': edge_security
            })
        
        # Calculate layout
        pos = nx.spring_layout(G, k=3, iterations=50)
        
        # Update node positions
        for node in node_data:
            if node['id'] in pos:
                node['x'] = pos[node['id']][0] * 500
                node['y'] = pos[node['id']][1] * 500
        
        # Create Plotly network graph
        network_fig = self._create_plotly_network_graph(node_data, edge_data)
        
        # Create Cytoscape graph for advanced interactions
        cytoscape_elements = self._create_cytoscape_elements(node_data, edge_data)
        
        return {
            'plotly_figure': network_fig,
            'cytoscape_elements': cytoscape_elements,
            'network_statistics': self._calculate_network_statistics(G),
            'security_summary': self._create_security_summary(hosts, security_events)
        }
    
    def create_security_dashboard(self, network_entities: Dict[str, Any], 
                                analysis_summary: Dict[str, Any]) -> go.Figure:
        """Create comprehensive security dashboard"""
        
        logger.info("Creating security dashboard...")
        
        # Create subplot layout
        fig = make_subplots(
            rows=3, cols=3,
            subplot_titles=[
                'Security Events Timeline', 'Threat Distribution', 'Host Risk Assessment',
                'Protocol Security Analysis', 'Service Vulnerability Matrix', 'Attack Vector Analysis',  
                'Network Traffic Patterns', 'Compliance Status', 'Security Score Trends'
            ],
            specs=[
                [{"colspan": 2}, None, {"type": "pie"}],
                [{"type": "bar"}, {"type": "heatmap"}, {"type": "scatter"}],
                [{"type": "area"}, {"type": "indicator"}, {"type": "scatter"}]
            ]
        )
        
        security_events = network_entities.get('security_events', [])
        hosts = network_entities.get('hosts', {})
        
        # 1. Security Events Timeline
        if security_events:
            event_df = pd.DataFrame([asdict(event) for event in security_events])
            event_df['datetime'] = pd.to_datetime(event_df['timestamp'], unit='s')
            
            timeline_data = event_df.groupby([event_df['datetime'].dt.hour, 'severity']).size().reset_index()
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                severity_data = timeline_data[timeline_data['severity'] == severity]
                if not severity_data.empty:
                    fig.add_trace(
                        go.Scatter(
                            x=severity_data['datetime'],
                            y=severity_data[0],
                            mode='lines+markers',
                            name=f'{severity} Events',
                            line=dict(color=self._get_severity_color(severity))
                        ),
                        row=1, col=1
                    )
        
        # 2. Threat Distribution Pie Chart
        threat_counts = {}
        for event in security_events:
            threat_type = event.event_type
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        if threat_counts:
            fig.add_trace(
                go.Pie(
                    labels=list(threat_counts.keys()),
                    values=list(threat_counts.values()),
                    name="Threats"
                ),
                row=1, col=3
            )
        
        # 3. Host Risk Assessment Bar Chart
        host_risks = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for host_data in hosts.values():
            risk = self._assess_host_risk_level(host_data, security_events)
            host_risks[risk] += 1
        
        fig.add_trace(
            go.Bar(
                x=list(host_risks.keys()),
                y=list(host_risks.values()),
                marker_color=['#F44336', '#FF9800', '#4CAF50'],
                name="Host Risk Levels"
            ),
            row=2, col=1
        )
        
        # 4. Protocol Security Heatmap
        protocol_security = self._analyze_protocol_security(network_entities)
        
        fig.add_trace(
            go.Heatmap(
                z=list(protocol_security.values()),
                x=['Security Score'],
                y=list(protocol_security.keys()),
                colorscale='RdYlGn',
                name="Protocol Security"
            ),
            row=2, col=2
        )
        
        # 5. Attack Vector Scatter Plot
        attack_vectors = self._analyze_attack_vectors(security_events)
        
        if attack_vectors:
            fig.add_trace(
                go.Scatter(
                    x=[av['frequency'] for av in attack_vectors],
                    y=[av['severity_score'] for av in attack_vectors],
                    mode='markers+text',
                    text=[av['vector_type'] for av in attack_vectors],
                    marker=dict(size=[av['impact'] * 10 for av in attack_vectors]),
                    name="Attack Vectors"
                ),
                row=2, col=3
            )
        
        # 6. Network Traffic Patterns Area Chart
        traffic_patterns = self._analyze_traffic_patterns(network_entities)
        
        fig.add_trace(
            go.Scatter(
                x=list(range(len(traffic_patterns))),
                y=traffic_patterns,
                fill='tozeroy',
                name="Traffic Volume"
            ),
            row=3, col=1
        )
        
        # 7. Security Score Indicator
        overall_security_score = analysis_summary.get('security_score', 0)
        
        fig.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=overall_security_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Security Score"},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 50], 'color': "lightgray"},
                        {'range': [50, 80], 'color': "gray"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ),
            row=3, col=2
        )
        
        # Update layout
        fig.update_layout(
            height=1000,
            title_text="Security Analysis Dashboard",
            showlegend=True,
            template="plotly_dark"
        )
        
        return fig
    
    def create_threat_heatmap(self, security_events: List[Any]) -> go.Figure:
        """Create threat intensity heatmap"""
        
        logger.info("Creating threat heatmap...")
        
        # Create time-based heatmap data
        if not security_events:
            return go.Figure().add_annotation(
                text="No security events detected",
                x=0.5, y=0.5,
                showarrow=False
            )
        
        # Convert events to DataFrame
        event_df = pd.DataFrame([asdict(event) for event in security_events])
        event_df['datetime'] = pd.to_datetime(event_df['timestamp'], unit='s')
        event_df['hour'] = event_df['datetime'].dt.hour
        event_df['day'] = event_df['datetime'].dt.day
        
        # Create pivot table for heatmap
        heatmap_data = event_df.pivot_table(
            values='confidence_score',
            index='hour',
            columns='event_type',
            aggfunc='mean',
            fill_value=0
        )
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data.values,
            x=heatmap_data.columns,
            y=heatmap_data.index,
            colorscale='Reds',
            showscale=True,
            hoverongaps=False,
            colorbar=dict(title="Threat Intensity")
        ))
        
        fig.update_layout(
            title="Threat Activity Heatmap",
            xaxis_title="Threat Types",
            yaxis_title="Hour of Day",
            template="plotly_dark"
        )
        
        return fig
    
    def create_attack_timeline(self, security_events: List[Any]) -> go.Figure:
        """Create detailed attack timeline visualization"""
        
        logger.info("Creating attack timeline...")
        
        if not security_events:
            return go.Figure().add_annotation(
                text="No attacks detected",
                x=0.5, y=0.5,
                showarrow=False
            )
        
        # Sort events by timestamp
        sorted_events = sorted(security_events, key=lambda x: x.timestamp)
        
        # Create timeline data
        timeline_data = []
        for i, event in enumerate(sorted_events):
            timeline_data.append({
                'x': datetime.fromtimestamp(event.timestamp),
                'y': i,
                'text': f"{event.event_type}: {event.description}",
                'severity': event.severity,
                'source_ip': event.source_ip or 'Unknown',
                'dest_ip': event.dest_ip or 'Unknown',
                'confidence': event.confidence_score
            })
        
        df = pd.DataFrame(timeline_data)
        
        # Create timeline figure
        fig = go.Figure()
        
        # Add traces for each severity level
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_data = df[df['severity'] == severity]
            if not severity_data.empty:
                fig.add_trace(go.Scatter(
                    x=severity_data['x'],
                    y=severity_data['y'],
                    mode='markers+lines',
                    name=severity,
                    marker=dict(
                        size=severity_data['confidence'] * 20,
                        color=self._get_severity_color(severity),
                        opacity=0.8
                    ),
                    text=severity_data['text'],
                    hovertemplate="<b>%{text}</b><br>" +
                                "Time: %{x}<br>" +
                                "Source: %{customdata[0]}<br>" +
                                "Target: %{customdata[1]}<br>" +
                                "Confidence: %{customdata[2]:.2f}<extra></extra>",
                    customdata=severity_data[['source_ip', 'dest_ip', 'confidence']].values
                ))
        
        fig.update_layout(
            title="Attack Timeline Analysis",
            xaxis_title="Time",
            yaxis_title="Event Sequence",
            template="plotly_dark",
            hovermode="closest"
        )
        
        return fig
    
    def create_cytoscape_graph(self, network_entities: Dict[str, Any]) -> List[Dict]:
        """Create Cytoscape elements for advanced graph interactions"""
        
        elements = []
        
        hosts = network_entities.get('hosts', {})
        services = network_entities.get('services', {})
        security_events = network_entities.get('security_events', [])
        
        # Create host nodes
        for ip, host_info in hosts.items():
            security_score = self._calculate_host_security_score(host_info, security_events)
            
            elements.append({
                'data': {
                    'id': ip,
                    'label': ip,
                    'type': 'host',
                    'internal': host_info.get('is_internal', False),
                    'security_score': security_score,
                    'packet_count': host_info.get('packet_count', 0),
                    'reputation': host_info.get('reputation', 'unknown')
                },
                'classes': f"host {'internal' if host_info.get('is_internal') else 'external'} {self._get_risk_class(security_score)}"
            })
        
        # Create service nodes
        for service_key, service_info in services.items():
            service_id = f"svc_{service_key}"
            
            elements.append({
                'data': {
                    'id': service_id,
                    'label': f"{service_info.get('service_name', 'Unknown')}:{service_info.get('port', 0)}",
                    'type': 'service',
                    'host': service_info.get('host', 'unknown'),
                    'port': service_info.get('port', 0),
                    'risk_level': service_info.get('risk_level', 'MEDIUM')
                },
                'classes': f"service {service_info.get('risk_level', 'medium').lower()}"
            })
        
        # Create edges for communications
        connections = network_entities.get('connections', [])
        edge_counts = {}
        
        for conn in connections:
            if conn.get('type') == 'ip_communication':
                source = conn.get('source_ip')
                target = conn.get('dest_ip')
                
                if source in hosts and target in hosts:
                    edge_key = f"{source}-{target}"
                    edge_counts[edge_key] = edge_counts.get(edge_key, 0) + 1
        
        for edge_key, count in edge_counts.items():
            source, target = edge_key.split('-')
            security_status = self._assess_edge_security(source, target, security_events)
            
            elements.append({
                'data': {
                    'id': edge_key,
                    'source': source,
                    'target': target,
                    'weight': count,
                    'security_status': security_status
                },
                'classes': f"edge {security_status.replace('_', '-')}"
            })
        
        return elements
    
    def _calculate_host_security_score(self, host_info: Dict, security_events: List) -> float:
        """Calculate security score for a host"""
        base_score = 100.0
        
        # Reputation factor
        reputation = host_info.get('reputation', 'unknown')
        if reputation == 'malicious':
            base_score -= 50
        elif reputation == 'suspicious':
            base_score -= 30
        
        # Security events factor
        host_events = [e for e in security_events if e.source_ip == host_info.get('ip_address') or e.dest_ip == host_info.get('ip_address')]
        base_score -= len(host_events) * 10
        
        # Activity level factor (very high activity can be suspicious)
        packet_count = host_info.get('packet_count', 0)
        if packet_count > 50000:
            base_score -= 15
        
        return max(0, min(100, base_score))
    
    def _get_security_color(self, security_score: float) -> str:
        """Get color based on security score"""
        if security_score >= 80:
            return '#4CAF50'  # Green - Good
        elif security_score >= 60:
            return '#FF9800'  # Orange - Warning
        elif security_score >= 40:
            return '#F44336'  # Red - Danger
        else:
            return '#9C27B0'  # Purple - Critical
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity levels"""
        colors = {
            'CRITICAL': '#8B0000',
            'HIGH': '#FF0000',
            'MEDIUM': '#FFA500',
            'LOW': '#FFFF00'
        }
        return colors.get(severity, '#808080')
    
    # Additional helper methods...
    def export_visualizations(self, output_dir: str, formats: List[str] = None) -> Dict[str, str]:
        """Export visualizations in various formats"""
        
        if formats is None:
            formats = ['html', 'png', 'svg', 'json']
        
        exported_files = {}
        
        # Export network graph
        if self.network_graph:
            for fmt in formats:
                if fmt == 'html':
                    filepath = f"{output_dir}/network_graph.html"
                    self.network_graph.write_html(filepath)
                    exported_files['network_graph_html'] = filepath
                elif fmt == 'png':
                    filepath = f"{output_dir}/network_graph.png"
                    self.network_graph.write_image(filepath)
                    exported_files['network_graph_png'] = filepath
        
        # Export security dashboard
        if self.security_timeline:
            for fmt in formats:
                if fmt == 'html':
                    filepath = f"{output_dir}/security_dashboard.html"
                    self.security_timeline.write_html(filepath)
                    exported_files['security_dashboard_html'] = filepath
        
        logger.info(f"Exported {len(exported_files)} visualization files")
        return exported_files