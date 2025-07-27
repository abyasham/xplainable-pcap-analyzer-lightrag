"""
Neo4j HTML Visualizer for Interactive Security Graph Visualization
Replaces Plotly with HTML-based interactive graphs using D3.js and Vis.js
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from neo4j import GraphDatabase
import networkx as nx
from dataclasses import asdict
from .simple_html_template import SIMPLE_HTML_TEMPLATE

logger = logging.getLogger(__name__)

class Neo4jHTMLVisualizer:
    """
    HTML-based visualization engine for Neo4j security graphs
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.neo4j_driver = None
        self.visualization_templates = self._load_visualization_templates()
        
        # Initialize Neo4j connection
        self._initialize_neo4j_connection()
    
    def _initialize_neo4j_connection(self):
        """Initialize Neo4j database connection"""
        neo4j_config = self.config.get('neo4j', {})
        
        try:
            uri = neo4j_config.get('uri', 'bolt://localhost:7687')
            username = neo4j_config.get('username', 'neo4j')
            password = neo4j_config.get('password', 'password')
            
            logger.info(f"Connecting to Neo4j at {uri} with user {username}")
            
            # For neo4j+s:// URI, encryption is built-in, no need for extra params
            if uri.startswith('neo4j+s://') or uri.startswith('bolt+s://'):
                self.neo4j_driver = GraphDatabase.driver(uri, auth=(username, password))
            else:
                # For regular bolt:// connections, use encryption settings
                self.neo4j_driver = GraphDatabase.driver(
                    uri,
                    auth=(username, password),
                    encrypted=True,
                    trust='TRUST_ALL_CERTIFICATES'
                )
            
            # Test connection
            with self.neo4j_driver.session() as session:
                result = session.run("RETURN 1 as test")
                result.single()
                
            logger.info("Neo4j HTML Visualizer connection established")
            
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self.neo4j_driver = None
    
    def _load_visualization_templates(self) -> Dict[str, str]:
        """Load HTML visualization templates"""
        
        return {
            'base_template': SIMPLE_HTML_TEMPLATE,
            'threat_alert_template': '''
<div class="alert alert-{severity_class}">
    <strong>{severity}:</strong> {description}
</div>
            '''
        }
    
    def create_interactive_security_graph(self, network_entities: Dict[str, Any]) -> str:
        """Create interactive HTML security graph visualization"""
        
        logger.info("Creating interactive HTML security graph...")
        
        try:
            # Extract graph data from Neo4j
            graph_data = self._extract_neo4j_graph_data(network_entities)
            
            # Generate threat alerts
            threat_alerts = self._generate_threat_alerts(network_entities)
            
            # Get analysis metadata
            analysis_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            threat_count = len(network_entities.get('security_events', []))
            
            # Generate HTML
            html_content = self.visualization_templates['base_template'].format(
                analysis_time=analysis_time,
                threat_count=threat_count,
                graph_data=json.dumps(graph_data, indent=2),
                threat_alerts=threat_alerts
            )
            
            logger.info(f"Interactive HTML security graph created successfully, length: {len(html_content)}")
            logger.info(f"HTML content starts with: {html_content[:100]}...")
            return html_content
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            logger.error(f"Failed to create interactive security graph: {e}")
            logger.error(f"Full traceback: {error_details}")
            return self._create_error_visualization(f"Error: {str(e)}\n\nTraceback:\n{error_details}")
    
    def _extract_neo4j_graph_data(self, network_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Extract graph data from Neo4j or network entities"""
        
        nodes = []
        edges = []
        
        # Extract hosts
        hosts = network_entities.get('hosts', {})
        for ip, host_data in hosts.items():
            security_score = self._calculate_host_security_score(host_data)
            
            node = {
                'id': f"host_{ip}",
                'label': ip,
                'group': 'host',
                'color': self._get_host_color(security_score),
                'size': min(50, max(20, host_data.get('packet_count', 0) / 100)),
                'ip_address': ip,
                'security_score': security_score,
                'is_internal': host_data.get('is_internal', False),
                'reputation': host_data.get('reputation', 'unknown'),
                'description': f"Host {ip} - Security Score: {security_score:.1f}"
            }
            nodes.append(node)
        
        # Extract services
        services = network_entities.get('services', {})
        for service_key, service_data in services.items():
            service_id = f"service_{service_key}"
            
            node = {
                'id': service_id,
                'label': f"{service_data.get('service_name', 'Unknown')}:{service_data.get('port', 0)}",
                'group': 'service',
                'color': self._get_service_color(service_data.get('risk_level', 'MEDIUM')),
                'size': 25,
                'service_name': service_data.get('service_name', 'Unknown'),
                'port': service_data.get('port', 0),
                'risk_level': service_data.get('risk_level', 'MEDIUM'),
                'description': f"Service: {service_data.get('service_name', 'Unknown')} on port {service_data.get('port', 0)}"
            }
            nodes.append(node)
            
            # Connect service to host
            host_ip = service_data.get('host', 'unknown')
            if host_ip in hosts:
                edge = {
                    'from': f"host_{host_ip}",
                    'to': service_id,
                    'label': 'hosts',
                    'color': '#666666',
                    'width': 2
                }
                edges.append(edge)
        
        # Extract security events
        security_events = network_entities.get('security_events', [])
        for i, event in enumerate(security_events):
            event_id = f"event_{i}"
            
            node = {
                'id': event_id,
                'label': event.event_type.replace('_', ' ').title(),
                'group': 'threat',
                'color': self._get_severity_color(event.severity),
                'size': 30 + (10 if event.severity == 'CRITICAL' else 5 if event.severity == 'HIGH' else 0),
                'severity': event.severity,
                'event_type': event.event_type,
                'confidence': event.confidence_score,
                'description': event.description,
                'evidence': event.evidence,
                'shape': 'triangle'
            }
            nodes.append(node)
            
            # Connect event to source host
            if event.source_ip and event.source_ip in hosts:
                edge = {
                    'from': f"host_{event.source_ip}",
                    'to': event_id,
                    'label': 'generates',
                    'color': self._get_severity_color(event.severity),
                    'width': 3,
                    'dashes': True
                }
                edges.append(edge)
            
            # Connect event to target host
            if event.dest_ip and event.dest_ip in hosts and event.dest_ip != event.source_ip:
                edge = {
                    'from': event_id,
                    'to': f"host_{event.dest_ip}",
                    'label': 'targets',
                    'color': self._get_severity_color(event.severity),
                    'width': 3,
                    'dashes': True
                }
                edges.append(edge)
        
        # Extract connections between hosts
        connections = network_entities.get('connections', [])
        connection_counts = {}
        
        for conn in connections:
            if conn.get('connection_type') == 'ip_communication':
                source = conn.get('source_ip')
                target = conn.get('dest_ip')
                
                if source in hosts and target in hosts:
                    edge_key = f"{source}-{target}"
                    connection_counts[edge_key] = connection_counts.get(edge_key, 0) + 1
        
        # Add connection edges
        for edge_key, count in connection_counts.items():
            source, target = edge_key.split('-')
            
            edge = {
                'from': f"host_{source}",
                'to': f"host_{target}",
                'label': f"{count} connections",
                'color': '#4CAF50' if count < 100 else '#FF9800' if count < 1000 else '#F44336',
                'width': min(10, max(1, count / 100)),
                'value': count
            }
            edges.append(edge)
        
        return {
            'nodes': nodes,
            'edges': edges
        }
    
    def _generate_threat_alerts(self, network_entities: Dict[str, Any]) -> str:
        """Generate threat alert HTML"""
        
        security_events = network_entities.get('security_events', [])
        alerts_html = ""
        
        # Count events by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for event in security_events:
            severity_counts[event.severity] += 1
        
        # Generate alerts
        if severity_counts['CRITICAL'] > 0:
            alerts_html += self.visualization_templates['threat_alert_template'].format(
                severity_class='critical',
                severity='CRITICAL',
                description=f"{severity_counts['CRITICAL']} critical threats detected requiring immediate attention"
            )
        
        if severity_counts['HIGH'] > 0:
            alerts_html += self.visualization_templates['threat_alert_template'].format(
                severity_class='high',
                severity='HIGH',
                description=f"{severity_counts['HIGH']} high-severity threats identified"
            )
        
        if len(security_events) == 0:
            alerts_html += self.visualization_templates['threat_alert_template'].format(
                severity_class='success',
                severity='SECURE',
                description="No security threats detected in network traffic"
            )
        
        return alerts_html
    
    def _calculate_host_security_score(self, host_data: Dict) -> float:
        """Calculate security score for a host"""
        base_score = 100.0
        
        # Reputation factor
        reputation = host_data.get('reputation', 'unknown')
        if reputation == 'malicious':
            base_score -= 50
        elif reputation == 'suspicious':
            base_score -= 30
        
        # Activity level factor
        packet_count = host_data.get('packet_count', 0)
        if packet_count > 50000:
            base_score -= 15
        
        # Suspicious activities
        suspicious_count = len(host_data.get('suspicious_activities', []))
        base_score -= suspicious_count * 10
        
        return max(0, min(100, base_score))
    
    def _get_host_color(self, security_score: float) -> str:
        """Get color based on host security score"""
        if security_score >= 80:
            return '#4CAF50'  # Green - Secure
        elif security_score >= 60:
            return '#FF9800'  # Orange - Suspicious
        else:
            return '#F44336'  # Red - Compromised
    
    def _get_service_color(self, risk_level: str) -> str:
        """Get color based on service risk level"""
        colors = {
            'LOW': '#2196F3',    # Blue
            'MEDIUM': '#FF9800', # Orange
            'HIGH': '#F44336'    # Red
        }
        return colors.get(risk_level, '#2196F3')
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color based on severity level"""
        colors = {
            'CRITICAL': '#8B0000',  # Dark Red
            'HIGH': '#FF0000',      # Red
            'MEDIUM': '#FFA500',    # Orange
            'LOW': '#FFFF00'        # Yellow
        }
        return colors.get(severity, '#808080')
    
    def _create_error_visualization(self, error_message: str) -> str:
        """Create error visualization HTML"""
        return f'''
<!DOCTYPE html>
<html>
<head>
    <title>Visualization Error</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; }}
        .error {{ color: red; background: #ffe6e6; padding: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="error">
        <h2>Visualization Error</h2>
        <p>Failed to create security graph visualization:</p>
        <pre>{error_message}</pre>
    </div>
</body>
</html>
        '''
    
    def create_enhanced_threat_dashboard(self, network_entities: Dict[str, Any],
                                       analysis_summary: Dict[str, Any]) -> str:
        """Create enhanced threat dashboard visualization"""
        
        logger.info("Creating enhanced threat dashboard...")
        
        try:
            # For now, return the same interactive security graph
            # This could be enhanced with specific dashboard elements
            result = self.create_interactive_security_graph(network_entities)
            logger.info(f"Enhanced threat dashboard created, type: {type(result)}, length: {len(result) if isinstance(result, str) else 'N/A'}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to create enhanced threat dashboard: {e}")
            return self._create_error_visualization(str(e))
    
    def create_enhanced_attack_timeline(self, security_events: List) -> str:
        """Create enhanced attack timeline visualization"""
        
        logger.info("Creating enhanced attack timeline...")
        
        try:
            # Create a timeline-focused HTML visualization
            timeline_data = []
            for i, event in enumerate(security_events):
                timeline_data.append({
                    'id': i,
                    'timestamp': event.timestamp,
                    'event_type': event.event_type,
                    'severity': event.severity,
                    'description': event.description,
                    'source_ip': getattr(event, 'source_ip', None),
                    'dest_ip': getattr(event, 'dest_ip', None)
                })
            
            # Generate timeline HTML (simplified version)
            timeline_html = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Timeline</title>
                <script src="https://d3js.org/d3.v7.min.js"></script>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .timeline {{ background: #f5f5f5; padding: 20px; border-radius: 10px; }}
                    .event {{ margin: 10px 0; padding: 10px; border-radius: 5px; }}
                    .critical {{ background: #ffebee; border-left: 4px solid #f44336; }}
                    .high {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
                    .medium {{ background: #f3e5f5; border-left: 4px solid #9c27b0; }}
                    .low {{ background: #e8f5e8; border-left: 4px solid #4caf50; }}
                </style>
            </head>
            <body>
                <h1>🕐 Security Events Timeline</h1>
                <div class="timeline">
                    {self._generate_timeline_events(timeline_data)}
                </div>
            </body>
            </html>
            '''
            
            return timeline_html
            
        except Exception as e:
            logger.error(f"Failed to create enhanced attack timeline: {e}")
            return self._create_error_visualization(str(e))
    
    def _generate_timeline_events(self, timeline_data: List[Dict]) -> str:
        """Generate HTML for timeline events"""
        
        events_html = ""
        for event in sorted(timeline_data, key=lambda x: x['timestamp'], reverse=True):
            severity_class = event['severity'].lower()
            timestamp_str = datetime.fromtimestamp(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            
            events_html += f'''
            <div class="event {severity_class}">
                <strong>{event['event_type'].replace('_', ' ').title()}</strong> - {event['severity']}
                <br><small>{timestamp_str}</small>
                <br>{event['description']}
                {f"<br><small>Source: {event['source_ip']} → Target: {event['dest_ip']}</small>" if event['source_ip'] else ""}
            </div>
            '''
        
        return events_html
    
    def export_html_visualization(self, html_content: str, output_path: str) -> str:
        """Export HTML visualization to file"""
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML visualization exported to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to export HTML visualization: {e}")
            raise
    
    def close(self):
        """Close Neo4j connection"""
        if self.neo4j_driver:
            self.neo4j_driver.close()
            logger.info("Neo4j HTML Visualizer connection closed")