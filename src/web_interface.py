"""
Streamlit Web Interface for PCAP Security Analyzer
Provides intuitive web-based interface for security analysis and visualization
"""

import streamlit as st
import asyncio
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import os
import logging
from typing import Dict, List, Any, Optional
import zipfile
import io
from dataclasses import asdict

from pcap_processor import AdvancedPcapProcessor
from knowledge_graph import SecurityKnowledgeGraph
from visualization import SecurityVisualizationEngine

logger = logging.getLogger(__name__)

class PCAPSecurityAnalyzerApp:
    """Main Streamlit application for PCAP Security Analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.processor = None
        self.knowledge_graph = None
        self.visualizer = None
        self.analysis_results = None
        
    def run(self):
        """Run the Streamlit application"""
        st.set_page_config(
            page_title="PCAP Security Analyzer",
            page_icon="🔒",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Apply custom CSS
        self._apply_custom_css()
        
        # Initialize session state
        self._initialize_session_state()
        
        # Sidebar
        self._create_sidebar()
        
        # Main content
        if st.session_state.get('analysis_completed', False):
            self._display_analysis_results()
        else:
            self._display_upload_interface()
    
    def _apply_custom_css(self):
        """Apply custom CSS styling"""
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #1e3c72, #2a5298);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            margin-bottom: 2rem;
        }
        
        .metric-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #007bff;
            margin: 0.5rem 0;
        }
        
        .security-alert {
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }
        
        .alert-critical {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .alert-high {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }
        
        .alert-success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .stProgress > div > div > div > div {
            background-color: #007bff;
        }
        
        .knowledge-graph-container {
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            padding: 1rem;
            background: #fafafa;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def _initialize_session_state(self):
        """Initialize Streamlit session state"""
        if 'analysis_results' not in st.session_state:
            st.session_state.analysis_results = None
        if 'knowledge_graph_ready' not in st.session_state:
            st.session_state.knowledge_graph_ready = False
        if 'analysis_completed' not in st.session_state:
            st.session_state.analysis_completed = False
        if 'query_history' not in st.session_state:
            st.session_state.query_history = []
    
    def _create_sidebar(self):
        """Create application sidebar"""
        with st.sidebar:
            st.markdown("""
            <div class="main-header">
                <h2>🔒 PCAP Security Analyzer</h2>
                <p>Advanced Network Security Analysis Tool</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Analysis Status
            st.subheader("📊 Analysis Status")
            
            if st.session_state.get('analysis_completed', False):
                st.success("✅ Analysis Complete")
                
                results = st.session_state.analysis_results
                if results:
                    summary = results.get('analysis_summary', {})
                    
                    # Display key metrics
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Security Score", f"{summary.get('security_score', 0)}/100")
                        st.metric("Hosts Found", summary.get('hosts_discovered', 0))
                    with col2:
                        st.metric("Threats Detected", summary.get('security_events', {}).get('total', 0))
                        st.metric("Services Found", summary.get('services_discovered', 0))
            else:
                st.info("🔄 Ready for Analysis")
            
            # Quick Actions
            st.subheader("⚡ Quick Actions")
            
            if st.button("🆕 New Analysis", use_container_width=True):
                self._reset_analysis()
            
            if st.session_state.get('analysis_completed', False):
                if st.button("📥 Export Results", use_container_width=True):
                    self._export_analysis_results()
                
                if st.button("🔍 Advanced Query", use_container_width=True):
                    st.session_state.show_advanced_query = True
            
            # Configuration
            st.subheader("⚙️ Configuration")
            
            analysis_depth = st.selectbox(
                "Analysis Depth",
                ["Quick", "Standard", "Deep"],
                index=1
            )
            
            enable_ml_detection = st.checkbox("Enable ML Threat Detection", value=True)
            enable_behavioral_analysis = st.checkbox("Behavioral Analysis", value=True)
            
            # Store config in session state
            st.session_state.analysis_config = {
                'depth': analysis_depth.lower(),
                'ml_detection': enable_ml_detection,
                'behavioral_analysis': enable_behavioral_analysis
            }
    
    def _display_upload_interface(self):
        """Display PCAP file upload interface"""
        
        st.markdown("""
        <div class="main-header">
            <h1>🕸️ PCAP Security Analysis Platform</h1>
            <p>Upload your PCAP file for comprehensive network security analysis with AI-powered threat detection and interactive knowledge graphs.</p>
        </div>
        """, unsafe_allow_html=True)
        
        # File Upload Section
        st.subheader("📁 Upload PCAP File")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader(
                "Choose a PCAP/PCAPNG file",
                type=['pcap', 'pcapng'],
                help="Upload network traffic capture files for security analysis"
            )
            
            if uploaded_file:
                # Display file info
                file_size = len(uploaded_file.getvalue())
                st.info(f"📄 **File:** {uploaded_file.name} ({self._format_file_size(file_size)})")
                
                # Analysis options
                with st.expander("🔧 Analysis Options", expanded=True):
                    col_opt1, col_opt2 = st.columns(2)
                    
                    with col_opt1:
                        max_packets = st.number_input(
                            "Max Packets to Analyze",
                            min_value=100,
                            max_value=100000,
                            value=10000,
                            step=1000
                        )
                        
                        enable_payload_analysis = st.checkbox(
                            "Deep Payload Inspection",
                            value=True
                        )
                    
                    with col_opt2:
                        enable_ml_scoring = st.checkbox(
                            "ML Threat Scoring",
                            value=True
                        )
                        
                        create_knowledge_graph = st.checkbox(
                            "Build Knowledge Graph",
                            value=True
                        )
                
                # Start Analysis Button
                if st.button("🚀 Start Security Analysis", type="primary", use_container_width=True):
                    self._start_analysis(uploaded_file, {
                        'max_packets': max_packets,
                        'payload_analysis': enable_payload_analysis,
                        'ml_scoring': enable_ml_scoring,
                        'knowledge_graph': create_knowledge_graph
                    })
        
        with col2:
            st.markdown("""
            ### 🛡️ Analysis Features
            
            ✅ **Advanced Threat Detection**
            - SQL Injection & XSS Detection
            - Port Scanning & Brute Force
            - DNS Tunneling & Data Exfiltration
            - Malware Communication Patterns
            
            ✅ **AI-Powered Analysis**
            - LLM-based Security Assessment
            - Behavioral Pattern Recognition
            - Automated Risk Scoring
            
            ✅ **Interactive Knowledge Graph**
            - Query Network Relationships
            - Visual Threat Correlations
            - Natural Language Queries
            
            ✅ **Comprehensive Reporting**
            - Executive Security Summary
            - Technical Threat Details
            - Remediation Recommendations
            """)
        
        # Example Files Section
        st.subheader("📚 Example Analysis")
        
        col_ex1, col_ex2, col_ex3 = st.columns(3)
        
        with col_ex1:
            if st.button("🌐 Web Attack Sample", use_container_width=True):
                st.info("This would demonstrate analysis of web-based attacks including SQL injection and XSS attempts.")
        
        with col_ex2:
            if st.button("🕵️ Lateral Movement", use_container_width=True):
                st.info("This would show detection of lateral movement and privilege escalation attempts.")
        
        with col_ex3:
            if st.button("📡 DNS Tunneling", use_container_width=True):
                st.info("This would demonstrate detection of DNS tunneling and data exfiltration.")
    
    def _start_analysis(self, uploaded_file, options):
        """Start the PCAP analysis process"""
        
        # Save uploaded file
        temp_file_path = f"/tmp/{uploaded_file.name}"
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        
        # Create progress indicator
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            # Initialize components
            status_text.text("🔧 Initializing analysis components...")
            progress_bar.progress(10)
            
            self.processor = AdvancedPcapProcessor(self.config)
            self.visualizer = SecurityVisualizationEngine(self.config)
            
            if options.get('knowledge_graph', True):
                self.knowledge_graph = SecurityKnowledgeGraph(self.config)
                asyncio.run(self.knowledge_graph.initialize())
            
            # Process PCAP
            status_text.text("📡 Processing network traffic...")
            progress_bar.progress(30)
            
            analysis_results = asyncio.run(self.processor.process_pcap_file(temp_file_path))
            
            # Build knowledge graph
            if self.knowledge_graph and options.get('knowledge_graph', True):
                status_text.text("🕸️ Building knowledge graph...")
                progress_bar.progress(60)
                
                kg_success = asyncio.run(
                    self.knowledge_graph.build_knowledge_graph(
                        analysis_results['network_entities']
                    )
                )
                
                if kg_success:
                    st.session_state.knowledge_graph_ready = True
            
            # Create visualizations
            status_text.text("📊 Generating visualizations...")
            progress_bar.progress(80)
            
            network_viz = self.visualizer.create_interactive_network_graph(
                analysis_results['network_entities']
            )
            
            security_dashboard = self.visualizer.create_security_dashboard(
                analysis_results['network_entities'],
                analysis_results['analysis_summary']
            )
            
            # Complete analysis
            progress_bar.progress(100)
            status_text.text("✅ Analysis complete!")
            
            # Store results
            st.session_state.analysis_results = {
                **analysis_results,
                'network_visualization': network_viz,
                'security_dashboard': security_dashboard,
                'file_info': {
                    'name': uploaded_file.name,
                    'size': len(uploaded_file.getvalue()),
                    'analysis_time': datetime.now().isoformat()
                }
            }
            
            st.session_state.analysis_completed = True
            
            # Clean up
            os.remove(temp_file_path)
            
            # Refresh the page to show results
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            logger.error(f"Analysis failed: {e}")
            
            # Clean up
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    
    def _display_analysis_results(self):
        """Display comprehensive analysis results"""
        
        results = st.session_state.analysis_results
        if not results:
            st.error("No analysis results available")
            return
        
        # Header with key metrics
        file_info = results.get('file_info', {})
        summary = results.get('analysis_summary', {})
        
        st.markdown(f"""
        <div class="main-header">
            <h1>🔍 Security Analysis Results</h1>
            <p><strong>File:</strong> {file_info.get('name', 'Unknown')} | 
            <strong>Analyzed:</strong> {datetime.fromisoformat(file_info.get('analysis_time', '')).strftime('%Y-%m-%d %H:%M:%S') if file_info.get('analysis_time') else 'Unknown'}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Key Metrics Dashboard
        self._display_key_metrics(summary)
        
        # Tabs for different views
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🛡️ Security Overview",
            "🕸️ Knowledge Graph",
            "📊 Network Analysis", 
            "⚠️ Threat Details",
            "📋 Executive Report"
        ])
        
        with tab1:
            self._display_security_overview(results)
        
        with tab2:
            self._display_knowledge_graph_interface(results)
        
        with tab3:
            self._display_network_analysis(results)
        
        with tab4:
            self._display_threat_details(results)
        
        with tab5:
            self._display_executive_report(results)
    
    def _display_key_metrics(self, summary: Dict):
        """Display key security metrics"""
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        security_score = summary.get('security_score', 0)
        risk_level = summary.get('risk_level', 'UNKNOWN')
        
        with col1:
            # Security Score with color coding
            score_color = "normal" if security_score >= 80 else "inverse" if security_score >= 60 else "off"
            st.metric(
                "Security Score",
                f"{security_score}/100",
                delta=f"{risk_level} Risk",
                delta_color=score_color
            )
        
        with col2:
            threat_count = summary.get('security_events', {}).get('total', 0)
            st.metric(
                "Threats Detected",
                threat_count,
                delta="Active" if threat_count > 0 else "None",
                delta_color="inverse" if threat_count > 0 else "normal"
            )
        
        with col3:
            st.metric(
                "Hosts Analyzed",
                summary.get('hosts_discovered', 0),
                delta=f"{summary.get('internal_hosts', 0)} Internal"
            )
        
        with col4:
            st.metric(
                "Network Services",
                summary.get('services_discovered', 0),
                delta="Active"
            )
        
        with col5:
            total_packets = summary.get('total_packets', 0)
            st.metric(
                "Traffic Volume",
                self._format_number(total_packets),
                delta="Packets"
            )
    
    def _display_security_overview(self, results: Dict):
        """Display security overview with visualizations"""
        
        summary = results.get('analysis_summary', {})
        security_events = results.get('network_entities', {}).get('security_events', [])
        
        # Security Status Alert
        security_score = summary.get('security_score', 0)
        threat_count = summary.get('security_events', {}).get('total', 0)
        
        if threat_count == 0:
            st.markdown("""
            <div class="security-alert alert-success">
                <h3>✅ Network Security Status: SECURE</h3>
                <p>No security threats detected during the analysis period. The network demonstrates normal operational patterns without identified malicious activities.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            if threat_count >= 10 or security_score < 50:
                alert_class = "alert-critical"
                status = "CRITICAL THREATS DETECTED"
                icon = "🚨"
            else:
                alert_class = "alert-high"
                status = "SECURITY ISSUES FOUND"
                icon = "⚠️"
            
            st.markdown(f"""
            <div class="security-alert {alert_class}">
                <h3>{icon} Network Security Status: {status}</h3>
                <p>{threat_count} security events detected requiring immediate attention and investigation.</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Security Dashboard
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Display security dashboard
            security_dashboard = results.get('security_dashboard')
            if security_dashboard:
                st.plotly_chart(security_dashboard, use_container_width=True)
        
        with col2:
            # Top threats summary
            st.subheader("🎯 Top Threats")
            
            top_threats = summary.get('top_threats', [])
            if top_threats:
                for i, threat in enumerate(top_threats[:5], 1):
                    threat_type = threat['threat_type'].replace('_', ' ').title()
                    count = threat['count']
                    
                    st.markdown(f"""
                    <div class="metric-card">
                        <strong>{i}. {threat_type}</strong><br>
                        <span style="color: #666;">Incidents: {count}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("No specific threats identified")
            
            # Recommendations
            st.subheader("💡 Recommendations")
            
            recommendations = summary.get('recommendations', [])
            for rec in recommendations[:3]:
                st.markdown(f"• {rec}")
        
        # Timeline visualization
        if security_events:
            st.subheader("📈 Threat Timeline")
            timeline_fig = self.visualizer.create_attack_timeline(security_events)
            st.plotly_chart(timeline_fig, use_container_width=True)
    
    def _display_knowledge_graph_interface(self, results: Dict):
        """Display interactive knowledge graph interface"""
        
        st.markdown("""
        <div class="knowledge-graph-container">
            <h2>🕸️ Interactive Security Knowledge Graph</h2>
            <p>Query the knowledge graph using natural language to explore network relationships and security insights.</p>
        </div>
        """, unsafe_allow_html=True)
        
        if not st.session_state.get('knowledge_graph_ready', False):
            st.warning("⚠️ Knowledge graph is not available. Please re-run analysis with knowledge graph enabled.")
            return
        
        # Query Interface
        col1, col2 = st.columns([3, 1])
        
        with col1:
            # Predefined queries
            predefined_queries = [
                "What hosts are in the network and what are their security risks?",
                "What security threats were detected and what is their impact?",
                "Which network services are running and are they vulnerable?",
                "Are there any indicators of compromise or malicious activities?",
                "What are the communication patterns between internal and external hosts?",
                "Identify any suspicious network behaviors or anomalies",
                "What attack vectors were used and how can they be mitigated?",
                "Provide a comprehensive security assessment of the network",
                "Are there any signs of lateral movement or privilege escalation?",
                "What data exfiltration attempts were detected?"
            ]
            
            query_input = st.selectbox(
                "Select a predefined query or enter custom query below:",
                [""] + predefined_queries,
                index=0
            )
            
            custom_query = st.text_area(
                "Custom Security Query:",
                value=query_input,
                height=60,
                placeholder="Ask about network security, threats, vulnerabilities, or any aspect of the analysis..."
            )
        
        with col2:
            query_mode = st.selectbox(
                "Query Mode:",
                ["hybrid", "global", "local", "naive"],
                index=0,
                help="Hybrid: Best overall results, Global: Broad context, Local: Specific details, Naive: Simple search"
            )
            
            if st.button("🔍 Query Knowledge Graph", type="primary", use_container_width=True):
                if custom_query.strip():
                    self._execute_knowledge_graph_query(custom_query, query_mode)
                else:
                    st.error("Please enter a query")
        
        # Query History
        if st.session_state.query_history:
            with st.expander("📚 Query History"):
                for i, query_record in enumerate(reversed(st.session_state.query_history[-5:]), 1):
                    st.markdown(f"**{i}.** {query_record['query']}")
                    with st.container():
                        st.markdown(f"*Response:* {query_record['response'][:200]}...")
                        st.caption(f"Timestamp: {query_record['timestamp']}")
        
        # Network Graph Visualization
        network_viz = results.get('network_visualization')
        if network_viz and 'cytoscape_elements' in network_viz:
            st.subheader("🌐 Interactive Network Graph")
            
            # Display cytoscape graph (placeholder - would need dash-cytoscape integration)
            st.info("Interactive Cytoscape network graph would be displayed here with clickable nodes and edges")
            
            # Alternative: Display Plotly network graph
            plotly_fig = network_viz.get('plotly_figure')
            if plotly_fig:
                st.plotly_chart(plotly_fig, use_container_width=True)
    
    def _execute_knowledge_graph_query(self, query: str, mode: str):
        """Execute knowledge graph query and display results"""
        
        if not self.knowledge_graph:
            st.error("Knowledge graph not available")
            return
        
        try:
            with st.spinner("🧠 Processing query with AI knowledge graph..."):
                # Execute query
                query_result = asyncio.run(
                    self.knowledge_graph.query_security_knowledge(query, mode)
                )
                
                # Display results
                if query_result.get('lightrag_response'):
                    response = query_result['lightrag_response']
                    confidence = query_result.get('confidence_score', 0)
                    
                    # Success message
                    st.success("✅ Query executed successfully")
                    
                    # Response with confidence indicator
                    col_resp1, col_resp2 = st.columns([4, 1])
                    
                    with col_resp1:
                        st.markdown("### 🤖 AI Analysis Response")
                        st.markdown(response)
                    
                    with col_resp2:
                        st.metric(
                            "Confidence Score",
                            f"{confidence:.2f}",
                            delta="High" if confidence > 0.8 else "Medium" if confidence > 0.6 else "Low"
                        )
                    
                    # Structured data if available
                    structured_data = query_result.get('structured_data')
                    if structured_data:
                        with st.expander("📊 Structured Data"):
                            st.json(structured_data)
                    
                    # Add to query history
                    st.session_state.query_history.append({
                        'query': query,
                        'response': response,
                        'mode': mode,
                        'confidence': confidence,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                else:
                    st.error("❌ Query failed or returned no results")
                    if 'error' in query_result:
                        st.error(f"Error: {query_result['error']}")
        
        except Exception as e:
            st.error(f"❌ Query execution failed: {str(e)}")
            logger.error(f"Knowledge graph query failed: {e}")
    
    def _display_network_analysis(self, results: Dict):
        """Display detailed network analysis"""
        
        network_entities = results.get('network_entities', {})
        hosts = network_entities.get('hosts', {})
        services = network_entities.get('services', {})
        
        # Network topology overview
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Network graph
            network_viz = results.get('network_visualization')
            if network_viz and 'plotly_figure' in network_viz:
                st.subheader("🌐 Network Topology")
                st.plotly_chart(network_viz['plotly_figure'], use_container_width=True)
        
        with col2:
            # Network statistics
            st.subheader("📊 Network Statistics")
            
            internal_hosts = len([h for h in hosts.values() if h.get('is_internal')])
            external_hosts = len(hosts) - internal_hosts
            
            st.metric("Total Hosts", len(hosts))
            st.metric("Internal Hosts", internal_hosts)
            st.metric("External Hosts", external_hosts)
            st.metric("Active Services", len(services))
        
        # Detailed host analysis
        st.subheader("🖥️ Host Analysis")
        
        if hosts:
            host_data = []
            for ip, host_info in hosts.items():
                host_data.append({
                    'IP Address': ip,
                    'Type': 'Internal' if host_info.get('is_internal') else 'External',
                    'Packets': host_info.get('packet_count', 0),
                    'Reputation': host_info.get('reputation', 'Unknown'),
                    'Protocols': ', '.join(list(host_info.get('protocols', set()))[:3]),
                    'Risk Level': self._assess_display_risk(host_info)
                })
            
            df_hosts = pd.DataFrame(host_data)
            
            # Add filters
            col_filter1, col_filter2, col_filter3 = st.columns(3)
            
            with col_filter1:
                type_filter = st.selectbox("Filter by Type", ["All", "Internal", "External"])
            
            with col_filter2:
                risk_filter = st.selectbox("Filter by Risk", ["All", "High", "Medium", "Low"])
            
            with col_filter3:
                min_packets = st.number_input("Min Packets", min_value=0, value=0)
            
            # Apply filters
            filtered_df = df_hosts.copy()
            if type_filter != "All":
                filtered_df = filtered_df[filtered_df['Type'] == type_filter]
            if risk_filter != "All":
                filtered_df = filtered_df[filtered_df['Risk Level'] == risk_filter]
            if min_packets > 0:
                filtered_df = filtered_df[filtered_df['Packets'] >= min_packets]
            
            st.dataframe(filtered_df, use_container_width=True)
        
        # Service analysis
        st.subheader("⚙️ Service Analysis")
        
        if services:
            service_data = []
            for service_key, service_info in services.items():
                service_data.append({
                    'Service': service_info.get('service_name', 'Unknown'),
                    'Host': service_info.get('host', 'Unknown'),
                    'Port': service_info.get('port', 0),
                    'Protocol': service_info.get('protocol', 'Unknown'),
                    'Clients': len(service_info.get('clients', [])),
                    'Risk Level': service_info.get('risk_level', 'Medium')
                })
            
            df_services = pd.DataFrame(service_data)
            st.dataframe(df_services, use_container_width=True)
    
    def _display_threat_details(self, results: Dict):
        """Display detailed threat analysis"""
        
        security_events = results.get('network_entities', {}).get('security_events', [])
        
        if not security_events:
            st.success("🎉 No security threats detected in the analyzed traffic!")
            st.info("The network appears to be operating normally without any identified security issues.")
            return
        
        st.subheader(f"⚠️ {len(security_events)} Security Events Detected")
        
        # Event severity distribution
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for event in security_events:
            severity_counts[event.severity] += 1
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Critical", severity_counts['CRITICAL'], delta_color="inverse")
        with col2:
            st.metric("High", severity_counts['HIGH'], delta_color="inverse")
        with col3:
            st.metric("Medium", severity_counts['MEDIUM'], delta_color="inverse") 
        with col4:
            st.metric("Low", severity_counts['LOW'])
        
        # Detailed event list
        st.subheader("📋 Event Details")
        
        # Event filters
        col_f1, col_f2, col_f3 = st.columns(3)
        
        with col_f1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )
        
        with col_f2:
            event_types = list(set([e.event_type for e in security_events]))
            type_filter = st.selectbox("Filter by Type", ["All"] + event_types)
        
        with col_f3:
            limit_events = st.number_input("Max Events to Display", min_value=1, max_value=100, value=20)
        
        # Filter events
        filtered_events = security_events
        if severity_filter != "All":
            filtered_events = [e for e in filtered_events if e.severity == severity_filter]
        if type_filter != "All":
            filtered_events = [e for e in filtered_events if e.event_type == type_filter]
        
        # Sort by severity and timestamp
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        filtered_events.sort(key=lambda x: (severity_order[x.severity], -x.timestamp))
        
        # Display events
        for i, event in enumerate(filtered_events[:limit_events], 1):
            with st.expander(f"🚨 {event.event_type.replace('_', ' ').title()} - {event.severity}"):
                col_event1, col_event2 = st.columns([2, 1])
                
                with col_event1:
                    st.markdown(f"**Description:** {event.description}")
                    st.markdown(f"**Event ID:** `{event.event_id}`")
                    st.markdown(f"**Timestamp:** {datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if event.source_ip:
                        st.markdown(f"**Source:** {event.source_ip}" + (f":{event.source_port}" if event.source_port else ""))
                    if event.dest_ip:
                        st.markdown(f"**Target:** {event.dest_ip}" + (f":{event.dest_port}" if event.dest_port else ""))
                    
                    st.markdown(f"**Protocol:** {event.protocol}")
                    
                    # Evidence details
                    if event.evidence:
                        with st.expander("🔍 Evidence"):
                            st.json(event.evidence)
                
                with col_event2:
                    st.metric("Confidence Score", f"{event.confidence_score:.2f}")
                    st.markdown(f"**Attack Category:** {event.attack_category}")
                    
                    # Remediation recommendations
                    if event.remediation:
                        st.markdown("**Remediation:**")
                        for rec in event.remediation[:3]:
                            st.markdown(f"• {rec}")
    
    def _display_executive_report(self, results: Dict):
        """Display executive summary report"""
        
        summary = results.get('analysis_summary', {})
        file_info = results.get('file_info', {})
        
        st.markdown("""
        # 📋 Executive Security Report
        
        This report provides a high-level summary of the network security analysis findings for executive review.
        """)
        
        # Executive Summary
        st.subheader("📊 Executive Summary")
        
        security_score = summary.get('security_score', 0)
        risk_level = summary.get('risk_level', 'UNKNOWN')
        threat_count = summary.get('security_events', {}).get('total', 0)
        
        if threat_count == 0:
            summary_text = f"""
            **Security Status: ✅ SECURE**
            
            The network analysis reveals a secure environment with no identified security threats. 
            The security score of {security_score}/100 indicates good security posture with {risk_level.lower()} risk profile.
            
            **Key Findings:**
            - No malicious activities detected
            - {summary.get('hosts_discovered', 0)} hosts analyzed with normal behavior patterns
            - {summary.get('services_discovered', 0)} network services operating within security parameters
            - Network communications follow expected patterns
            """
        else:
            summary_text = f"""
            **Security Status: ⚠️ THREATS DETECTED**
            
            The network analysis has identified {threat_count} security events requiring immediate attention. 
            The security score of {security_score}/100 indicates a {risk_level.lower()} risk environment.
            
            **Critical Findings:**
            - {summary.get('security_events', {}).get('critical', 0)} critical security events
            - {summary.get('security_events', {}).get('high', 0)} high-severity incidents
            - Immediate investigation and remediation required
            - Potential business impact from identified threats
            """
        
        st.markdown(summary_text)
        
        # Risk Assessment
        st.subheader("🎯 Risk Assessment")
        
        col_risk1, col_risk2 = st.columns(2)
        
        with col_risk1:
            # Risk level gauge
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=security_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Security Score"},
                delta={'reference': 80},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 50], 'color': "red"},
                        {'range': [50, 80], 'color': "yellow"},
                        {'range': [80, 100], 'color': "green"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ))
            fig_gauge.update_layout(height=300)
            st.plotly_chart(fig_gauge, use_container_width=True)
        
        with col_risk2:
            st.markdown("### 🔍 Risk Factors")
            
            risk_factors = []
            if threat_count > 0:
                risk_factors.append(f"• {threat_count} active security threats")
            if summary.get('external_hosts', 0) > 10:
                risk_factors.append(f"• High external connectivity ({summary.get('external_hosts', 0)} hosts)")
            if security_score < 70:
                risk_factors.append("• Below-average security score")
            
            if risk_factors:
                for factor in risk_factors:
                    st.markdown(factor)
            else:
                st.success("✅ No significant risk factors identified")
        
        # Recommendations
        st.subheader("💡 Strategic Recommendations")
        
        recommendations = summary.get('recommendations', [])
        if recommendations:
            st.markdown("**Immediate Actions Required:**")
            for i, rec in enumerate(recommendations[:5], 1):
                st.markdown(f"{i}. {rec}")
        
        # Technical Details for IT Teams
        with st.expander("🔧 Technical Details for IT Teams"):
            
            col_tech1, col_tech2 = st.columns(2)
            
            with col_tech1:
                st.markdown("**Network Infrastructure:**")
                st.markdown(f"- Total packets analyzed: {summary.get('total_packets', 0):,}")
                st.markdown(f"- Hosts discovered: {summary.get('hosts_discovered', 0)}")
                st.markdown(f"- Internal hosts: {summary.get('internal_hosts', 0)}")
                st.markdown(f"- External hosts: {summary.get('external_hosts', 0)}")
                st.markdown(f"- Active services: {summary.get('services_discovered', 0)}")
            
            with col_tech2:
                st.markdown("**Analysis Parameters:**")
                st.markdown(f"- File analyzed: {file_info.get('name', 'Unknown')}")
                st.markdown(f"- File size: {self._format_file_size(file_info.get('size', 0))}")
                st.markdown(f"- Analysis time: {file_info.get('analysis_time', 'Unknown')}")
                st.markdown(f"- Protocols detected: {len(summary.get('protocols_detected', []))}")
        
        # Export options
        st.subheader("📥 Export Options")
        
        col_exp1, col_exp2, col_exp3 = st.columns(3)
        
        with col_exp1:
            if st.button("📄 Download PDF Report", use_container_width=True):
                st.info("PDF report generation would be implemented here")
        
        with col_exp2:
            if st.button("📊 Export Data (JSON)", use_container_width=True):
                self._export_json_data(results)
        
        with col_exp3:
            if st.button("📈 Export Visualizations", use_container_width=True):
                st.info("Visualization export would be implemented here")
    
    # Helper methods
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def _format_number(self, num: int) -> str:
        """Format number with appropriate suffix"""
        if num >= 1_000_000:
            return f"{num/1_000_000:.1f}M"
        elif num >= 1_000:
            return f"{num/1_000:.1f}K"
        return str(num)
    
    def _assess_display_risk(self, host_info: Dict) -> str:
        """Assess risk level for display"""
        # Simplified risk assessment for display
        reputation = host_info.get('reputation', 'unknown')
        if reputation == 'malicious':
            return 'High'
        elif reputation == 'suspicious':
            return 'Medium'
        elif not host_info.get('is_internal', True):
            return 'Medium'
        return 'Low'
    
    def _export_json_data(self, results: Dict):
        """Export analysis results as JSON"""
        try:
            # Prepare data for export
            export_data = {
                'metadata': {
                    'export_timestamp': datetime.now().isoformat(),
                    'tool_version': '1.0.0',
                    'analysis_type': 'PCAP Security Analysis'
                },
                'file_info': results.get('file_info', {}),
                'analysis_summary': results.get('analysis_summary', {}),
                'network_entities': results.get('network_entities', {}),
                # Note: Remove non-serializable objects
            }
            
            # Convert to JSON string
            json_str = json.dumps(export_data, indent=2, default=str)
            
            # Create download
            st.download_button(
                label="📥 Download Analysis Data",
                data=json_str,
                file_name=f"pcap_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
            
        except Exception as e:
            st.error(f"Export failed: {str(e)}")
    
    def _reset_analysis(self):
        """Reset analysis state"""
        st.session_state.analysis_results = None
        st.session_state.knowledge_graph_ready = False
        st.session_state.analysis_completed = False
        st.session_state.query_history = []
        st.rerun()
    
    def _export_analysis_results(self):
        """Export comprehensive analysis results"""
        results = st.session_state.analysis_results
        if not results:
            st.error("No results to export")
            return
        
        try:
            # Create ZIP file with all results
            zip_buffer = io.BytesIO()
            
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                # Add JSON data
                json_data = json.dumps(results, indent=2, default=str)
                zip_file.writestr("analysis_data.json", json_data)
                
                # Add executive report (would be generated as text/markdown)
                report_text = self._generate_text_report(results)
                zip_file.writestr("executive_report.md", report_text)
                
                # Add query history if available
                if st.session_state.query_history:
                    query_data = json.dumps(st.session_state.query_history, indent=2, default=str)
                    zip_file.writestr("query_history.json", query_data)
            
            zip_buffer.seek(0)
            
            # Offer download
            st.download_button(
                label="📥 Download Complete Analysis Package",
                data=zip_buffer.getvalue(),
                file_name=f"pcap_security_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                mime="application/zip",
                use_container_width=True
            )
            
        except Exception as e:
            st.error(f"Export failed: {str(e)}")
    
    def _generate_text_report(self, results: Dict) -> str:
        """Generate text-based executive report"""
        summary = results.get('analysis_summary', {})
        file_info = results.get('file_info', {})
        
        report = f"""# PCAP Security Analysis Report

## Executive Summary

**File Analyzed:** {file_info.get('name', 'Unknown')}
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Security Score:** {summary.get('security_score', 0)}/100
**Risk Level:** {summary.get('risk_level', 'Unknown')}

## Key Findings

- **Hosts Discovered:** {summary.get('hosts_discovered', 0)}
- **Security Events:** {summary.get('security_events', {}).get('total', 0)}
- **Network Services:** {summary.get('services_discovered', 0)}
- **Traffic Volume:** {summary.get('total_packets', 0):,} packets

## Threat Analysis

"""
        
        security_events = summary.get('security_events', {})
        if security_events.get('total', 0) > 0:
            report += f"""
**Threats Detected:** {security_events.get('total', 0)}
- Critical: {security_events.get('critical', 0)}
- High: {security_events.get('high', 0)}
- Medium: {security_events.get('medium', 0)}
- Low: {security_events.get('low', 0)}

"""
        else:
            report += "No security threats detected.\n\n"
        
        # Add recommendations
        recommendations = summary.get('recommendations', [])
        if recommendations:
            report += "## Recommendations\n\n"
            for i, rec in enumerate(recommendations, 1):
                report += f"{i}. {rec}\n"
        
        report += f"\n---\nGenerated by PCAP Security Analyzer v1.0"
        
        return report

def main():
    """Main entry point for Streamlit application"""
    
    # Load configuration
    config = {
        'openai': {
            'api_key': os.getenv('OPENAI_API_KEY'),
            'model': 'gpt-4o-mini',
            'embedding_model': 'text-embedding-3-large'
        },
        'neo4j': {
            'uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
            'username': os.getenv('NEO4J_USERNAME', 'neo4j'),
            'password': os.getenv('NEO4J_PASSWORD', 'password')
        },
        'lightrag': {
            'working_dir': './data/lightrag_cache',
            'max_tokens': 8192
        }
    }
    
    # Initialize and run app
    app = PCAPSecurityAnalyzerApp(config)
    app.run()

if __name__ == "__main__":
    main()