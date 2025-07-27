"""
PCAP Security Analyzer - Main Application Entry Point
Advanced network security analysis with AI-powered threat detection
"""

import asyncio
import logging
import os
import sys
import yaml
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import subprocess

# Import application components
from src.pcap_processor import AdvancedPcapProcessor
from src.enhanced_knowledge_graph import EnhancedSecurityKnowledgeGraph
from src.neo4j_html_visualizer import Neo4jHTMLVisualizer
from src.jina_reranker import JinaRerankerService
from src.web_interface import main as run_web_interface

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/pcap_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class PCAPSecurityAnalyzer:
    """Main PCAP Security Analyzer Application"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize the analyzer with configuration"""
        
        self.config = self._load_config(config_path)
        self.processor = None
        self.knowledge_graph = None
        self.visualizer = None
        self.jina_reranker = None
        
        # Create necessary directories
        self._setup_directories()
        
        logger.info("Enhanced PCAP Security Analyzer initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Environment variable substitution
            config = self._substitute_env_vars(config)
            
            logger.info(f"Configuration loaded from {config_path}")
            return config
            
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            return self._get_default_config()
        
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return self._get_default_config()
    
    def _substitute_env_vars(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Substitute environment variables in configuration"""
        
        def substitute_recursive(obj):
            if isinstance(obj, dict):
                return {k: substitute_recursive(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [substitute_recursive(item) for item in obj]
            elif isinstance(obj, str) and obj.startswith('${') and obj.endswith('}'):
                env_var = obj[2:-1]
                return os.getenv(env_var, obj)
            return obj
        
        return substitute_recursive(config)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        
        return {
            'openai': {
                'api_key': os.getenv('OPENAI_API_KEY'),
                'model': 'gpt-4o-mini',
                'embedding_model': 'text-embedding-3-large',
                'max_tokens': 4096
            },
            'neo4j': {
                'uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
                'username': os.getenv('NEO4J_USERNAME', 'neo4j'),
                'password': os.getenv('NEO4J_PASSWORD', 'password')
            },
            'jina': {
                'api_key': os.getenv('JINA_API_KEY'),
                'model': 'jina-reranker-v2-base-multilingual',
                'max_documents': 100,
                'enable_fallback': True
            },
            'lightrag': {
                'working_dir': './data/lightrag_cache',
                'max_tokens': 8192,
                'entity_extract_max_gleaning': 3,
                'enable_llm_cache': True,
                'enable_enhanced_extraction': True
            },
            'pcap': {
                'max_packet_size': 50000,
                'chunk_size': 1000,
                'enable_payload_analysis': True,
                'enable_enhanced_analysis': True
            },
            'security': {
                'enable_deep_packet_inspection': True,
                'enable_ml_detection': True,
                'enable_behavioral_analysis': True,
                'enable_compliance_analysis': True,
                'enable_threat_correlation': True
            },
            'visualization': {
                'enable_neo4j_graphs': True,
                'enable_interactive_html': True,
                'graph_layout': 'force-directed',
                'max_nodes': 1000
            },
            'web': {
                'host': 'localhost',
                'port': 8501,
                'title': 'Enhanced PCAP Security Analyzer'
            }
        }
    
    def _setup_directories(self):
        """Create necessary directories"""
        
        directories = [
            'data/pcaps',
            'data/lightrag_cache',
            'output/reports',
            'output/graphs',
            'output/visualizations',
            'logs'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        logger.info("Directory structure created")
    
    async def analyze_pcap(self, pcap_path: str, output_dir: str = "output") -> Dict[str, Any]:
        """Perform comprehensive PCAP analysis"""
        
        logger.info(f"Starting analysis of {pcap_path}")
        
        try:
            # Initialize components
            await self._initialize_components()
            
            # Process PCAP file
            logger.info("Processing PCAP file...")
            analysis_results = await self.processor.process_pcap_file(pcap_path)
            
            # Build enhanced knowledge graph
            if self.knowledge_graph:
                logger.info("Building comprehensive knowledge graph...")
                kg_success = await self.knowledge_graph.build_comprehensive_knowledge_graph(
                    analysis_results['network_entities'],
                    self.jina_reranker
                )
                
                if kg_success:
                    analysis_results['knowledge_graph_ready'] = True
                    logger.info("Enhanced knowledge graph built successfully")
                else:
                    logger.warning("Enhanced knowledge graph construction failed")
                    analysis_results['knowledge_graph_ready'] = False
            
            # Generate visualizations
            logger.info("Creating visualizations...")
            visualizations = self._create_visualizations(analysis_results)
            analysis_results['visualizations'] = visualizations
            
            # Export results
            export_paths = await self._export_results(analysis_results, output_dir)
            analysis_results['export_paths'] = export_paths
            
            logger.info("Analysis completed successfully")
            return analysis_results
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise
    
    async def _initialize_components(self):
        """Initialize enhanced analysis components"""
        
        # Initialize PCAP processor with enhanced capabilities
        self.processor = AdvancedPcapProcessor(self.config)
        
        # Initialize Jina reranker service (if configured)
        if self.config.get('jina', {}).get('api_key'):
            self.jina_reranker = JinaRerankerService(self.config)
            logger.info("Jina reranker service initialized")
        
        # Initialize enhanced knowledge graph (if configured)
        if self.config.get('lightrag', {}).get('working_dir'):
            self.knowledge_graph = EnhancedSecurityKnowledgeGraph(self.config)
            await self.knowledge_graph.initialize()
            logger.info("Enhanced knowledge graph initialized")
        
        # Initialize Neo4j HTML visualizer
        self.visualizer = Neo4jHTMLVisualizer(self.config)
        
        logger.info("All enhanced components initialized")
    
    def _create_visualizations(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive enhanced visualizations"""
        
        visualizations = {}
        
        network_entities = analysis_results.get('network_entities', {})
        summary = analysis_results.get('analysis_summary', {})
        
        # Interactive security graph with Neo4j integration
        security_graph = self.visualizer.create_interactive_security_graph(network_entities)
        visualizations['security_graph'] = security_graph
        
        # Enhanced threat analysis dashboard
        threat_dashboard = self.visualizer.create_enhanced_threat_dashboard(network_entities, summary)
        visualizations['threat_dashboard'] = threat_dashboard
        
        # Attack correlation network
        security_events = network_entities.get('security_events', [])
        correlation_network = self.visualizer.create_attack_correlation_network(security_events)
        visualizations['correlation_network'] = correlation_network
        
        # Compliance visualization
        compliance_data = network_entities.get('compliance_assessment', {})
        if compliance_data:
            compliance_viz = self.visualizer.create_compliance_visualization(compliance_data)
            visualizations['compliance_visualization'] = compliance_viz
        
        # Timeline with enhanced context
        enhanced_timeline = self.visualizer.create_enhanced_attack_timeline(security_events)
        visualizations['enhanced_timeline'] = enhanced_timeline
        
        logger.info("Enhanced visualizations created")
        return visualizations
    
    async def _export_results(self, analysis_results: Dict[str, Any], output_dir: str) -> Dict[str, str]:
        """Export analysis results to various formats"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        export_paths = {}
        
        # Export JSON data
        json_path = f"{output_dir}/reports/analysis_{timestamp}.json"
        with open(json_path, 'w') as f:
            import json
            json.dump(analysis_results, f, indent=2, default=str)
        export_paths['json_report'] = json_path
        
        # Export visualizations
        viz_dir = f"{output_dir}/visualizations"
        if 'visualizations' in analysis_results:
            viz_exports = self.visualizer.export_visualizations(
                viz_dir, 
                formats=['html', 'png', 'svg']
            )
            export_paths.update(viz_exports)
        
        # Generate executive report
        exec_report_path = f"{output_dir}/reports/executive_report_{timestamp}.md"
        exec_report = self._generate_executive_report(analysis_results)
        with open(exec_report_path, 'w') as f:
            f.write(exec_report)
        export_paths['executive_report'] = exec_report_path
        
        # Generate technical report
        tech_report_path = f"{output_dir}/reports/technical_report_{timestamp}.md"
        tech_report = self._generate_technical_report(analysis_results)
        with open(tech_report_path, 'w') as f:
            f.write(tech_report)
        export_paths['technical_report'] = tech_report_path
        
        logger.info(f"Results exported to {export_paths}")
        return export_paths
    
    def _generate_executive_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate executive summary report"""
        
        summary = analysis_results.get('analysis_summary', {})
        
        report = f"""# Network Security Analysis - Executive Report

**Analysis Date:** {datetime.now().strftime('%B %d, %Y')}
**Analysis Duration:** {summary.get('analysis_duration', 'Unknown')}

## Executive Summary

This report presents the findings from a comprehensive network security analysis conducted on captured network traffic. The analysis employed advanced AI-powered threat detection and network behavior analysis techniques.

## Key Findings

### Security Score: {summary.get('security_score', 0)}/100
**Risk Level:** {summary.get('risk_level', 'Unknown')}

### Network Overview
- **Total Hosts Analyzed:** {summary.get('hosts_discovered', 0)}
- **Internal Network Assets:** {summary.get('internal_hosts', 0)}
- **External Communications:** {summary.get('external_hosts', 0)}
- **Active Network Services:** {summary.get('services_discovered', 0)}
- **Traffic Volume:** {summary.get('total_packets', 0):,} packets analyzed

### Security Events
- **Total Security Events:** {summary.get('security_events', {}).get('total', 0)}
- **Critical Threats:** {summary.get('security_events', {}).get('critical', 0)}
- **High Priority:** {summary.get('security_events', {}).get('high', 0)}
- **Medium Priority:** {summary.get('security_events', {}).get('medium', 0)}

## Risk Assessment

"""
        
        # Risk assessment based on findings
        threat_count = summary.get('security_events', {}).get('total', 0)
        if threat_count == 0:
            report += """
✅ **LOW RISK** - No security threats detected. The network demonstrates secure operational patterns.

**Business Impact:** Minimal security concerns identified.
**Recommended Actions:** Maintain current security posture with routine monitoring.
"""
        elif threat_count < 5:
            report += """
⚠️ **MEDIUM RISK** - Limited security events detected requiring investigation.

**Business Impact:** Potential security exposure that should be addressed.
**Recommended Actions:** Investigate identified threats and implement recommended mitigations.
"""
        else:
            report += """
🚨 **HIGH RISK** - Multiple security threats detected requiring immediate attention.

**Business Impact:** Significant security risk that could impact business operations.
**Recommended Actions:** Immediate incident response and security hardening required.
"""
        
        # Top recommendations
        recommendations = summary.get('recommendations', [])
        if recommendations:
            report += "\n## Strategic Recommendations\n\n"
            for i, rec in enumerate(recommendations[:5], 1):
                report += f"{i}. {rec}\n"
        
        report += f"""
## Next Steps

1. **Immediate:** Review and address any critical or high-priority security events
2. **Short-term:** Implement recommended security improvements
3. **Long-term:** Establish continuous security monitoring and regular assessments

---
*This report was generated by PCAP Security Analyzer using advanced AI-powered network analysis*
"""
        
        return report
    
    def _generate_technical_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate detailed technical report"""
        
        network_entities = analysis_results.get('network_entities', {})
        summary = analysis_results.get('analysis_summary', {})
        
        report = f"""# Network Security Analysis - Technical Report

**Analysis Timestamp:** {datetime.now().isoformat()}
**Analysis Method:** Advanced PCAP Analysis with AI-powered Threat Detection

## Technical Summary

### Analysis Parameters
- **Packets Processed:** {summary.get('total_packets', 0):,}
- **Data Volume:** {summary.get('total_bytes', 0):,} bytes
- **Analysis Duration:** {summary.get('analysis_duration', 'Unknown')}
- **Protocols Detected:** {len(summary.get('protocols_detected', []))} unique protocols

### Network Infrastructure Details

#### Host Analysis
"""
        
        hosts = network_entities.get('hosts', {})
        for ip, host_data in hosts.items():
            report += f"""
**Host {ip}:**
- Type: {'Internal' if host_data.get('is_internal') else 'External'}
- Activity: {host_data.get('packet_count', 0)} packets
- Protocols: {', '.join(list(host_data.get('protocols', set())))}
- Reputation: {host_data.get('reputation', 'Unknown')}
- Geographic: {host_data.get('geographic_info', {}).get('country', 'Unknown')}
"""
        
        # Service analysis
        services = network_entities.get('services', {})
        if services:
            report += "\n#### Service Analysis\n"
            for service_key, service_data in services.items():
                service_name = service_data.get('service_name', 'Unknown')
                host = service_data.get('host', 'Unknown')
                port = service_data.get('port', 0)
                protocol = service_data.get('protocol', 'Unknown')
                
                report += f"""
**Service {service_name}:**
- Host: {host}
- Port: {port}
- Protocol: {protocol}
- Risk Level: {service_data.get('risk_level', 'Unknown')}
- Client Connections: {len(service_data.get('clients', []))}
"""
        
        # Security events details
        security_events = network_entities.get('security_events', [])
        if security_events:
            report += f"\n## Security Events Detail\n\n**Total Events:** {len(security_events)}\n"
            
            for i, event in enumerate(security_events[:10], 1):  # First 10 events
                report += f"""
### Event {i}: {event.event_type.replace('_', ' ').title()}
- **Severity:** {event.severity}
- **Timestamp:** {datetime.fromtimestamp(event.timestamp).isoformat()}
- **Source:** {event.source_ip or 'N/A'}
- **Target:** {event.dest_ip or 'N/A'}
- **Description:** {event.description}
- **Confidence:** {event.confidence_score:.2f}
- **Attack Category:** {event.attack_category}
"""
        
        # Protocol distribution
        protocols = summary.get('protocols_detected', [])
        if protocols:
            report += f"\n## Protocol Distribution\n\n"
            for protocol in protocols:
                report += f"- {protocol}\n"
        
        report += f"""
## Analysis Methodology

This analysis employed the following advanced techniques:

1. **Deep Packet Inspection:** Comprehensive analysis of packet headers and payloads
2. **AI-Powered Threat Detection:** Machine learning models for attack pattern recognition
3. **Behavioral Analysis:** Statistical analysis of network communication patterns
4. **Knowledge Graph Construction:** Relationship mapping between network entities
5. **Threat Intelligence Integration:** Cross-referencing with known threat indicators

## Tools and Technologies

- **PCAP Processing:** Python Scapy library for packet analysis
- **AI Analysis:** OpenAI GPT-4 for natural language threat assessment
- **Knowledge Graph:** LightRAG with Neo4j backend for relationship mapping
- **Visualization:** Plotly and Cytoscape for interactive network graphs

---
*Generated by PCAP Security Analyzer v1.0*
"""
        
        return report
    
    async def query_knowledge_graph(self, query: str, mode: str = "hybrid") -> Dict[str, Any]:
        """Query the enhanced knowledge graph with Jina reranking"""
        
        if not self.knowledge_graph:
            return {'error': 'Enhanced knowledge graph not initialized'}
        
        try:
            # Use enhanced query with Jina reranking if available
            result = await self.knowledge_graph.query_enhanced_security_knowledge(
                query, mode, self.jina_reranker
            )
            return result
            
        except Exception as e:
            logger.error(f"Enhanced knowledge graph query failed: {e}")
            return {'error': str(e)}
    
    def run_web_interface(self, host: str = None, port: int = None):
        """Run the web interface"""
        
        web_config = self.config.get('web', {})
        
        host = host or web_config.get('host', 'localhost')
        port = port or web_config.get('port', 8501)
        
        logger.info(f"Starting web interface at http://{host}:{port}")
        
        # Set environment variables for the web interface
        os.environ['PCAP_ANALYZER_CONFIG'] = str(self.config)
        
        # Run Streamlit
        subprocess.run([
            "streamlit", "run", "src/web_interface.py",
            "--server.address", host,
            "--server.port", str(port),
            "--browser.gatherUsageStats", "false"
        ])

def setup_environment():
    """Setup the environment and check dependencies"""
    
    # Check Python version
    if sys.version_info < (3, 8):
        logger.error("Python 3.8 or higher is required")
        sys.exit(1)
    
    # Check required environment variables
    required_env_vars = ['OPENAI_API_KEY']
    optional_env_vars = ['NEO4J_PASSWORD', 'JINA_API_KEY', 'NEO4J_URI', 'NEO4J_USERNAME']
    missing_vars = []
    
    for var in required_env_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        logger.info("Please set the following environment variables:")
        for var in missing_vars:
            logger.info(f"  export {var}=<your_{var.lower()}>")
        sys.exit(1)
    
    # Check optional environment variables and warn if missing
    missing_optional = []
    for var in optional_env_vars:
        if not os.getenv(var):
            missing_optional.append(var)
    
    if missing_optional:
        logger.warning(f"Optional environment variables not set: {missing_optional}")
        logger.info("Some enhanced features may not be available. Consider setting:")
        for var in missing_optional:
            logger.info(f"  export {var}=<your_{var.lower()}>")
    
    logger.info("Environment setup complete")

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(description="PCAP Security Analyzer")
    parser.add_argument("--config", "-c", default="config/config.yaml", help="Configuration file path")
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze PCAP file')
    analyze_parser.add_argument('pcap_file', help='Path to PCAP file')
    analyze_parser.add_argument('--output', '-o', default='output', help='Output directory')
    
    # Web interface command
    web_parser = subparsers.add_parser('web', help='Run web interface')
    web_parser.add_argument('--host', default='localhost', help='Host address')
    web_parser.add_argument('--port', type=int, default=8501, help='Port number')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Query knowledge graph')
    query_parser.add_argument('query_text', help='Query text')
    query_parser.add_argument('--mode', default='hybrid', choices=['hybrid', 'global', 'local', 'naive'])
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup environment
    setup_environment()
    
    # Initialize analyzer
    analyzer = PCAPSecurityAnalyzer(args.config)
    
    try:
        if args.command == 'analyze':
            results = asyncio.run(analyzer.analyze_pcap(args.pcap_file, args.output))
            print(f"\n✅ Analysis complete! Results saved to {args.output}")
            
            summary = results.get('analysis_summary', {})
            print(f"Security Score: {summary.get('security_score', 0)}/100")
            print(f"Threats Detected: {summary.get('security_events', {}).get('total', 0)}")
            
        elif args.command == 'web':
            analyzer.run_web_interface(args.host, args.port)
            
        elif args.command == 'query':
            if not analyzer.knowledge_graph:
                print("❌ Knowledge graph not available. Please run analysis first.")
                return
            
            result = asyncio.run(analyzer.query_knowledge_graph(args.query_text, args.mode))
            
            if 'error' in result:
                print(f"❌ Query failed: {result['error']}")
            else:
                print(f"🔍 Query: {args.query_text}")
                print(f"📄 Response: {result.get('lightrag_response', 'No response')}")
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()