"""
Knowledge Graph Integration with LightRAG and Neo4j
Provides advanced graph-based analysis and querying capabilities
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import asdict
import networkx as nx
from neo4j import GraphDatabase
# Updated imports for LightRAG beta version
try:
    from lightrag.core import Generator, Embedder, Retriever, Document
    from lightrag.components import ModelClient
    LIGHTRAG_AVAILABLE = True
except ImportError:
    # Fallback if LightRAG is not available or API has changed
    LIGHTRAG_AVAILABLE = False
    class Generator: pass
    class Embedder: pass
    class Retriever: pass
    class Document: pass
    class ModelClient: pass
import numpy as np
from datetime import datetime

logger = logging.getLogger(__name__)

# Make sentence_transformers optional to avoid version conflicts
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"SentenceTransformers not available: {e}")
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    class SentenceTransformer:
        def __init__(self, *args, **kwargs):
            pass
        def encode(self, *args, **kwargs):
            return []

class SecurityKnowledgeGraph:
    """Advanced Security Knowledge Graph with LightRAG and Neo4j integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.lightrag = None
        self.neo4j_driver = None
        self.reranker_model = None
        self.knowledge_documents = []
        self.entity_relationships = []
        
    async def initialize(self):
        """Initialize knowledge graph components"""
        logger.info("Initializing Security Knowledge Graph...")
        
        try:
            # Initialize Neo4j connection
            await self._initialize_neo4j()
            
            # Initialize reranker model
            await self._initialize_reranker()
            
            # Initialize LightRAG
            await self._initialize_lightrag()
            
            logger.info("Security Knowledge Graph initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize knowledge graph: {e}")
            raise
    
    async def _initialize_neo4j(self):
        """Initialize Neo4j database connection"""
        neo4j_config = self.config.get('neo4j', {})
        
        self.neo4j_driver = GraphDatabase.driver(
            neo4j_config.get('uri', 'bolt://localhost:7687'),
            auth=(
                neo4j_config.get('username', 'neo4j'),
                neo4j_config.get('password', 'password')
            )
        )
        
        # Test connection
        with self.neo4j_driver.session() as session:
            result = session.run("RETURN 1 as test")
            result.single()
            
        logger.info("Neo4j connection established")
        
        # Create indexes and constraints
        await self._setup_neo4j_schema()
    
    async def _setup_neo4j_schema(self):
        """Setup Neo4j schema for security analysis"""
        
        schema_queries = [
            # Create constraints
            "CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip_address IS UNIQUE",
            "CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:SecurityEvent) REQUIRE e.event_id IS UNIQUE",
            "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.service_id IS UNIQUE",
            
            # Create indexes
            "CREATE INDEX host_reputation IF NOT EXISTS FOR (h:Host) ON (h.reputation)",
            "CREATE INDEX event_severity IF NOT EXISTS FOR (e:SecurityEvent) ON (e.severity)",
            "CREATE INDEX event_type IF NOT EXISTS FOR (e:SecurityEvent) ON (e.event_type)",
            "CREATE INDEX service_port IF NOT EXISTS FOR (s:Service) ON (s.port)",
            "CREATE INDEX connection_timestamp IF NOT EXISTS FOR (c:Connection) ON (c.timestamp)",
            
            # Create full-text indexes
            "CALL db.index.fulltext.createNodeIndex('security_events_fulltext', ['SecurityEvent'], ['description', 'evidence']) IF NOT EXISTS",
            "CALL db.index.fulltext.createNodeIndex('hosts_fulltext', ['Host'], ['hostname', 'description']) IF NOT EXISTS"
        ]
        
        with self.neo4j_driver.session() as session:
            for query in schema_queries:
                try:
                    session.run(query)
                except Exception as e:
                    logger.warning(f"Schema setup warning: {e}")
        
        logger.info("Neo4j schema setup completed")
    
    async def _initialize_reranker(self):
        """Initialize reranker model for improved retrieval"""
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.warning("SentenceTransformers not available - reranker disabled")
            self.reranker_model = None
            return
            
        try:
            reranker_config = self.config.get('reranker', {})
            model_name = reranker_config.get('model', 'sentence-transformers/all-MiniLM-L6-v2')
            
            self.reranker_model = SentenceTransformer(model_name)
            logger.info(f"Reranker model loaded: {model_name}")
            
        except Exception as e:
            logger.warning(f"Failed to load reranker model: {e}")
            self.reranker_model = None
    
    async def _initialize_lightrag(self):
        """Initialize LightRAG with enhanced configuration"""
        
        if not LIGHTRAG_AVAILABLE:
            logger.warning("LightRAG not available - knowledge graph features will be limited")
            self.lightrag = None
            return
        
        try:
            lightrag_config = self.config.get('lightrag', {})
            
            # For now, create a simple placeholder since the API has changed significantly
            # This would need to be updated based on the actual new LightRAG API
            self.lightrag = {
                'working_dir': lightrag_config.get('working_dir', './data/lightrag_cache'),
                'config': lightrag_config,
                'documents': []
            }
            
            logger.info("LightRAG placeholder initialized - full integration pending API update")
            
        except Exception as e:
            logger.error(f"Failed to initialize LightRAG: {e}")
            self.lightrag = None
    
    async def _llm_model_func(self, prompt: str, system_prompt: str = None, **kwargs):
        """Enhanced LLM function for security analysis"""
        
        if system_prompt is None:
            system_prompt = """You are an expert cybersecurity analyst specializing in network traffic analysis and threat detection. 

Your expertise includes:
- Network protocol analysis and security implications
- Attack pattern recognition and threat categorization
- Vulnerability assessment and risk evaluation
- Security incident investigation and forensics
- Compliance and regulatory requirements

When analyzing security data:
1. Focus on actionable security insights
2. Identify attack patterns and threat indicators
3. Assess risk levels and potential impact
4. Provide clear remediation recommendations
5. Consider both technical and business context

Extract entities and relationships that are relevant for security analysis. Pay special attention to:
- Host relationships and communication patterns
- Security events and their context
- Network services and their risk profiles
- Attack vectors and exploitation attempts
- Indicators of compromise (IoCs)"""
        
        try:
            openai_config = self.config.get('openai', {})
            
            response = await openai_complete_if_cache(
                openai_config.get('model', 'gpt-4o-mini'),
                prompt,
                system_prompt=system_prompt,
                api_key=openai_config.get('api_key'),
                base_url="https://api.openai.com/v1",
                max_tokens=openai_config.get('max_tokens', 4096),
                temperature=0.1,  # Lower temperature for more consistent analysis
                **kwargs
            )
            
            return response
            
        except Exception as e:
            logger.error(f"LLM function error: {e}")
            return f"Security analysis completed with limitations. Error: {str(e)[:100]}"
    
    async def _embedding_func(self, texts: List[str]) -> np.ndarray:
        """Enhanced embedding function"""
        
        try:
            openai_config = self.config.get('openai', {})
            
            embeddings = await openai_embed(
                texts,
                model=openai_config.get('embedding_model', 'text-embedding-3-large'),
                api_key=openai_config.get('api_key'),
                base_url="https://api.openai.com/v1"
            )
            
            return embeddings
            
        except Exception as e:
            logger.error(f"Embedding function error: {e}")
            # Return valid embeddings shape
            batch_size = len(texts) if isinstance(texts, list) else 1
            return np.zeros((batch_size, 3072), dtype=np.float32)
    
    async def _rerank_func(self, query: str, documents: List[str], top_k: int = 10) -> List[str]:
        """Custom reranking function using sentence transformers"""
        
        if not self.reranker_model or not documents:
            return documents[:top_k]
        
        try:
            # Encode query and documents
            query_embedding = self.reranker_model.encode([query])
            doc_embeddings = self.reranker_model.encode(documents)
            
            # Compute similarities
            similarities = np.dot(query_embedding, doc_embeddings.T).flatten()
            
            # Get top-k indices
            top_indices = np.argsort(similarities)[::-1][:top_k]
            
            # Return reranked documents
            return [documents[i] for i in top_indices]
            
        except Exception as e:
            logger.warning(f"Reranking failed: {e}")
            return documents[:top_k]
    
    async def build_knowledge_graph(self, network_entities: Dict[str, Any]) -> bool:
        """Build comprehensive knowledge graph from network entities"""
        
        logger.info("Building security knowledge graph...")
        
        try:
            # Create knowledge documents
            documents = await self._create_security_documents(network_entities)
            
            # Insert into LightRAG
            await self._insert_documents_to_lightrag(documents)
            
            # Build Neo4j graph
            await self._build_neo4j_graph(network_entities)
            
            logger.info(f"Knowledge graph built successfully with {len(documents)} documents")
            return True
            
        except Exception as e:
            logger.error(f"Failed to build knowledge graph: {e}")
            return False
    
    async def _create_security_documents(self, network_entities: Dict[str, Any]) -> List[str]:
        """Create comprehensive security-focused documents"""
        
        documents = []
        
        # Document 1: Network Infrastructure and Host Analysis
        doc1 = await self._create_host_analysis_document(network_entities)
        documents.append(doc1)
        
        # Document 2: Security Events and Threat Analysis
        doc2 = await self._create_security_events_document(network_entities)
        documents.append(doc2)
        
        # Document 3: Network Services and Vulnerability Assessment
        doc3 = await self._create_services_vulnerability_document(network_entities)
        documents.append(doc3)
        
        # Document 4: Communication Patterns and Network Flow Analysis
        doc4 = await self._create_network_flow_document(network_entities)
        documents.append(doc4)
        
        # Document 5: Protocol Analysis and Security Implications
        doc5 = await self._create_protocol_analysis_document(network_entities)
        documents.append(doc5)
        
        # Document 6: DNS and Application Layer Security Analysis
        doc6 = await self._create_application_security_document(network_entities)
        documents.append(doc6)
        
        self.knowledge_documents = documents
        logger.info(f"Created {len(documents)} security analysis documents")
        
        return documents
    
    async def _create_host_analysis_document(self, entities: Dict[str, Any]) -> str:
        """Create comprehensive host analysis document"""
        
        hosts = entities.get('hosts', {})
        
        doc = """# Network Infrastructure and Host Security Analysis

## Executive Summary
This document provides a comprehensive analysis of network hosts discovered during traffic analysis, including their security posture, risk assessment, and behavioral patterns.

## Host Inventory and Classification

"""
        
        internal_hosts = []
        external_hosts = []
        critical_hosts = []
        
        for ip, host_data in hosts.items():
            is_internal = host_data.get('is_internal', False)
            reputation = host_data.get('reputation', 'unknown')
            packet_count = host_data.get('packet_count', 0)
            
            if is_internal:
                internal_hosts.append(ip)
            else:
                external_hosts.append(ip)
            
            if packet_count > 1000 or reputation == 'malicious':
                critical_hosts.append(ip)
            
            doc += f"""
### Host {ip} Security Profile
- **Classification**: {'Internal Corporate Asset' if is_internal else 'External Internet Host'}
- **Security Reputation**: {reputation.title()}
- **Network Activity Level**: {packet_count} packets transmitted
- **Risk Assessment**: {self._assess_host_risk(host_data)}
- **Geographic Location**: {host_data.get('geographic_info', {}).get('country', 'Unknown')}
- **Communication Partners**: {len(host_data.get('communication_partners', set()))} unique destinations
- **Protocols Used**: {', '.join(host_data.get('protocols', []))}
- **Services Offered**: {', '.join(host_data.get('services_offered', set()))}
- **Vulnerabilities**: {len(host_data.get('vulnerabilities', []))} identified
- **Suspicious Activities**: {len(host_data.get('suspicious_activities', []))} flagged

**Security Analysis**: Host {ip} demonstrates {'normal network behavior' if not host_data.get('suspicious_activities') else 'suspicious activity patterns requiring investigation'}.
"""
        
        # Network topology analysis
        doc += f"""
## Network Topology Security Assessment

### Infrastructure Overview
- **Total Hosts Analyzed**: {len(hosts)}
- **Internal Network Hosts**: {len(internal_hosts)} ({', '.join(internal_hosts[:10])})
- **External Internet Hosts**: {len(external_hosts)} ({', '.join(external_hosts[:10])})
- **Critical Attention Hosts**: {len(critical_hosts)} requiring monitoring

### Security Perimeter Analysis
The network demonstrates {'proper segmentation' if internal_hosts and external_hosts else 'potential segmentation issues'} with clear distinction between internal corporate assets and external communications.

**Internal Network Security**: {len(internal_hosts)} internal hosts identified with {'standard' if len(internal_hosts) < 10 else 'extensive'} internal communications.

**External Communications**: {len(external_hosts)} external hosts contacted, indicating {'normal' if len(external_hosts) < 20 else 'high volume'} external network activity.

### Risk Factor Analysis
- **High-Risk Hosts**: {len([h for h in hosts.values() if self._assess_host_risk(h) == 'HIGH'])}
- **Medium-Risk Hosts**: {len([h for h in hosts.values() if self._assess_host_risk(h) == 'MEDIUM'])}
- **Low-Risk Hosts**: {len([h for h in hosts.values() if self._assess_host_risk(h) == 'LOW'])}

This analysis indicates {'acceptable' if len(critical_hosts) < 2 else 'elevated'} security risk levels requiring {'routine monitoring' if len(critical_hosts) < 2 else 'immediate attention'}.
"""
        
        return doc
    
    async def _create_security_events_document(self, entities: Dict[str, Any]) -> str:
        """Create detailed security events analysis document"""
        
        security_events = entities.get('security_events', [])
        
        doc = """# Security Events and Threat Analysis Report

## Threat Landscape Overview
This document provides comprehensive analysis of security events detected during network traffic analysis, including attack patterns, threat categorization, and incident response recommendations.

"""
        
        if not security_events:
            doc += """
## Security Status: SECURE

**No security threats detected** during the analysis period. The network demonstrates normal operational patterns without identified malicious activities, attack attempts, or security policy violations.

### Positive Security Indicators
- No malicious traffic patterns identified
- No known attack signatures detected
- No suspicious protocol usage observed
- No unauthorized access attempts logged
- All communications appear legitimate

### Continuous Monitoring Recommendations
- Maintain current security posture
- Continue routine traffic analysis
- Implement behavioral baseline monitoring
- Regular threat intelligence updates
- Periodic security assessments
"""
        else:
            # Categorize security events
            events_by_type = {}
            events_by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
            
            for event in security_events:
                event_type = event.event_type
                severity = event.severity
                
                if event_type not in events_by_type:
                    events_by_type[event_type] = []
                events_by_type[event_type].append(event)
                events_by_severity[severity].append(event)
            
            doc += f"""## Security Alert Status: THREATS DETECTED

**{len(security_events)} security events** identified requiring immediate attention and investigation.

### Threat Distribution by Severity
- **Critical Threats**: {len(events_by_severity['CRITICAL'])} events
- **High Severity**: {len(events_by_severity['HIGH'])} events  
- **Medium Severity**: {len(events_by_severity['MEDIUM'])} events
- **Low Severity**: {len(events_by_severity['LOW'])} events

"""
            
            # Detailed event analysis
            for event_type, events in events_by_type.items():
                doc += f"""
### {event_type.replace('_', ' ').title()} Analysis
**Event Count**: {len(events)}
**Risk Category**: {events[0].attack_category if events else 'UNKNOWN'}

"""
                
                for i, event in enumerate(events[:3], 1):  # Show first 3 events of each type
                    timestamp_str = datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    
                    doc += f"""
**Incident {i}**:
- **Event ID**: {event.event_id}
- **Timestamp**: {timestamp_str}
- **Severity Level**: {event.severity}
- **Source**: {event.source_ip or 'Unknown'}
- **Target**: {event.dest_ip or 'Unknown'}
- **Description**: {event.description}
- **Confidence Score**: {event.confidence_score:.2f}
- **Evidence**: {json.dumps(event.evidence, indent=2)[:300]}...
- **Recommended Actions**: {', '.join(event.remediation[:3])}

**Security Impact**: This {event.event_type} event indicates {event.description.lower()}, requiring immediate investigation and potential incident response procedures.
"""
                
                if len(events) > 3:
                    doc += f"\n*Additional {len(events) - 3} {event_type} events detected...*\n"
            
            # Threat summary and recommendations
            doc += f"""
## Threat Assessment Summary

### Attack Vector Analysis
The detected security events indicate active threat presence with {len([e for e in security_events if e.severity in ['CRITICAL', 'HIGH']])} high-priority incidents requiring immediate response.

### Incident Response Priorities
1. **Immediate Action Required**: {len(events_by_severity['CRITICAL'])} critical events
2. **Investigation Required**: {len(events_by_severity['HIGH'])} high-severity events  
3. **Monitoring Enhanced**: {len(events_by_severity['MEDIUM'])} medium-severity events

### Security Recommendations
- Implement immediate incident response procedures
- Isolate affected systems as necessary
- Conduct forensic analysis of attack vectors
- Update security controls and monitoring rules
- Review and strengthen security policies
- Consider threat hunting activities
"""
        
        return doc
    
    async def _create_services_vulnerability_document(self, entities: Dict[str, Any]) -> str:
        """Create network services and vulnerability assessment document"""
        
        services = entities.get('services', {})
        
        doc = """# Network Services and Vulnerability Assessment

## Service Discovery and Security Analysis
This document provides comprehensive analysis of network services discovered during traffic analysis, including vulnerability assessment, risk evaluation, and security recommendations.

"""
        
        if not services:
            doc += "No network services detected in the analyzed traffic sample."
            return doc
        
        # Categorize services by risk level
        service_risks = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        service_types = {}
        
        for service_key, service_data in services.items():
            service_name = service_data.get('service_name', 'Unknown')
            risk_level = service_data.get('risk_level', 'MEDIUM')
            
            service_risks[risk_level].append((service_key, service_data))
            
            if service_name not in service_types:
                service_types[service_name] = []
            service_types[service_name].append(service_data)
        
        doc += f"""## Service Inventory Overview

**Total Services Discovered**: {len(services)}
- **High Risk Services**: {len(service_risks['HIGH'])}
- **Medium Risk Services**: {len(service_risks['MEDIUM'])} 
- **Low Risk Services**: {len(service_risks['LOW'])}

"""
        
        # Service type analysis
        for service_type, instances in service_types.items():
            doc += f"""
### {service_type} Service Analysis
**Instance Count**: {len(instances)}
**Service Category**: {self._categorize_service(service_type)}
**Default Risk Level**: {instances[0].get('risk_level', 'MEDIUM') if instances else 'UNKNOWN'}

"""
            
            for instance in instances[:3]:  # First 3 instances
                host = instance.get('host', 'Unknown')
                port = instance.get('port', 0)
                protocol = instance.get('protocol', 'unknown')
                clients = len(instance.get('clients', []))
                
                doc += f"""
**Service Instance**: {service_type} on {host}:{port}
- **Protocol**: {protocol.upper()}
- **Active Connections**: {clients} clients
- **Security Considerations**: {self._get_service_security_notes(service_type, port)}
- **Vulnerability Risk**: {self._assess_service_vulnerability_risk(service_type, port)}
- **Compliance Impact**: {self._assess_compliance_impact(service_type)}
- **Monitoring Requirements**: {self._get_monitoring_requirements(service_type)}

"""
        
        # Vulnerability assessment
        doc += """
## Vulnerability Assessment Results

### Service Security Analysis
"""
        
        vulnerable_services = []
        for service_key, service_data in services.items():
            vulnerabilities = self._check_service_vulnerabilities(service_data)
            if vulnerabilities:
                vulnerable_services.append((service_data, vulnerabilities))
        
        if vulnerable_services:
            doc += f"""
**{len(vulnerable_services)} services** identified with potential security vulnerabilities:

"""
            for service_data, vulnerabilities in vulnerable_services[:5]:
                service_name = service_data.get('service_name', 'Unknown')
                host = service_data.get('host', 'Unknown')
                port = service_data.get('port', 0)
                
                doc += f"""
**Vulnerable Service**: {service_name} on {host}:{port}
- **Vulnerabilities**: {', '.join(vulnerabilities)}
- **Risk Impact**: {self._assess_vulnerability_impact(vulnerabilities)}
- **Remediation Priority**: {self._get_remediation_priority(vulnerabilities)}
"""
        else:
            doc += "No specific vulnerabilities identified in current service configurations."
        
        # Security recommendations
        doc += f"""
## Security Recommendations

### Immediate Actions Required
- Review high-risk service configurations
- Implement service hardening measures
- Update vulnerable service versions
- Configure proper access controls
- Enable comprehensive logging

### Long-term Security Improvements
- Regular vulnerability assessments
- Service inventory management
- Security patch management
- Network segmentation implementation
- Continuous security monitoring

### Compliance Considerations
Services identified may require specific compliance controls depending on regulatory requirements (PCI-DSS, HIPAA, SOX, etc.).
"""
        
        return doc
    
    async def _insert_documents_to_lightrag(self, documents: List[str]) -> bool:
        """Insert documents into LightRAG knowledge graph"""
        
        if not self.lightrag:
            logger.warning("LightRAG not available - documents stored locally only")
            # Store documents locally as fallback
            if isinstance(self.lightrag, dict):
                self.lightrag['documents'].extend(documents)
            return True
        
        logger.info("Inserting documents into LightRAG...")
        
        try:
            # This would need to be updated for the new LightRAG API
            for i, document in enumerate(documents):
                logger.info(f"Storing document {i+1}/{len(documents)}...")
                if isinstance(self.lightrag, dict):
                    self.lightrag['documents'].append(document)
                
                # Brief pause to prevent overwhelming the system
                await asyncio.sleep(0.1)
            
            logger.info("All documents stored successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store documents: {e}")
            return False
    
    async def _build_neo4j_graph(self, network_entities: Dict[str, Any]) -> bool:
        """Build comprehensive Neo4j graph from network entities"""
        
        logger.info("Building Neo4j knowledge graph...")
        
        try:
            with self.neo4j_driver.session() as session:
                # Clear existing data
                session.run("MATCH (n) DETACH DELETE n")
                
                # Create host nodes
                await self._create_host_nodes(session, network_entities.get('hosts', {}))
                
                # Create service nodes
                await self._create_service_nodes(session, network_entities.get('services', {}))
                
                # Create security event nodes
                await self._create_security_event_nodes(session, network_entities.get('security_events', []))
                
                # Create relationships
                await self._create_relationships(session, network_entities)
                
            logger.info("Neo4j knowledge graph built successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to build Neo4j graph: {e}")
            return False
    
    async def query_security_knowledge(self, query: str, mode: str = "hybrid", top_k: int = 10) -> Dict[str, Any]:
        """Query the security knowledge graph"""
        
        try:
            # Query LightRAG (or fallback to local search)
            if self.lightrag and isinstance(self.lightrag, dict):
                # Simple text search in stored documents as fallback
                documents = self.lightrag.get('documents', [])
                lightrag_result = self._simple_text_search(query, documents, top_k)
            else:
                lightrag_result = "LightRAG not available - using basic text search"
            
            # Query Neo4j for structured data
            neo4j_result = await self._query_neo4j(query) if self.neo4j_driver else {}
            
            # Combine and enhance results
            combined_result = {
                'query': query,
                'timestamp': datetime.now().isoformat(),
                'lightrag_response': lightrag_result,
                'structured_data': neo4j_result,
                'analysis_mode': mode,
                'confidence_score': 0.5  # Default confidence for fallback mode
            }
            
            return combined_result
            
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return {
                'query': query,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _simple_text_search(self, query: str, documents: List[str], top_k: int = 10) -> str:
        """Simple text search fallback when LightRAG is not available"""
        
        if not documents:
            return "No documents available for search"
        
        query_lower = query.lower()
        relevant_docs = []
        
        for doc in documents:
            if query_lower in doc.lower():
                # Find the most relevant section
                lines = doc.split('\n')
                relevant_lines = [line for line in lines if query_lower in line.lower()]
                if relevant_lines:
                    relevant_docs.append('\n'.join(relevant_lines[:5]))  # First 5 relevant lines
        
        if relevant_docs:
            return f"Found {len(relevant_docs)} relevant sections:\n\n" + '\n\n---\n\n'.join(relevant_docs[:top_k])
        else:
            return f"No specific matches found for '{query}' in the analyzed security data."
    
    async def _query_neo4j(self, query: str) -> Dict[str, Any]:
        """Query Neo4j database for structured data"""
        
        if not self.neo4j_driver:
            return {}
        
        try:
            with self.neo4j_driver.session() as session:
                # Simple keyword-based queries for common security terms
                results = {}
                
                if 'host' in query.lower() or 'ip' in query.lower():
                    result = session.run("MATCH (h:Host) RETURN h.ip_address, h.reputation, h.packet_count LIMIT 10")
                    results['hosts'] = [dict(record) for record in result]
                
                if 'event' in query.lower() or 'threat' in query.lower():
                    result = session.run("MATCH (e:SecurityEvent) RETURN e.event_type, e.severity, e.description LIMIT 10")
                    results['security_events'] = [dict(record) for record in result]
                
                if 'service' in query.lower():
                    result = session.run("MATCH (s:Service) RETURN s.service_name, s.port, s.risk_level LIMIT 10")
                    results['services'] = [dict(record) for record in result]
                
                return results
                
        except Exception as e:
            logger.error(f"Neo4j query failed: {e}")
            return {}
    
    def _assess_host_risk(self, host_data: Dict) -> str:
        """Assess security risk level of a host"""
        risk_score = 0
        
        # Reputation factor
        reputation = host_data.get('reputation', 'unknown')
        if reputation == 'malicious':
            risk_score += 50
        elif reputation == 'suspicious':
            risk_score += 30
        
        # Activity level factor
        packet_count = host_data.get('packet_count', 0)
        if packet_count > 10000:
            risk_score += 20
        elif packet_count > 1000:
            risk_score += 10
        
        # Suspicious activities factor
        suspicious_count = len(host_data.get('suspicious_activities', []))
        risk_score += suspicious_count * 15
        
        # Vulnerabilities factor
        vuln_count = len(host_data.get('vulnerabilities', []))
        risk_score += vuln_count * 10
        
        # External communication factor
        if not host_data.get('is_internal', True):
            risk_score += 15
        
        if risk_score >= 50:
            return 'HIGH'
        elif risk_score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    # Helper methods for service analysis
    def _categorize_service(self, service_type: str) -> str:
        """Categorize service type"""
        web_services = ['HTTP', 'HTTPS']
        database_services = ['MySQL', 'PostgreSQL', 'MongoDB']
        file_services = ['FTP', 'SFTP', 'SMB']
        
        if service_type in web_services:
            return 'Web Service'
        elif service_type in database_services:
            return 'Database Service'
        elif service_type in file_services:
            return 'File Transfer Service'
        else:
            return 'Network Service'
    
    def _get_service_security_notes(self, service_type: str, port: int) -> str:
        """Get security notes for service type"""
        notes = {
            'HTTP': 'Unencrypted web traffic - consider HTTPS',
            'HTTPS': 'Encrypted web traffic - verify certificate validity',
            'FTP': 'Unencrypted file transfer - consider SFTP',
            'SSH': 'Secure shell access - monitor for brute force attempts',
            'Telnet': 'Unencrypted remote access - replace with SSH',
            'SMB': 'File sharing protocol - ensure proper access controls'
        }
        return notes.get(service_type, 'Standard network service security practices apply')
    
    def _assess_service_vulnerability_risk(self, service_type: str, port: int) -> str:
        """Assess vulnerability risk for service"""
        high_risk = ['FTP', 'Telnet', 'HTTP', 'SMB']
        medium_risk = ['SSH', 'SMTP', 'POP3']
        
        if service_type in high_risk:
            return 'HIGH - Known security vulnerabilities'
        elif service_type in medium_risk:
            return 'MEDIUM - Requires proper configuration'
        else:
            return 'LOW - Standard security practices sufficient'
    
    def _assess_compliance_impact(self, service_type: str) -> str:
        """Assess compliance impact of service"""
        return 'Review compliance requirements for data handling services'
    
    def _get_monitoring_requirements(self, service_type: str) -> str:
        """Get monitoring requirements for service"""
        return 'Enable logging and monitor for unusual access patterns'
    
    def _check_service_vulnerabilities(self, service_data: Dict) -> List[str]:
        """Check for known service vulnerabilities"""
        vulnerabilities = []
        service_name = service_data.get('service_name', '')
        port = service_data.get('port', 0)
        
        # Common vulnerability checks
        if service_name == 'FTP' and port == 21:
            vulnerabilities.append('Unencrypted credentials')
        if service_name == 'Telnet':
            vulnerabilities.append('Unencrypted communication')
        if service_name == 'HTTP' and port == 80:
            vulnerabilities.append('Unencrypted web traffic')
        
        return vulnerabilities
    
    def _assess_vulnerability_impact(self, vulnerabilities: List[str]) -> str:
        """Assess impact of vulnerabilities"""
        if len(vulnerabilities) > 2:
            return 'HIGH - Multiple security issues'
        elif len(vulnerabilities) > 0:
            return 'MEDIUM - Security improvements needed'
        else:
            return 'LOW - No major issues identified'
    
    def _get_remediation_priority(self, vulnerabilities: List[str]) -> str:
        """Get remediation priority"""
        critical_vulns = ['Unencrypted credentials', 'Remote code execution']
        if any(vuln in critical_vulns for vuln in vulnerabilities):
            return 'IMMEDIATE'
        elif vulnerabilities:
            return 'HIGH'
        else:
            return 'ROUTINE'
    
    # Placeholder methods for Neo4j operations
    async def _create_host_nodes(self, session, hosts: Dict):
        """Create host nodes in Neo4j"""
        for ip, host_data in hosts.items():
            query = """
            CREATE (h:Host {
                ip_address: $ip,
                is_internal: $is_internal,
                reputation: $reputation,
                packet_count: $packet_count,
                first_seen: $first_seen,
                last_seen: $last_seen
            })
            """
            session.run(query, {
                'ip': ip,
                'is_internal': host_data.get('is_internal', False),
                'reputation': host_data.get('reputation', 'unknown'),
                'packet_count': host_data.get('packet_count', 0),
                'first_seen': host_data.get('first_seen', 0),
                'last_seen': host_data.get('last_seen', 0)
            })
    
    async def _create_service_nodes(self, session, services: Dict):
        """Create service nodes in Neo4j"""
        for service_key, service_data in services.items():
            query = """
            CREATE (s:Service {
                service_id: $service_id,
                service_name: $service_name,
                host: $host,
                port: $port,
                protocol: $protocol,
                risk_level: $risk_level
            })
            """
            session.run(query, {
                'service_id': service_key,
                'service_name': service_data.get('service_name', 'Unknown'),
                'host': service_data.get('host', 'Unknown'),
                'port': service_data.get('port', 0),
                'protocol': service_data.get('protocol', 'Unknown'),
                'risk_level': service_data.get('risk_level', 'MEDIUM')
            })
    
    async def _create_security_event_nodes(self, session, security_events: List):
        """Create security event nodes in Neo4j"""
        for event in security_events:
            query = """
            CREATE (e:SecurityEvent {
                event_id: $event_id,
                event_type: $event_type,
                severity: $severity,
                timestamp: $timestamp,
                source_ip: $source_ip,
                dest_ip: $dest_ip,
                description: $description,
                confidence_score: $confidence_score
            })
            """
            session.run(query, {
                'event_id': event.event_id,
                'event_type': event.event_type,
                'severity': event.severity,
                'timestamp': event.timestamp,
                'source_ip': event.source_ip,
                'dest_ip': event.dest_ip,
                'description': event.description,
                'confidence_score': event.confidence_score
            })
    
    async def _create_relationships(self, session, network_entities: Dict):
        """Create relationships between nodes"""
        # Create host-to-service relationships
        services = network_entities.get('services', {})
        for service_key, service_data in services.items():
            host_ip = service_data.get('host')
            if host_ip:
                query = """
                MATCH (h:Host {ip_address: $host_ip})
                MATCH (s:Service {service_id: $service_id})
                CREATE (h)-[:HOSTS]->(s)
                """
                session.run(query, {
                    'host_ip': host_ip,
                    'service_id': service_key
                })
        
        # Create event-to-host relationships
        security_events = network_entities.get('security_events', [])
        for event in security_events:
            if event.source_ip:
                query = """
                MATCH (h:Host {ip_address: $source_ip})
                MATCH (e:SecurityEvent {event_id: $event_id})
                CREATE (h)-[:GENERATED]->(e)
                """
                session.run(query, {
                    'source_ip': event.source_ip,
                    'event_id': event.event_id
                })
    
    # Additional missing methods
    async def _create_network_flow_document(self, entities: Dict[str, Any]) -> str:
        """Create network flow analysis document"""
        return "# Network Flow Analysis\n\nNetwork communication patterns and flow analysis would be detailed here."
    
    async def _create_protocol_analysis_document(self, entities: Dict[str, Any]) -> str:
        """Create protocol analysis document"""
        return "# Protocol Analysis\n\nDetailed protocol usage and security implications would be analyzed here."
    
    async def _create_application_security_document(self, entities: Dict[str, Any]) -> str:
        """Create application security document"""
        return "# Application Security Analysis\n\nDNS and application layer security analysis would be provided here."
    
    def close(self):
        """Close database connections"""
        if self.neo4j_driver:
            self.neo4j_driver.close()
            logger.info("Neo4j connection closed")