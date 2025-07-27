"""
Advanced Security Analyzer Module
Provides sophisticated security analysis capabilities including threat detection,
vulnerability assessment, and behavioral analysis
"""

import re
import math
import hashlib
import ipaddress
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
import numpy as np
from scipy import stats
import asyncio

logger = logging.getLogger(__name__)

@dataclass
class ThreatSignature:
    """Represents a threat signature for detection"""
    name: str
    category: str
    severity: str
    patterns: List[str]
    indicators: List[str]
    ports: List[int]
    protocols: List[str]
    confidence_threshold: float
    description: str
    mitigation_steps: List[str]

@dataclass
class VulnerabilityAssessment:
    """Represents a vulnerability assessment result"""
    cve_id: Optional[str]
    vulnerability_name: str
    affected_service: str
    severity_score: float
    exploit_likelihood: str
    impact_assessment: str
    remediation_priority: str
    technical_details: Dict[str, Any]
    references: List[str]

@dataclass
class BehavioralAnomaly:
    """Represents a behavioral anomaly detection result"""
    anomaly_id: str
    anomaly_type: str
    confidence_score: float
    statistical_significance: float
    baseline_deviation: float
    affected_entities: List[str]
    temporal_pattern: str
    risk_assessment: str
    investigation_priority: str

class AdvancedSecurityAnalyzer:
    """Advanced Security Analyzer with ML-based threat detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threat_signatures = self._load_threat_signatures()
        self.vulnerability_database = self._load_vulnerability_database()
        self.behavioral_baselines = {}
        self.statistical_models = {}
        
        # Analysis results storage
        self.detected_threats = []
        self.vulnerability_assessments = []
        self.behavioral_anomalies = []
        self.risk_assessments = {}
        
        logger.info("Advanced Security Analyzer initialized")
    
    def _load_threat_signatures(self) -> List[ThreatSignature]:
        """Load comprehensive threat signatures database"""
        
        signatures = [
            # Web Application Attacks
            ThreatSignature(
                name="SQL Injection Attack",
                category="WEB_APPLICATION",
                severity="HIGH",
                patterns=[
                    r"('|(\\'))+.*(or|union|select|insert|update|delete|drop|exec)",
                    r"union\s+select",
                    r"1=1|1='1'|1=\"1\"",
                    r"exec\s*\(",
                    r"sp_executesql",
                    r"xp_cmdshell",
                    r"benchmark\s*\(",
                    r"sleep\s*\(",
                    r"waitfor\s+delay"
                ],
                indicators=["sql_keywords", "union_statements", "boolean_injection"],
                ports=[80, 443, 8080, 8443, 3000],
                protocols=["HTTP", "HTTPS"],
                confidence_threshold=0.8,
                description="SQL injection attempt detected in HTTP traffic",
                mitigation_steps=[
                    "Implement parameterized queries",
                    "Input validation and sanitization", 
                    "Web Application Firewall deployment",
                    "Database user privilege restriction"
                ]
            ),
            
            ThreatSignature(
                name="Cross-Site Scripting (XSS)",
                category="WEB_APPLICATION", 
                severity="MEDIUM",
                patterns=[
                    r"<script[^>]*>.*?</script>",
                    r"javascript\s*:",
                    r"on\w+\s*=",
                    r"alert\s*\(",
                    r"document\.cookie",
                    r"eval\s*\(",
                    r"String\.fromCharCode",
                    r"<iframe[^>]*>",
                    r"<object[^>]*>",
                    r"<embed[^>]*>"
                ],
                indicators=["script_tags", "javascript_execution", "dom_manipulation"],
                ports=[80, 443, 8080, 8443],
                protocols=["HTTP", "HTTPS"],
                confidence_threshold=0.7,
                description="Cross-site scripting attack detected",
                mitigation_steps=[
                    "Output encoding/escaping",
                    "Content Security Policy implementation",
                    "Input validation",
                    "XSS filtering"
                ]
            ),
            
            ThreatSignature(
                name="Command Injection",
                category="WEB_APPLICATION",
                severity="CRITICAL",
                patterns=[
                    r";\s*(cat|ls|id|whoami|uname|pwd)",
                    r"\|\s*(nc|netcat|curl|wget)",
                    r"`.*`",
                    r"\$\(.*\)",
                    r"&&\s*(rm|mv|cp)",
                    r";\s*(echo|printf)",
                    r"\|\s*(base64|xxd)"
                ],
                indicators=["shell_commands", "command_chaining", "output_redirection"],
                ports=[80, 443, 22, 23],
                protocols=["HTTP", "HTTPS", "SSH", "TELNET"],
                confidence_threshold=0.9,
                description="Command injection attempt detected",
                mitigation_steps=[
                    "Input sanitization",
                    "Avoid system calls in web applications",
                    "Principle of least privilege",
                    "Application sandboxing"
                ]
            ),
            
            # Network-based Attacks
            ThreatSignature(
                name="Port Scanning Activity",
                category="RECONNAISSANCE",
                severity="MEDIUM",
                patterns=[],  # Behavioral pattern
                indicators=["multiple_ports", "rapid_connections", "connection_failures"],
                ports=[],  # Any port
                protocols=["TCP", "UDP"],
                confidence_threshold=0.8,
                description="Port scanning activity detected from source",
                mitigation_steps=[
                    "Implement rate limiting",
                    "Deploy intrusion detection system",
                    "Network segmentation",
                    "Host-based firewall rules"
                ]
            ),
            
            ThreatSignature(
                name="DDoS Attack",
                category="DENIAL_OF_SERVICE",
                severity="HIGH", 
                patterns=[],  # Volume-based detection
                indicators=["high_volume", "multiple_sources", "resource_exhaustion"],
                ports=[80, 443, 53, 25],
                protocols=["TCP", "UDP", "ICMP"],
                confidence_threshold=0.85,
                description="Distributed Denial of Service attack detected",
                mitigation_steps=[
                    "Traffic filtering and rate limiting", 
                    "CDN and DDoS protection services",
                    "Load balancing and scaling",
                    "Upstream provider notification"
                ]
            ),
            
            ThreatSignature(
                name="Brute Force Authentication",
                category="CREDENTIAL_ATTACK",
                severity="HIGH",
                patterns=[
                    r"failed\s+login",
                    r"authentication\s+failed",
                    r"invalid\s+(user|password)",
                    r"login\s+incorrect"
                ],
                indicators=["multiple_login_attempts", "failed_authentication", "dictionary_attack"],
                ports=[21, 22, 23, 25, 110, 143, 993, 995, 3389, 5900],
                protocols=["FTP", "SSH", "TELNET", "SMTP", "POP3", "IMAP", "RDP", "VNC"],
                confidence_threshold=0.8,
                description="Brute force authentication attack detected",
                mitigation_steps=[
                    "Account lockout policies",
                    "Strong password requirements",
                    "Multi-factor authentication",
                    "IP-based access controls"
                ]
            ),
            
            # DNS-based Attacks
            ThreatSignature(
                name="DNS Tunneling",
                category="DATA_EXFILTRATION", 
                severity="HIGH",
                patterns=[
                    r"[A-Za-z0-9+/=]{20,}\..*",  # Base64-like patterns
                    r"[0-9a-f]{32,}\..*",        # Hex-encoded data
                ],
                indicators=["high_entropy", "unusual_query_length", "suspicious_domains"],
                ports=[53],
                protocols=["DNS"],
                confidence_threshold=0.7,
                description="DNS tunneling activity detected",
                mitigation_steps=[
                    "DNS monitoring and filtering",
                    "Query length restrictions",
                    "Domain reputation checking",
                    "Network egress controls"
                ]
            ),
            
            ThreatSignature(
                name="DNS Cache Poisoning",
                category="DNS_ATTACK",
                severity="HIGH", 
                patterns=[],  # Response analysis
                indicators=["response_mismatch", "suspicious_authority", "cache_manipulation"],
                ports=[53],
                protocols=["DNS"],
                confidence_threshold=0.8,
                description="DNS cache poisoning attempt detected",
                mitigation_steps=[
                    "DNS Security Extensions (DNSSEC)",
                    "Secure DNS resolvers",
                    "Query source randomization",
                    "DNS response validation"
                ]
            ),
            
            # Malware Detection
            ThreatSignature(
                name="Malware Communication",
                category="MALWARE",
                severity="CRITICAL",
                patterns=[
                    r"\/[a-zA-Z0-9]{8,}\/[a-zA-Z0-9]{8,}",  # Suspicious URL patterns
                    r"User-Agent:\s*(curl|wget|python|powershell)"
                ],
                indicators=["c2_communication", "malware_domains", "suspicious_user_agents"],
                ports=[80, 443, 8080, 8443],
                protocols=["HTTP", "HTTPS"],
                confidence_threshold=0.85,
                description="Malware command and control communication detected",
                mitigation_steps=[
                    "Endpoint detection and response",
                    "Network traffic filtering",
                    "Malware domain blocking",
                    "System isolation and analysis"
                ]
            ),
            
            # Protocol-specific Attacks
            ThreatSignature(
                name="ARP Spoofing/Poisoning",
                category="NETWORK_ATTACK",
                severity="MEDIUM",
                patterns=[],  # ARP analysis
                indicators=["duplicate_mac", "gratuitous_arp", "mac_ip_conflict"],
                ports=[],
                protocols=["ARP"],
                confidence_threshold=0.8,
                description="ARP spoofing/poisoning attack detected",
                mitigation_steps=[
                    "Static ARP entries",
                    "Dynamic ARP inspection",
                    "Network access control",
                    "VLAN segmentation"
                ]
            ),
            
            ThreatSignature(
                name="SMB/NetBIOS Attack",
                category="LATERAL_MOVEMENT",
                severity="HIGH",
                patterns=[
                    rb"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72",  # EternalBlue signature
                    rb"\xfe\x53\x4d\x42",  # SMB2/3
                ],
                indicators=["smb_exploit", "lateral_movement", "credential_harvesting"],
                ports=[139, 445],
                protocols=["SMB", "NetBIOS"],
                confidence_threshold=0.9,
                description="SMB-based attack detected (potential EternalBlue or lateral movement)",
                mitigation_steps=[
                    "SMB protocol restrictions",
                    "Network segmentation",
                    "Patch management",
                    "Credential protection"
                ]
            )
        ]
        
        logger.info(f"Loaded {len(signatures)} threat signatures")
        return signatures
    
    def _load_vulnerability_database(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability database with CVE mappings"""
        
        vulnerabilities = {
            # Network Service Vulnerabilities
            "ssh_weak_config": {
                "name": "SSH Weak Configuration",
                "cve_ids": ["CVE-2021-28041", "CVE-2020-14145"],
                "affected_services": ["SSH"],
                "ports": [22],
                "severity": 7.5,
                "description": "SSH service with weak configuration detected",
                "indicators": ["password_auth", "weak_ciphers", "old_version"],
                "remediation": [
                    "Disable password authentication",
                    "Use strong cipher suites",
                    "Update to latest version",
                    "Implement key-based authentication"
                ]
            },
            
            "ftp_anonymous": {
                "name": "Anonymous FTP Access", 
                "cve_ids": [],
                "affected_services": ["FTP"],
                "ports": [21],
                "severity": 5.0,
                "description": "FTP server allowing anonymous access",
                "indicators": ["anonymous_login", "public_access"],
                "remediation": [
                    "Disable anonymous access",
                    "Implement authentication",
                    "Use secure file transfer protocols",
                    "Access control restrictions"
                ]
            },
            
            "telnet_cleartext": {
                "name": "Cleartext Telnet Protocol",
                "cve_ids": [],
                "affected_services": ["TELNET"],
                "ports": [23],
                "severity": 8.0,
                "description": "Insecure cleartext Telnet protocol detected",
                "indicators": ["cleartext_auth", "unencrypted_session"],
                "remediation": [
                    "Replace with SSH",
                    "Disable Telnet service",
                    "Use encrypted alternatives",
                    "Network access restrictions"
                ]
            },
            
            # Web Application Vulnerabilities
            "http_no_encryption": {
                "name": "Unencrypted HTTP Traffic",
                "cve_ids": [],
                "affected_services": ["HTTP"],
                "ports": [80],
                "severity": 4.0,
                "description": "Sensitive data transmitted over unencrypted HTTP",
                "indicators": ["cleartext_http", "sensitive_data", "authentication_data"],
                "remediation": [
                    "Implement HTTPS",
                    "SSL/TLS certificates",
                    "HTTP to HTTPS redirects",
                    "Strict transport security"
                ]
            },
            
            # DNS Vulnerabilities
            "dns_open_resolver": {
                "name": "DNS Open Resolver",
                "cve_ids": [],
                "affected_services": ["DNS"],
                "ports": [53],
                "severity": 5.0,
                "description": "DNS server configured as open resolver",
                "indicators": ["recursive_queries", "external_access", "amplification_risk"],
                "remediation": [
                    "Restrict recursive queries",
                    "Access control lists",
                    "Rate limiting",
                    "Monitoring and logging"
                ]
            },
            
            # Database Vulnerabilities
            "database_default_creds": {
                "name": "Database Default Credentials",
                "cve_ids": [],
                "affected_services": ["MySQL", "PostgreSQL", "MSSQL", "Oracle"],
                "ports": [1433, 1521, 3306, 5432],
                "severity": 9.0,
                "description": "Database service using default credentials",
                "indicators": ["default_passwords", "weak_authentication"],
                "remediation": [
                    "Change default passwords",
                    "Strong password policies",
                    "Database hardening",
                    "Access restrictions"
                ]
            },
            
            # IoT Device Vulnerabilities  
            "iot_default_config": {
                "name": "IoT Device Default Configuration",
                "cve_ids": [],
                "affected_services": ["HTTP", "TELNET", "SSH"],
                "ports": [80, 23, 22, 8080, 8081, 9000],
                "severity": 7.0,
                "description": "IoT device with default configuration detected",
                "indicators": ["default_credentials", "open_management", "weak_security"],
                "remediation": [
                    "Change default credentials",
                    "Firmware updates",
                    "Network segmentation",
                    "Access restrictions"
                ]
            }
        }
        
        logger.info(f"Loaded {len(vulnerabilities)} vulnerability definitions")
        return vulnerabilities
    
    async def analyze_security_threats(self, network_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive security threat analysis"""
        
        logger.info("Starting comprehensive security threat analysis...")
        
        try:
            # Clear previous results
            self.detected_threats.clear()
            self.vulnerability_assessments.clear()
            self.behavioral_anomalies.clear()
            
            # Multi-layered threat analysis
            await self._analyze_network_layer_threats(network_entities)
            await self._analyze_application_layer_threats(network_entities)
            await self._analyze_behavioral_threats(network_entities)
            await self._perform_vulnerability_assessment(network_entities)
            await self._analyze_lateral_movement(network_entities)
            await self._detect_data_exfiltration(network_entities)
            
            # Generate comprehensive risk assessment
            risk_assessment = await self._generate_risk_assessment(network_entities)
            
            analysis_results = {
                'detected_threats': [asdict(threat) for threat in self.detected_threats],
                'vulnerability_assessments': [asdict(vuln) for vuln in self.vulnerability_assessments],
                'behavioral_anomalies': [asdict(anomaly) for anomaly in self.behavioral_anomalies],
                'risk_assessment': risk_assessment,
                'threat_statistics': self._calculate_threat_statistics(),
                'security_recommendations': self._generate_security_recommendations(),
                'analysis_metadata': {
                    'analysis_timestamp': datetime.now().isoformat(),
                    'threats_detected': len(self.detected_threats),
                    'vulnerabilities_found': len(self.vulnerability_assessments),
                    'anomalies_identified': len(self.behavioral_anomalies)
                }
            }
            
            logger.info(f"Security analysis complete: {len(self.detected_threats)} threats, {len(self.vulnerability_assessments)} vulnerabilities")
            return analysis_results
            
        except Exception as e:
            logger.error(f"Security threat analysis failed: {e}")
            raise
    
    async def _analyze_network_layer_threats(self, network_entities: Dict[str, Any]):
        """Analyze network layer (L3/L4) security threats"""
        
        logger.info("Analyzing network layer threats...")
        
        hosts = network_entities.get('hosts', {})
        connections = network_entities.get('connections', [])
        
        # Port scanning detection
        await self._detect_port_scanning(hosts, connections)
        
        # DDoS detection
        await self._detect_ddos_attacks(connections)
        
        # Suspicious connection patterns
        await self._analyze_connection_patterns(connections)
        
        # Network reconnaissance detection
        await self._detect_network_reconnaissance(hosts, connections)
    
    async def _detect_port_scanning(self, hosts: Dict, connections: List):
        """Detect port scanning activities"""
        
        # Track connections per source
        source_connections = defaultdict(lambda: {
            'ports': set(), 
            'targets': set(), 
            'timestamps': [],
            'failed_connections': 0
        })
        
        for conn in connections:
            if conn.get('type') == 'tcp_connection':
                source = conn.get('source_ip')
                target = conn.get('dest_ip')
                port = conn.get('dest_port')
                timestamp = conn.get('timestamp', 0)
                
                if source and target and port:
                    source_connections[source]['ports'].add(port)
                    source_connections[source]['targets'].add(target)
                    source_connections[source]['timestamps'].append(timestamp)
                    
                    # Check for connection failures (RST, timeout, etc.)
                    if conn.get('connection_state') in ['RESET', 'TIMEOUT', 'REFUSED']:
                        source_connections[source]['failed_connections'] += 1
        
        # Analyze for port scanning patterns
        for source_ip, conn_data in source_connections.items():
            ports_count = len(conn_data['ports'])
            targets_count = len(conn_data['targets'])
            failed_ratio = conn_data['failed_connections'] / max(1, len(conn_data['timestamps']))
            
            # Port scan detection criteria
            if ports_count >= 20 or (ports_count >= 10 and failed_ratio > 0.7):
                time_span = max(conn_data['timestamps']) - min(conn_data['timestamps']) if conn_data['timestamps'] else 0
                scan_rate = ports_count / max(1, time_span) if time_span > 0 else ports_count
                
                # Determine scan type
                if targets_count == 1:
                    scan_type = "Single Host Port Scan"
                elif targets_count > 1 and ports_count / targets_count > 10:
                    scan_type = "Network Port Sweep"
                else:
                    scan_type = "Distributed Port Scan"
                
                confidence = min(0.95, 0.6 + (ports_count / 50) + (failed_ratio * 0.3))
                
                from pcap_processor import SecurityEvent
                threat = SecurityEvent(
                    event_id=hashlib.sha256(f"port_scan_{source_ip}_{datetime.now()}".encode()).hexdigest()[:16],
                    event_type="port_scanning",
                    severity="HIGH" if ports_count >= 50 else "MEDIUM",
                    timestamp=max(conn_data['timestamps']) if conn_data['timestamps'] else datetime.now().timestamp(),
                    source_ip=source_ip,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    protocol="TCP",
                    description=f"{scan_type} detected: {ports_count} ports scanned on {targets_count} targets",
                    evidence={
                        'ports_scanned': list(conn_data['ports'])[:20],  # Limit for storage
                        'target_count': targets_count,
                        'failed_connections': conn_data['failed_connections'],
                        'scan_rate': scan_rate,
                        'time_span': time_span,
                        'scan_type': scan_type
                    },
                    attack_category="RECONNAISSANCE",
                    confidence_score=confidence,
                    remediation=[
                        "Implement rate limiting on firewall",
                        "Deploy intrusion detection system",
                        "Block scanning source IP",
                        "Network segmentation to limit scope"
                    ]
                )
                
                self.detected_threats.append(threat)
    
    async def _detect_ddos_attacks(self, connections: List):
        """Detect DDoS attack patterns"""
        
        # Track traffic volume per target
        target_traffic = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'source_ips': set(),
            'timestamps': [],
            'connection_rate': 0
        })
        
        for conn in connections:
            target_ip = conn.get('dest_ip')
            source_ip = conn.get('source_ip')
            timestamp = conn.get('timestamp', 0)
            packet_size = conn.get('packet_size', 0)
            
            if target_ip and source_ip:
                target_traffic[target_ip]['packet_count'] += 1
                target_traffic[target_ip]['byte_count'] += packet_size
                target_traffic[target_ip]['source_ips'].add(source_ip)
                target_traffic[target_ip]['timestamps'].append(timestamp)
        
        # Analyze for DDoS patterns
        for target_ip, traffic_data in target_traffic.items():
            packet_count = traffic_data['packet_count']
            source_count = len(traffic_data['source_ips'])
            byte_count = traffic_data['byte_count']
            
            # DDoS detection thresholds
            high_volume_threshold = 10000  # packets
            distributed_threshold = 50      # unique source IPs
            
            if packet_count >= high_volume_threshold and source_count >= distributed_threshold:
                time_span = max(traffic_data['timestamps']) - min(traffic_data['timestamps'])
                attack_rate = packet_count / max(1, time_span)
                
                # Determine attack type
                if byte_count / packet_count > 1000:
                    attack_type = "Volumetric DDoS"
                elif source_count > 100:
                    attack_type = "Distributed DDoS" 
                else:
                    attack_type = "High-volume Attack"
                
                confidence = min(0.95, 0.7 + min(0.2, source_count / 200) + min(0.1, packet_count / 50000))
                
                from pcap_processor import SecurityEvent
                threat = SecurityEvent(
                    event_id=hashlib.sha256(f"ddos_{target_ip}_{datetime.now()}".encode()).hexdigest()[:16],
                    event_type="ddos_attack",
                    severity="CRITICAL" if packet_count >= 50000 else "HIGH",
                    timestamp=max(traffic_data['timestamps']),
                    source_ip=None,  # Multiple sources
                    dest_ip=target_ip,
                    source_port=None,
                    dest_port=None,
                    protocol="Mixed",
                    description=f"{attack_type} detected against {target_ip}: {packet_count:,} packets from {source_count} sources",
                    evidence={
                        'packet_count': packet_count,
                        'byte_count': byte_count,
                        'source_count': source_count,
                        'attack_rate': attack_rate,
                        'time_span': time_span,
                        'attack_type': attack_type,
                        'top_sources': list(traffic_data['source_ips'])[:10]
                    },
                    attack_category="DENIAL_OF_SERVICE",
                    confidence_score=confidence,
                    remediation=[
                        "Activate DDoS protection services",
                        "Implement traffic filtering and rate limiting",
                        "Contact upstream ISP for mitigation",
                        "Scale infrastructure resources",
                        "Implement geographic IP filtering"
                    ]
                )
                
                self.detected_threats.append(threat)
    
    async def _analyze_application_layer_threats(self, network_entities: Dict[str, Any]):
        """Analyze application layer (L7) security threats"""
        
        logger.info("Analyzing application layer threats...")
        
        # HTTP/HTTPS traffic analysis
        http_sessions = network_entities.get('http_sessions', {})
        await self._analyze_web_attacks(http_sessions)
        
        # DNS traffic analysis
        dns_records = network_entities.get('dns_records', {})
        await self._analyze_dns_threats(dns_records)
        
        # Email traffic analysis (if present)
        await self._analyze_email_threats(network_entities)
        
        # File transfer analysis
        if 'file_transfers' in network_entities:
            await self._analyze_file_transfer_threats(network_entities['file_transfers'])
    
    async def _analyze_web_attacks(self, http_sessions: Dict):
        """Analyze HTTP traffic for web-based attacks"""
        
        for session_key, requests in http_sessions.items():
            for request in requests:
                payload = request.get('payload', '')
                path = request.get('path', '')
                headers = request.get('headers', {})
                user_agent = headers.get('user-agent', '')
                
                # Combined analysis string
                analysis_text = f"{path} {payload} {user_agent}".lower()
                
                # Check against threat signatures
                for signature in self.threat_signatures:
                    if signature.category == "WEB_APPLICATION":
                        threat_detected = False
                        matched_patterns = []
                        
                        for pattern in signature.patterns:
                            if re.search(pattern, analysis_text, re.IGNORECASE):
                                threat_detected = True
                                matched_patterns.append(pattern)
                        
                        if threat_detected:
                            confidence = len(matched_patterns) / len(signature.patterns)
                            if confidence >= signature.confidence_threshold:
                                from pcap_processor import SecurityEvent
                                threat = SecurityEvent(
                                    event_id=hashlib.sha256(f"{signature.name}_{request.get('timestamp', 0)}".encode()).hexdigest()[:16],
                                    event_type=signature.name.lower().replace(' ', '_'),
                                    severity=signature.severity,
                                    timestamp=request.get('timestamp', datetime.now().timestamp()),
                                    source_ip=request.get('source_ip'),
                                    dest_ip=request.get('dest_ip'),
                                    source_port=None,
                                    dest_port=80 if 'http://' in path else 443,
                                    protocol="HTTP",
                                    description=signature.description,
                                    evidence={
                                        'matched_patterns': matched_patterns,
                                        'request_path': path,
                                        'payload_sample': payload[:500],
                                        'user_agent': user_agent,
                                        'request_method': request.get('method', 'UNKNOWN')
                                    },
                                    attack_category=signature.category,
                                    confidence_score=confidence,
                                    remediation=signature.mitigation_steps
                                )
                                
                                self.detected_threats.append(threat)
    
    async def _analyze_dns_threats(self, dns_records: Dict):
        """Analyze DNS traffic for threats"""
        
        for record_key, dns_data in dns_records.items():
            query = dns_data.get('query', '')
            requester = dns_data.get('requester', '')
            
            # DNS Tunneling Detection
            await self._detect_dns_tunneling_advanced(query, requester, dns_data)
            
            # Malicious Domain Detection
            await self._detect_malicious_domains(query, requester, dns_data)
            
            # DNS Cache Poisoning Detection
            await self._detect_dns_cache_poisoning(dns_data)
    
    async def _detect_dns_tunneling_advanced(self, query: str, requester: str, dns_data: Dict):
        """Advanced DNS tunneling detection"""
        
        indicators = []
        confidence_factors = []
        
        # Length analysis
        if len(query) > 100:
            indicators.append("extremely_long_query")
            confidence_factors.append(0.3)
        elif len(query) > 50:
            indicators.append("long_query")
            confidence_factors.append(0.1)
        
        # Entropy analysis
        entropy = self._calculate_entropy(query)
        if entropy > 4.5:
            indicators.append("high_entropy")
            confidence_factors.append(0.4)
        
        # Base64 detection
        subdomain = query.split('.')[0]
        if re.match(r'^[A-Za-z0-9+/=]+$', subdomain) and len(subdomain) > 16:
            indicators.append("base64_encoding")
            confidence_factors.append(0.3)
        
        # Hex encoding detection
        if re.match(r'^[0-9a-fA-F]+$', subdomain) and len(subdomain) > 20:
            indicators.append("hex_encoding") 
            confidence_factors.append(0.3)
        
        # Frequency analysis (requires baseline)
        # This would compare against normal DNS query patterns
        
        # Suspicious TLD check
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion']
        for tld in suspicious_tlds:
            if query.endswith(tld):
                indicators.append(f"suspicious_tld_{tld}")
                confidence_factors.append(0.2)
        
        # If multiple indicators present, likely tunneling
        if len(indicators) >= 2:
            total_confidence = min(0.95, sum(confidence_factors))
            
            if total_confidence >= 0.6:
                from pcap_processor import SecurityEvent 
                threat = SecurityEvent(
                    event_id=hashlib.sha256(f"dns_tunnel_{query}_{requester}".encode()).hexdigest()[:16],
                    event_type="dns_tunneling",
                    severity="HIGH",
                    timestamp=dns_data.get('timestamp', datetime.now().timestamp()),
                    source_ip=requester,
                    dest_ip=None,
                    source_port=None,
                    dest_port=53,
                    protocol="DNS",
                    description=f"DNS tunneling detected: suspicious query pattern from {requester}",
                    evidence={
                        'query': query,
                        'indicators': indicators,
                        'entropy': entropy,
                        'query_length': len(query),
                        'subdomain_analysis': subdomain
                    },
                    attack_category="DATA_EXFILTRATION",
                    confidence_score=total_confidence,
                    remediation=[
                        "DNS monitoring and filtering",
                        "Block suspicious domains",
                        "Implement DNS query length limits",
                        "Monitor for data exfiltration patterns"
                    ]
                )
                
                self.detected_threats.append(threat)
    
    async def _analyze_behavioral_threats(self, network_entities: Dict[str, Any]):
        """Analyze behavioral patterns for anomalies"""
        
        logger.info("Analyzing behavioral patterns...")
        
        hosts = network_entities.get('hosts', {})
        connections = network_entities.get('connections', [])
        
        # Build behavioral baselines
        await self._build_behavioral_baselines(hosts, connections)
        
        # Detect anomalies
        await self._detect_behavioral_anomalies(hosts, connections)
        
        # Temporal pattern analysis
        await self._analyze_temporal_patterns(connections)
    
    async def _build_behavioral_baselines(self, hosts: Dict, connections: List):
        """Build behavioral baselines for hosts and network"""
        
        # Host communication patterns
        for ip, host_data in hosts.items():
            communication_partners = host_data.get('communication_partners', set())
            packet_count = host_data.get('packet_count', 0)
            protocols_used = host_data.get('protocols', set())
            
            self.behavioral_baselines[ip] = {
                'normal_partners': len(communication_partners),
                'normal_traffic_volume': packet_count,
                'normal_protocols': protocols_used,
                'activity_pattern': 'baseline'  # Would be learned over time
            }
        
        # Network-wide patterns
        connection_rates = [1 for _ in connections]  # Simplified
        if connection_rates:
            self.behavioral_baselines['network'] = {
                'normal_connection_rate': np.mean(connection_rates),
                'connection_rate_stddev': np.std(connection_rates)
            }
    
    async def _detect_behavioral_anomalies(self, hosts: Dict, connections: List):
        """Detect behavioral anomalies using statistical analysis"""
        
        for ip, host_data in hosts.items():
            baseline = self.behavioral_baselines.get(ip, {})
            
            if not baseline:
                continue
            
            # Analyze communication patterns
            current_partners = len(host_data.get('communication_partners', set()))
            normal_partners = baseline.get('normal_partners', 0)
            
            # Statistical significance test
            if normal_partners > 0:
                deviation = abs(current_partners - normal_partners) / normal_partners
                
                if deviation > 2.0:  # More than 200% deviation
                    anomaly = BehavioralAnomaly(
                        anomaly_id=hashlib.sha256(f"comm_anomaly_{ip}".encode()).hexdigest()[:16],
                        anomaly_type="unusual_communication_pattern",
                        confidence_score=min(0.95, deviation / 3.0),
                        statistical_significance=deviation,
                        baseline_deviation=deviation,
                        affected_entities=[ip],
                        temporal_pattern="persistent",
                        risk_assessment="MEDIUM" if deviation < 5.0 else "HIGH",
                        investigation_priority="MEDIUM"
                    )
                    
                    self.behavioral_anomalies.append(anomaly)
    
    async def _perform_vulnerability_assessment(self, network_entities: Dict[str, Any]):
        """Perform comprehensive vulnerability assessment"""
        
        logger.info("Performing vulnerability assessment...")
        
        services = network_entities.get('services', {})
        
        for service_key, service_data in services.items():
            service_name = service_data.get('service_name', 'Unknown')
            port = service_data.get('port', 0)
            host = service_data.get('host', 'Unknown')
            protocol = service_data.get('protocol', 'Unknown')
            
            # Check against vulnerability database
            await self._assess_service_vulnerabilities(service_name, port, host, protocol, service_data)
            
            # Configuration-based vulnerabilities
            await self._assess_configuration_vulnerabilities(service_data)
    
    async def _assess_service_vulnerabilities(self, service_name: str, port: int, host: str, protocol: str, service_data: Dict):
        """Assess vulnerabilities for specific service"""
        
        for vuln_key, vuln_info in self.vulnerability_database.items():
            # Check if this vulnerability applies to the service
            applies = False
            
            if port in vuln_info.get('ports', []):
                applies = True
            elif service_name.upper() in [s.upper() for s in vuln_info.get('affected_services', [])]:
                applies = True
            
            if applies:
                # Assess likelihood based on service configuration
                exploit_likelihood = self._assess_exploit_likelihood(service_data, vuln_info)
                
                if exploit_likelihood in ['HIGH', 'CRITICAL']:
                    assessment = VulnerabilityAssessment(
                        cve_id=vuln_info.get('cve_ids', [None])[0],
                        vulnerability_name=vuln_info['name'],
                        affected_service=f"{service_name} on {host}:{port}",
                        severity_score=vuln_info.get('severity', 5.0),
                        exploit_likelihood=exploit_likelihood,
                        impact_assessment=self._assess_vulnerability_impact(vuln_info, service_data),
                        remediation_priority=self._get_remediation_priority(vuln_info, exploit_likelihood),
                        technical_details={
                            'service': service_name,
                            'port': port,
                            'host': host,
                            'protocol': protocol,
                            'vulnerability_type': vuln_key,
                            'indicators': vuln_info.get('indicators', [])
                        },
                        references=vuln_info.get('cve_ids', [])
                    )
                    
                    self.vulnerability_assessments.append(assessment)
    
    def _assess_exploit_likelihood(self, service_data: Dict, vuln_info: Dict) -> str:
        """Assess the likelihood of successful exploitation"""
        
        indicators = vuln_info.get('indicators', [])
        risk_factors = 0
        
        # Check for vulnerability indicators in service data
        for indicator in indicators:
            if indicator in ['default_passwords', 'weak_authentication']:
                # Would check authentication mechanisms
                risk_factors += 2
            elif indicator in ['cleartext_auth', 'unencrypted_session']:
                # Check if encryption is used
                risk_factors += 1
            elif indicator in ['old_version', 'weak_ciphers']:
                # Would check version information
                risk_factors += 1
        
        # Network exposure factor
        clients = service_data.get('clients', [])
        if len(clients) > 10:  # Publicly accessible
            risk_factors += 1
        
        # Determine likelihood
        if risk_factors >= 4:
            return 'CRITICAL'
        elif risk_factors >= 3:
            return 'HIGH'
        elif risk_factors >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _assess_vulnerability_impact(self, vuln_info: Dict, service_data: Dict) -> str:
        """Assess the potential impact of vulnerability exploitation"""
        
        severity = vuln_info.get('severity', 5.0)
        service_criticality = self._assess_service_criticality(service_data)
        
        if severity >= 9.0 and service_criticality == 'CRITICAL':
            return 'Potential for complete system compromise and data breach'
        elif severity >= 7.0:
            return 'Significant security impact with potential for unauthorized access'
        elif severity >= 4.0:
            return 'Moderate security impact with limited unauthorized access'
        else:
            return 'Low security impact with minimal risk exposure'
    
    def _assess_service_criticality(self, service_data: Dict) -> str:
        """Assess criticality of a service"""
        
        service_name = service_data.get('service_name', '').upper()
        port = service_data.get('port', 0)
        clients = len(service_data.get('clients', []))
        
        # Critical services
        if service_name in ['SSH', 'RDP', 'DATABASE'] or port in [22, 3389, 1433, 3306]:
            return 'CRITICAL'
        
        # High-value services  
        if service_name in ['HTTP', 'HTTPS', 'FTP'] or port in [80, 443, 21]:
            return 'HIGH'
        
        # Public-facing services
        if clients > 20:
            return 'HIGH'
        elif clients > 5:
            return 'MEDIUM'
        
        return 'LOW'
    
    def _get_remediation_priority(self, vuln_info: Dict, exploit_likelihood: str) -> str:
        """Determine remediation priority"""
        
        severity = vuln_info.get('severity', 5.0)
        
        if exploit_likelihood == 'CRITICAL' or severity >= 9.0:
            return 'IMMEDIATE'
        elif exploit_likelihood == 'HIGH' or severity >= 7.0:
            return 'HIGH'
        elif exploit_likelihood == 'MEDIUM' or severity >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    async def _analyze_lateral_movement(self, network_entities: Dict[str, Any]):
        """Detect lateral movement patterns"""
        
        logger.info("Analyzing lateral movement patterns...")
        
        connections = network_entities.get('connections', [])
        hosts = network_entities.get('hosts', {})
        
        # Build network topology
        internal_hosts = [ip for ip, data in hosts.items() if data.get('is_internal')]
        
        # Analyze internal-to-internal connections
        internal_connections = []
        for conn in connections:
            source = conn.get('source_ip')
            dest = conn.get('dest_ip')
            
            if source in internal_hosts and dest in internal_hosts:
                internal_connections.append(conn)
        
        # Look for lateral movement patterns
        await self._detect_privilege_escalation_attempts(internal_connections, hosts)
        await self._detect_credential_reuse_patterns(internal_connections, hosts)
        await self._detect_administrative_tool_usage(internal_connections)
    
    async def _detect_data_exfiltration(self, network_entities: Dict[str, Any]):
        """Detect data exfiltration patterns"""
        
        logger.info("Analyzing data exfiltration patterns...")
        
        connections = network_entities.get('connections', [])
        hosts = network_entities.get('hosts', {})
        
        # Analyze outbound traffic patterns
        outbound_traffic = defaultdict(lambda: {'bytes': 0, 'connections': 0, 'destinations': set()})
        
        for conn in connections:
            source = conn.get('source_ip')
            dest = conn.get('dest_ip')
            bytes_transferred = conn.get('packet_size', 0)
            
            if source and dest:
                source_host = hosts.get(source, {})
                dest_host = hosts.get(dest, {})
                
                # Internal to external data transfers
                if source_host.get('is_internal') and not dest_host.get('is_internal'):
                    outbound_traffic[source]['bytes'] += bytes_transferred
                    outbound_traffic[source]['connections'] += 1
                    outbound_traffic[source]['destinations'].add(dest)
        
        # Detect suspicious outbound patterns
        for source_ip, traffic_data in outbound_traffic.items():
            bytes_total = traffic_data['bytes']
            dest_count = len(traffic_data['destinations'])
            
            # Large data transfer threshold (100MB)
            if bytes_total > 100_000_000:
                confidence = min(0.9, bytes_total / 1_000_000_000)  # Scale to GB
                
                from pcap_processor import SecurityEvent
                threat = SecurityEvent(
                    event_id=hashlib.sha256(f"data_exfil_{source_ip}".encode()).hexdigest()[:16],
                    event_type="data_exfiltration",
                    severity="HIGH",
                    timestamp=datetime.now().timestamp(),
                    source_ip=source_ip,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    protocol="Mixed",
                    description=f"Large outbound data transfer detected: {bytes_total:,} bytes to {dest_count} destinations",
                    evidence={
                        'bytes_transferred': bytes_total,
                        'destination_count': dest_count,
                        'destinations': list(traffic_data['destinations'])[:10],
                        'connection_count': traffic_data['connections']
                    },
                    attack_category="DATA_EXFILTRATION", 
                    confidence_score=confidence,
                    remediation=[
                        "Investigate data access patterns",
                        "Implement data loss prevention (DLP)",
                        "Monitor file access and transfers",
                        "Review user access privileges",
                        "Network egress monitoring"
                    ]
                )
                
                self.detected_threats.append(threat)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Calculate character frequency
        char_freq = Counter(text)
        text_len = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in char_freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    async def _generate_risk_assessment(self, network_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive risk assessment"""
        
        # Calculate overall risk score
        threat_risk = len(self.detected_threats) * 10
        vuln_risk = sum(v.severity_score for v in self.vulnerability_assessments)
        anomaly_risk = len(self.behavioral_anomalies) * 5
        
        total_risk = threat_risk + vuln_risk + anomaly_risk
        normalized_risk = min(100, total_risk)
        
        # Risk categorization
        if normalized_risk >= 80:
            risk_level = "CRITICAL"
        elif normalized_risk >= 60:
            risk_level = "HIGH"
        elif normalized_risk >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Business impact assessment
        business_impact = self._assess_business_impact(network_entities)
        
        return {
            'overall_risk_score': normalized_risk,
            'risk_level': risk_level, 
            'threat_contribution': threat_risk,
            'vulnerability_contribution': vuln_risk,
            'anomaly_contribution': anomaly_risk,
            'business_impact': business_impact,
            'risk_factors': self._identify_risk_factors(),
            'mitigation_timeline': self._generate_mitigation_timeline()
        }
    
    def _assess_business_impact(self, network_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Assess potential business impact"""
        
        hosts = network_entities.get('hosts', {})
        critical_systems = len([h for h in hosts.values() if h.get('is_internal')])
        
        # Impact categories
        if len(self.detected_threats) >= 10:
            availability_impact = "HIGH"
        elif len(self.detected_threats) >= 5:
            availability_impact = "MEDIUM"
        else:
            availability_impact = "LOW"
        
        if any(t.severity == "CRITICAL" for t in self.detected_threats):
            confidentiality_impact = "HIGH"
        elif any(t.severity == "HIGH" for t in self.detected_threats):
            confidentiality_impact = "MEDIUM"
        else:
            confidentiality_impact = "LOW"
        
        return {
            'availability_impact': availability_impact,
            'confidentiality_impact': confidentiality_impact,
            'integrity_impact': confidentiality_impact,  # Simplified
            'estimated_downtime': self._estimate_downtime(),
            'compliance_impact': self._assess_compliance_impact()
        }
    
    def _calculate_threat_statistics(self) -> Dict[str, Any]:
        """Calculate threat detection statistics"""
        
        severity_counts = Counter(t.severity for t in self.detected_threats)
        category_counts = Counter(t.attack_category for t in self.detected_threats)
        
        return {
            'total_threats': len(self.detected_threats),
            'severity_distribution': dict(severity_counts),
            'category_distribution': dict(category_counts),
            'average_confidence': np.mean([t.confidence_score for t in self.detected_threats]) if self.detected_threats else 0,
            'high_confidence_threats': len([t for t in self.detected_threats if t.confidence_score >= 0.8])
        }
    
    def _generate_security_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized security recommendations"""
        
        recommendations = []
        
        # Based on detected threats
        threat_types = set(t.event_type for t in self.detected_threats)
        
        for threat_type in threat_types:
            if 'sql_injection' in threat_type:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Application Security',
                    'recommendation': 'Implement parameterized queries and input validation',
                    'timeline': 'Immediate',
                    'effort': 'Medium'
                })
            
            elif 'port_scanning' in threat_type:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Network Security',
                    'recommendation': 'Deploy network intrusion detection system',
                    'timeline': '1-2 weeks',
                    'effort': 'High'
                })
            
            elif 'dns_tunneling' in threat_type:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Network Security', 
                    'recommendation': 'Implement DNS monitoring and filtering',
                    'timeline': 'Immediate',
                    'effort': 'Medium'
                })
        
        # Based on vulnerabilities
        if self.vulnerability_assessments:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Vulnerability Management',
                'recommendation': 'Patch identified vulnerabilities immediately',
                'timeline': 'Immediate',
                'effort': 'Low'
            })
        
        return recommendations
    
    def _identify_risk_factors(self) -> List[str]:
        """Identify primary risk factors"""
        
        factors = []
        
        if len(self.detected_threats) > 5:
            factors.append("Multiple active threats detected")
        
        if any(t.severity == "CRITICAL" for t in self.detected_threats):
            factors.append("Critical severity threats present")
        
        if len(self.vulnerability_assessments) > 3:
            factors.append("Multiple vulnerabilities identified")
        
        return factors
    
    def _generate_mitigation_timeline(self) -> Dict[str, List[str]]:
        """Generate mitigation timeline"""
        
        return {
            'immediate': [
                "Address critical security events",
                "Patch high-severity vulnerabilities",
                "Implement emergency access controls"
            ],
            'short_term': [
                "Deploy additional security monitoring",
                "Update security policies",
                "Conduct security training"
            ],
            'long_term': [
                "Comprehensive security architecture review",
                "Regular penetration testing",
                "Security awareness program"
            ]
        }
    
    def _estimate_downtime(self) -> str:
        """Estimate potential downtime from threats"""
        
        critical_threats = len([t for t in self.detected_threats if t.severity == "CRITICAL"])
        
        if critical_threats >= 3:
            return "24-48 hours"
        elif critical_threats >= 1:
            return "4-24 hours"
        else:
            return "< 4 hours"
    
    def _assess_compliance_impact(self) -> str:
        """Assess impact on regulatory compliance"""
        
        # Simplified compliance assessment
        if any('data_exfiltration' in t.event_type for t in self.detected_threats):
            return "HIGH - Potential data breach requiring notification"
        elif len(self.detected_threats) > 0:
            return "MEDIUM - Security incidents requiring documentation"
        else:
            return "LOW - No compliance violations identified"

    # Additional helper methods for specific threat types...
    async def _detect_privilege_escalation_attempts(self, connections: List, hosts: Dict):
        """Detect privilege escalation attempts"""
        # Implementation would analyze administrative service access patterns
        pass
    
    async def _detect_credential_reuse_patterns(self, connections: List, hosts: Dict):
        """Detect credential reuse across multiple systems"""
        # Implementation would analyze authentication patterns
        pass
    
    async def _detect_administrative_tool_usage(self, connections: List):
        """Detect usage of administrative tools (PSExec, WMI, etc.)"""
        # Implementation would look for known admin tool signatures
        pass
    
    async def _analyze_connection_patterns(self, connections: List):
        """Analyze suspicious connection patterns"""
        # Implementation would look for abnormal connection behaviors
        pass
    
    async def _detect_network_reconnaissance(self, hosts: Dict, connections: List):
        """Detect network reconnaissance activities"""
        # Implementation would analyze scanning and enumeration patterns
        pass
    
    async def _analyze_temporal_patterns(self, connections: List):
        """Analyze temporal patterns for anomalies"""
        # Implementation would analyze time-based patterns
        pass
    
    async def _detect_malicious_domains(self, query: str, requester: str, dns_data: Dict):
        """Detect connections to malicious domains"""
        # Implementation would check against threat intelligence feeds
        pass
    
    async def _detect_dns_cache_poisoning(self, dns_data: Dict):
        """Detect DNS cache poisoning attempts"""
        # Implementation would analyze DNS response inconsistencies
        pass
    
    async def _analyze_email_threats(self, network_entities: Dict[str, Any]):
        """Analyze email-based threats"""
        # Implementation would analyze SMTP/POP3/IMAP traffic
        pass
    
    async def _analyze_file_transfer_threats(self, file_transfers: Dict):
        """Analyze file transfer patterns for threats"""
        # Implementation would analyze FTP/SFTP/HTTP file transfers
        pass
    
    async def _assess_configuration_vulnerabilities(self, service_data: Dict):
        """Assess configuration-based vulnerabilities"""
        # Implementation would analyze service configurations
        pass