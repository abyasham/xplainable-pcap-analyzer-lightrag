"""
Enhanced PCAP Processor for Security Analysis
Supports deep packet inspection and advanced security detection
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls import TLS
import asyncio
import hashlib
import json
import re
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import ipaddress
import logging

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Represents a security event detected in network traffic"""
    event_id: str
    event_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    timestamp: float
    source_ip: Optional[str]
    dest_ip: Optional[str]
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    description: str
    evidence: Dict[str, Any]
    attack_category: str
    confidence_score: float
    remediation: List[str]

class AdvancedPcapProcessor:
    """Advanced PCAP processor with comprehensive security analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.packets = []
        self.network_entities = {
            'hosts': {},
            'services': {},
            'protocols': {},
            'connections': [],
            'security_events': [],
            'dns_records': {},
            'arp_table': {},
            'tls_sessions': {},
            'http_sessions': {},
            'file_transfers': {},
            'malware_indicators': {},
            'network_flows': {}
        }
        
        # Security detection rules
        self.attack_patterns = self._load_attack_patterns()
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        
        # Statistical tracking
        self.packet_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load attack pattern definitions"""
        return {
            'port_scan': {
                'pattern': 'multiple_ports_single_source',
                'threshold': 10,
                'time_window': 60
            },
            'ddos': {
                'pattern': 'high_volume_single_target',
                'threshold': 1000,
                'time_window': 10
            },
            'brute_force': {
                'pattern': 'multiple_login_attempts',
                'threshold': 10,
                'ports': [21, 22, 23, 3389, 443]
            },
            'dns_tunneling': {
                'pattern': 'suspicious_dns_queries',
                'indicators': ['long_subdomain', 'base64_patterns', 'high_entropy']
            },
            'arp_poisoning': {
                'pattern': 'arp_reply_anomalies',
                'indicators': ['mac_ip_conflicts', 'gratuitous_arps']
            },
            'sql_injection': {
                'pattern': 'malicious_http_payloads',
                'signatures': ['union select', '1=1', 'drop table', 'xp_cmdshell']
            },
            'command_injection': {
                'pattern': 'shell_command_payloads',
                'signatures': ['|nc ', ';cat ', '`whoami`', '$(id)']
            },
            'data_exfiltration': {
                'pattern': 'large_outbound_transfers',
                'threshold': 10485760,  # 10MB
                'protocols': ['HTTP', 'HTTPS', 'FTP', 'DNS']
            }
        }
    
    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures"""
        return {
            'cve_2017_0144': {  # EternalBlue
                'name': 'EternalBlue SMB Exploit',
                'ports': [445],
                'protocols': ['SMB'],
                'patterns': [b'\\x00\\x00\\x00\\x2f\\xff\\x53\\x4d\\x42\\x72']
            },
            'cve_2014_0160': {  # Heartbleed
                'name': 'Heartbleed OpenSSL Vulnerability',
                'ports': [443],
                'protocols': ['TLS'],
                'patterns': [b'\\x18\\x03', b'\\x01\\x00\\x40\\x00']
            },
            'cve_2019_0708': {  # BlueKeep
                'name': 'BlueKeep RDP Vulnerability',
                'ports': [3389],
                'protocols': ['RDP'],
                'patterns': [b'\\x03\\x00\\x00\\x13\\x0e\\xe0']
            }
        }
    
    async def process_pcap_file(self, pcap_path: str) -> Dict[str, Any]:
        """Process PCAP file with comprehensive security analysis"""
        logger.info(f"Starting analysis of PCAP file: {pcap_path}")
        
        try:
            # Load PCAP
            self.packets = scapy.rdpcap(pcap_path)
            logger.info(f"Loaded {len(self.packets)} packets")
            
            # Process packets in chunks for better performance
            chunk_size = self.config.get('pcap', {}).get('chunk_size', 1000)
            total_packets = len(self.packets)
            
            for i in range(0, total_packets, chunk_size):
                chunk = self.packets[i:i + chunk_size]
                await self._process_packet_chunk(chunk, i)
                
                # Progress update
                progress = min(100, (i + chunk_size) / total_packets * 100)
                logger.info(f"Processing progress: {progress:.1f}%")
            
            # Perform advanced analysis
            await self._advanced_security_analysis()
            
            # Generate analysis summary
            analysis_summary = self._generate_analysis_summary()
            
            logger.info("PCAP analysis completed successfully")
            return {
                'network_entities': self.network_entities,
                'analysis_summary': analysis_summary,
                'packet_statistics': dict(self.packet_stats),
                'protocol_statistics': dict(self.protocol_stats)
            }
            
        except Exception as e:
            logger.error(f"PCAP processing failed: {e}")
            raise
    
    async def _process_packet_chunk(self, packets: List, chunk_start: int):
        """Process a chunk of packets"""
        
        for idx, packet in enumerate(packets):
            packet_idx = chunk_start + idx
            timestamp = float(packet.time) if hasattr(packet, 'time') else packet_idx
            
            try:
                # Basic packet analysis
                self._analyze_packet_layers(packet, packet_idx, timestamp)
                
                # Protocol-specific analysis
                if packet.haslayer(IP):
                    await self._analyze_ip_layer(packet, timestamp)
                
                if packet.haslayer(TCP):
                    await self._analyze_tcp_layer(packet, timestamp)
                    
                if packet.haslayer(UDP):
                    await self._analyze_udp_layer(packet, timestamp)
                
                if packet.haslayer(DNS):
                    await self._analyze_dns_layer(packet, timestamp)
                    
                if packet.haslayer(HTTP):
                    await self._analyze_http_layer(packet, timestamp)
                    
                if packet.haslayer(TLS):
                    await self._analyze_tls_layer(packet, timestamp)
                    
                if packet.haslayer(ARP):
                    await self._analyze_arp_layer(packet, timestamp)
                
                # Real-time threat detection
                await self._detect_threats_in_packet(packet, timestamp)
                
            except Exception as e:
                logger.warning(f"Error processing packet {packet_idx}: {e}")
                continue
    
    def _analyze_packet_layers(self, packet, packet_idx: int, timestamp: float):
        """Analyze packet layers and update statistics"""
        
        packet_size = len(packet)
        self.packet_stats['total_packets'] += 1
        self.packet_stats['total_bytes'] += packet_size
        
        # Layer analysis
        layer_names = []
        layer = packet
        while layer:
            layer_name = layer.__class__.__name__
            layer_names.append(layer_name)
            self.protocol_stats[layer_name] += 1
            layer = layer.payload if hasattr(layer, 'payload') and layer.payload else None
        
        # Store packet metadata
        packet_info = {
            'packet_idx': packet_idx,
            'timestamp': timestamp,
            'size': packet_size,
            'layers': layer_names
        }
        
        return packet_info
    
    async def _analyze_ip_layer(self, packet, timestamp: float):
        """Comprehensive IP layer analysis"""
        
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        
        # Update host entities
        for ip_addr in [src_ip, dst_ip]:
            if ip_addr not in self.network_entities['hosts']:
                self.network_entities['hosts'][ip_addr] = {
                    'ip_address': ip_addr,
                    'first_seen': timestamp,
                    'last_seen': timestamp,
                    'packet_count': 0,
                    'bytes_total': 0,
                    'protocols': set(),
                    'ports_contacted': set(),
                    'geographic_info': self._get_geographic_info(ip_addr),
                    'reputation': await self._check_ip_reputation(ip_addr),
                    'is_internal': self._is_internal_ip(ip_addr),
                    'communication_partners': set(),
                    'suspicious_activities': [],
                    'services_offered': set(),
                    'vulnerabilities': []
                }
        
        # Update host statistics
        host_src = self.network_entities['hosts'][src_ip]
        host_dst = self.network_entities['hosts'][dst_ip]
        
        host_src['last_seen'] = timestamp
        host_src['packet_count'] += 1
        host_src['bytes_total'] += len(packet)
        host_src['communication_partners'].add(dst_ip)
        
        host_dst['communication_partners'].add(src_ip)
        
        # Record connection
        connection = {
            'timestamp': timestamp,
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'protocol': ip.proto,
            'packet_size': len(packet),
            'ttl': ip.ttl,
            'flags': ip.flags if hasattr(ip, 'flags') else 0,
            'connection_type': 'ip_communication'
        }
        
        self.network_entities['connections'].append(connection)
    
    async def _analyze_tcp_layer(self, packet, timestamp: float):
        """Advanced TCP layer analysis"""
        
        tcp = packet[TCP]
        ip = packet[IP]
        
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = tcp.flags
        
        # Service identification
        service_info = self._identify_service(dst_port, 'tcp')
        
        # TCP session tracking
        session_key = f"{ip.src}:{src_port}-{ip.dst}:{dst_port}"
        
        if session_key not in self.network_entities['tcp_sessions']:
            self.network_entities['tcp_sessions'][session_key] = {
                'source_ip': ip.src,
                'dest_ip': ip.dst,
                'source_port': src_port,
                'dest_port': dst_port,
                'service': service_info,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'packet_count': 0,
                'bytes_transferred': 0,
                'flags_seen': set(),
                'session_state': 'UNKNOWN',
                'payload_data': [],
                'security_flags': []
            }
        
        session = self.network_entities['tcp_sessions'][session_key]
        session['last_seen'] = timestamp
        session['packet_count'] += 1
        session['bytes_transferred'] += len(packet)
        session['flags_seen'].add(flags)
        
        # TCP state analysis
        if flags & 0x02:  # SYN
            session['session_state'] = 'SYN_SENT'
        elif flags & 0x12:  # SYN-ACK
            session['session_state'] = 'SYN_RECEIVED'
        elif flags & 0x10:  # ACK
            if session['session_state'] == 'SYN_RECEIVED':
                session['session_state'] = 'ESTABLISHED'
        elif flags & 0x01:  # FIN
            session['session_state'] = 'CLOSING'
        elif flags & 0x04:  # RST
            session['session_state'] = 'RESET'
        
        # Payload analysis
        if tcp.payload:
            payload = bytes(tcp.payload)
            await self._analyze_tcp_payload(payload, session, timestamp)
        
        # Port scanning detection
        await self._detect_port_scanning(ip.src, dst_port, timestamp)
        
    async def _analyze_dns_layer(self, packet, timestamp: float):
        """Comprehensive DNS analysis with threat detection"""
        
        dns = packet[DNS]
        ip = packet[IP]
        
        # DNS query analysis
        if dns.qd:
            query_name = dns.qd.qname.decode('utf-8').rstrip('.')
            query_type = dns.qd.qtype
            
            dns_record = {
                'query': query_name,
                'query_type': query_type,
                'requester': ip.src,
                'timestamp': timestamp,
                'response_code': dns.rcode if hasattr(dns, 'rcode') else 0,
                'answers': [],
                'suspicious_indicators': []
            }
            
            # DNS tunneling detection
            await self._detect_dns_tunneling(query_name, dns_record)
            
            # Malicious domain detection
            await self._detect_malicious_domains(query_name, dns_record)
            
            # DNS response analysis
            if dns.an:
                for answer in dns.an:
                    if hasattr(answer, 'rdata'):
                        dns_record['answers'].append({
                            'type': answer.type,
                            'data': str(answer.rdata),
                            'ttl': answer.ttl
                        })
            
            record_key = f"{query_name}:{query_type}"
            self.network_entities['dns_records'][record_key] = dns_record
    
    async def _analyze_http_layer(self, packet, timestamp: float):
        """HTTP traffic analysis for security threats"""
        
        http = packet[HTTP]
        ip = packet[IP]
        tcp = packet[TCP]
        
        if isinstance(http, HTTPRequest):
            await self._analyze_http_request(http, ip, tcp, timestamp)
        elif isinstance(http, HTTPResponse):
            await self._analyze_http_response(http, ip, tcp, timestamp)
    
    async def _analyze_http_request(self, http, ip, tcp, timestamp):
        """Analyze HTTP request for security threats"""
        
        method = http.Method.decode() if hasattr(http, 'Method') else 'UNKNOWN'
        path = http.Path.decode() if hasattr(http, 'Path') else '/'
        host = http.Host.decode() if hasattr(http, 'Host') else ip.dst
        
        request_data = {
            'timestamp': timestamp,
            'source_ip': ip.src,
            'dest_ip': ip.dst,
            'method': method,
            'path': path,
            'host': host,
            'user_agent': '',
            'headers': {},
            'payload': '',
            'security_flags': []
        }
        
        # Extract headers
        if hasattr(http, 'headers'):
            for header in http.headers:
                if hasattr(header, 'name') and hasattr(header, 'value'):
                    header_name = header.name.decode()
                    header_value = header.value.decode()
                    request_data['headers'][header_name] = header_value
                    
                    if header_name.lower() == 'user-agent':
                        request_data['user_agent'] = header_value
        
        # Payload analysis
        if hasattr(http, 'load'):
            request_data['payload'] = http.load.decode('utf-8', errors='ignore')
        
        # Security analysis
        await self._detect_web_attacks(request_data)
        
        session_key = f"http_{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
        if session_key not in self.network_entities['http_sessions']:
            self.network_entities['http_sessions'][session_key] = []
        
        self.network_entities['http_sessions'][session_key].append(request_data)
    
    async def _detect_web_attacks(self, request_data: Dict):
        """Detect web-based attacks in HTTP requests"""
        
        path = request_data.get('path', '')
        payload = request_data.get('payload', '')
        headers = request_data.get('headers', {})
        
        # SQL Injection detection
        sql_patterns = [
            r"'.*union.*select", r"1=1", r"drop\s+table", r"xp_cmdshell",
            r"sp_executesql", r"exec\s*\(", r";\s*shutdown", r"benchmark\s*\("
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, path + payload, re.IGNORECASE):
                await self._create_security_event(
                    event_type="sql_injection_attempt",
                    severity="HIGH",
                    source_ip=request_data['source_ip'],
                    dest_ip=request_data['dest_ip'],
                    description=f"SQL injection pattern detected: {pattern}",
                    evidence={'pattern': pattern, 'path': path, 'payload': payload[:500]},
                    timestamp=request_data['timestamp']
                )
        
        # XSS detection
        xss_patterns = [
            r"<script", r"javascript:", r"onload=", r"onerror=",
            r"alert\s*\(", r"document\.cookie", r"eval\s*\("
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, path + payload, re.IGNORECASE):
                await self._create_security_event(
                    event_type="xss_attempt",
                    severity="MEDIUM",
                    source_ip=request_data['source_ip'],
                    dest_ip=request_data['dest_ip'],
                    description=f"Cross-site scripting pattern detected: {pattern}",
                    evidence={'pattern': pattern, 'path': path, 'payload': payload[:500]},
                    timestamp=request_data['timestamp']
                )
        
        # Command injection detection
        cmd_patterns = [
            r";\s*cat\s", r"\|.*nc\s", r"`.*whoami.*`", r"\$\(.*id.*\)",
            r"&&\s*ls", r";\s*wget", r"\|.*curl"
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, path + payload, re.IGNORECASE):
                await self._create_security_event(
                    event_type="command_injection_attempt",
                    severity="HIGH",
                    source_ip=request_data['source_ip'],
                    dest_ip=request_data['dest_ip'],
                    description=f"Command injection pattern detected: {pattern}",
                    evidence={'pattern': pattern, 'path': path, 'payload': payload[:500]},
                    timestamp=request_data['timestamp']
                )
    
    async def _detect_dns_tunneling(self, query_name: str, dns_record: Dict):
        """Detect DNS tunneling attempts"""
        
        indicators = []
        
        # Long subdomain detection
        if len(query_name) > 100:
            indicators.append('extremely_long_domain')
        
        # High entropy detection (Base64/encoded data)
        entropy = self._calculate_entropy(query_name)
        if entropy > 4.5:
            indicators.append('high_entropy_domain')
        
        # Suspicious TLD patterns
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit']
        for tld in suspicious_tlds:
            if query_name.endswith(tld):
                indicators.append('suspicious_tld')
        
        # Base64 pattern detection
        if re.search(r'^[A-Za-z0-9+/=]{20,}', query_name.split('.')[0]):
            indicators.append('base64_pattern')
        
        if indicators:
            dns_record['suspicious_indicators'] = indicators
            
            await self._create_security_event(
                event_type="dns_tunneling_attempt",
                severity="MEDIUM",
                source_ip=dns_record['requester'],
                description=f"DNS tunneling indicators detected: {', '.join(indicators)}",
                evidence={
                    'domain': query_name,
                    'indicators': indicators,
                    'entropy': entropy
                },
                timestamp=dns_record['timestamp']
            )
    
    async def _detect_port_scanning(self, source_ip: str, dest_port: int, timestamp: float):
        """Detect port scanning activities"""
        
        # Track port access per source
        scan_key = f"scan_{source_ip}"
        
        if scan_key not in self.network_entities['scan_tracking']:
            self.network_entities['scan_tracking'] = {}
        
        if scan_key not in self.network_entities['scan_tracking']:
            self.network_entities['scan_tracking'][scan_key] = {
                'source_ip': source_ip,
                'ports_contacted': set(),
                'timestamps': [],
                'targets': set()
            }
        
        scan_info = self.network_entities['scan_tracking'][scan_key]
        scan_info['ports_contacted'].add(dest_port)
        scan_info['timestamps'].append(timestamp)
        
        # Port scan detection logic
        if len(scan_info['ports_contacted']) > 20:  # More than 20 ports
            time_window = max(scan_info['timestamps']) - min(scan_info['timestamps'])
            
            if time_window < 60:  # In less than 1 minute
                await self._create_security_event(
                    event_type="port_scanning",
                    severity="MEDIUM",
                    source_ip=source_ip,
                    description=f"Port scanning detected: {len(scan_info['ports_contacted'])} ports in {time_window:.1f} seconds",
                    evidence={
                        'ports_scanned': list(scan_info['ports_contacted']),
                        'time_window': time_window,
                        'scan_rate': len(scan_info['ports_contacted']) / time_window
                    },
                    timestamp=timestamp
                )
    
    async def _create_security_event(self, event_type: str, severity: str, 
                                   source_ip: str = None, dest_ip: str = None,
                                   source_port: int = None, dest_port: int = None,
                                   protocol: str = 'UNKNOWN', description: str = '',
                                   evidence: Dict = None, timestamp: float = None,
                                   attack_category: str = 'UNKNOWN',
                                   confidence_score: float = 0.8,
                                   remediation: List[str] = None):
        """Create a comprehensive security event"""
        
        if evidence is None:
            evidence = {}
        
        if remediation is None:
            remediation = []
        
        event_id = hashlib.sha256(
            f"{event_type}{timestamp}{source_ip}{dest_ip}".encode()
        ).hexdigest()[:16]
        
        security_event = SecurityEvent(
            event_id=event_id,
            event_type=event_type,
            severity=severity,
            timestamp=timestamp or datetime.now().timestamp(),
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            description=description,
            evidence=evidence,
            attack_category=attack_category,
            confidence_score=confidence_score,
            remediation=remediation
        )
        
        self.network_entities['security_events'].append(security_event)
        
        logger.warning(f"Security event detected: {event_type} - {description}")
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = Counter(text)
        text_len = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP address is internal/private"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private
        except:
            return False
    
    def _get_geographic_info(self, ip_str: str) -> Dict[str, str]:
        """Get geographic information for IP address"""
        # Placeholder for GeoIP integration
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'asn': 'Unknown'
        }
    
    async def _check_ip_reputation(self, ip_str: str) -> str:
        """Check IP reputation against threat intelligence"""
        # Placeholder for threat intelligence integration
        return 'unknown'
    
    def _identify_service(self, port: int, protocol: str) -> Dict[str, str]:
        """Identify service based on port and protocol"""
        services = {
            'tcp': {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
                995: 'POP3S', 3389: 'RDP', 445: 'SMB', 139: 'NetBIOS', 135: 'RPC'
            },
            'udp': {
                53: 'DNS', 67: 'DHCP_Server', 68: 'DHCP_Client', 69: 'TFTP',
                123: 'NTP', 161: 'SNMP', 514: 'Syslog', 1194: 'OpenVPN'
            }
        }
        
        service_name = services.get(protocol, {}).get(port, f'Port_{port}')
        
        return {
            'name': service_name,
            'port': port,
            'protocol': protocol.upper(),
            'risk_level': self._assess_service_risk(service_name, port)
        }
    
    def _assess_service_risk(self, service_name: str, port: int) -> str:
        """Assess security risk level of a service"""
        high_risk_services = ['FTP', 'Telnet', 'HTTP', 'SMB', 'RPC']
        medium_risk_services = ['SSH', 'SMTP', 'POP3', 'IMAP']
        
        if service_name in high_risk_services:
            return 'HIGH'
        elif service_name in medium_risk_services:
            return 'MEDIUM'
        elif port > 49152:  # Dynamic/ephemeral ports
            return 'LOW'
        else:
            return 'MEDIUM'
    
    async def _advanced_security_analysis(self):
        """Perform advanced security analysis on collected data"""
        
        logger.info("Performing advanced security analysis...")
        
        # Behavioral analysis
        await self._analyze_communication_patterns()
        await self._detect_data_exfiltration()
        await self._analyze_protocol_anomalies()
        await self._detect_lateral_movement()
        
        # Statistical analysis
        await self._statistical_anomaly_detection()
        
        logger.info("Advanced security analysis completed")
    
    async def _analyze_communication_patterns(self):
        """Analyze communication patterns for anomalies"""
        
        # Analyze traffic flows
        flow_stats = defaultdict(lambda: {'packet_count': 0, 'byte_count': 0})
        
        for connection in self.network_entities['connections']:
            flow_key = f"{connection['source_ip']}->{connection['dest_ip']}"
            flow_stats[flow_key]['packet_count'] += 1
            flow_stats[flow_key]['byte_count'] += connection.get('packet_size', 0)
        
        # Detect unusual traffic patterns
        for flow_key, stats in flow_stats.items():
            if stats['byte_count'] > 100_000_000:  # >100MB
                source_ip, dest_ip = flow_key.split('->')
                await self._create_security_event(
                    event_type="large_data_transfer",
                    severity="MEDIUM",
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    description=f"Large data transfer detected: {stats['byte_count']:,} bytes",
                    evidence={'byte_count': stats['byte_count'], 'packet_count': stats['packet_count']},
                    attack_category="DATA_EXFILTRATION"
                )
    
    def _generate_analysis_summary(self) -> Dict[str, Any]:
        """Generate comprehensive analysis summary"""
        
        hosts = self.network_entities['hosts']
        security_events = self.network_entities['security_events']
        
        # Calculate security score
        security_score = 100
        critical_events = len([e for e in security_events if e.severity == 'CRITICAL'])
        high_events = len([e for e in security_events if e.severity == 'HIGH'])
        medium_events = len([e for e in security_events if e.severity == 'MEDIUM'])
        
        security_score -= critical_events * 30
        security_score -= high_events * 20
        security_score -= medium_events * 10
        security_score = max(0, security_score)
        
        return {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_packets': self.packet_stats['total_packets'],
            'total_bytes': self.packet_stats['total_bytes'],
            'analysis_duration': 'unknown',
            'hosts_discovered': len(hosts),
            'internal_hosts': len([h for h in hosts.values() if h['is_internal']]),
            'external_hosts': len([h for h in hosts.values() if not h['is_internal']]),
            'services_discovered': len(self.network_entities.get('services', {})),
            'protocols_detected': list(self.protocol_stats.keys()),
            'security_events': {
                'total': len(security_events),
                'critical': critical_events,
                'high': high_events,
                'medium': medium_events,
                'low': len([e for e in security_events if e.severity == 'LOW'])
            },
            'security_score': security_score,
            'risk_level': 'LOW' if security_score >= 80 else 'MEDIUM' if security_score >= 50 else 'HIGH',
            'top_threats': self._get_top_threats(),
            'recommendations': self._generate_recommendations()
        }
    
    def _get_top_threats(self) -> List[Dict[str, Any]]:
        """Get top security threats detected"""
        
        threat_counts = defaultdict(int)
        for event in self.network_entities['security_events']:
            threat_counts[event.event_type] += 1
        
        return [
            {'threat_type': threat, 'count': count}
            for threat, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        
        recommendations = []
        security_events = self.network_entities['security_events']
        
        if any(e.event_type == 'port_scanning' for e in security_events):
            recommendations.append("Implement network segmentation and intrusion detection systems")
        
        if any(e.event_type == 'sql_injection_attempt' for e in security_events):
            recommendations.append("Review web application security and implement input validation")
        
        if any(e.event_type == 'dns_tunneling_attempt' for e in security_events):
            recommendations.append("Implement DNS monitoring and filtering solutions")
        
        if any(e.event_type == 'large_data_transfer' for e in security_events):
            recommendations.append("Monitor for data exfiltration and implement DLP solutions")
        
        # Default recommendations
        recommendations.extend([
            "Regular security assessments and penetration testing",
            "Keep systems updated with latest security patches",
            "Implement comprehensive logging and monitoring",
            "Employee security awareness training"
        ])
        
        return recommendations