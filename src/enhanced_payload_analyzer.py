"""
Enhanced Payload Analyzer for Comprehensive Multi-Threat Detection
Provides advanced hexdump analysis with GPT-4o-mini integration for diverse attack detection
"""

import re
import json
import asyncio
import hashlib
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import binascii

logger = logging.getLogger(__name__)

@dataclass
class ThreatDetection:
    """Represents a detected threat in payload analysis"""
    attack_type: str
    severity: str
    confidence: float
    evidence: str
    description: str
    iso27001_control: str
    remediation: List[str]
    hex_offset: Optional[int] = None
    pattern_matched: Optional[str] = None

class EnhancedPayloadAnalyzer:
    """
    Advanced payload analysis with hexdump context for comprehensive threat detection
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threat_patterns = {
            'sql_injection': {
                'patterns': [
                    r'union\s+select', r'1\s*=\s*1', r'drop\s+table', r'xp_cmdshell',
                    r'information_schema', r'@@version', r'waitfor\s+delay',
                    r'exec\s*\(', r'sp_executesql', r'benchmark\s*\(',
                    r'or\s+1\s*=\s*1', r'and\s+1\s*=\s*1', r'having\s+1\s*=\s*1',
                    r'order\s+by\s+\d+', r'group\s+by\s+\d+', r'union\s+all\s+select'
                ],
                'hex_signatures': [
                    b'\x27\x20\x75\x6e\x69\x6f\x6e',  # ' union
                    b'\x31\x3d\x31',                   # 1=1
                    b'\x27\x20\x6f\x72\x20\x27',      # ' or '
                    b'\x22\x20\x6f\x72\x20\x22'       # " or "
                ],
                'iso_control': 'A.14.2.5 - Secure System Engineering Principles'
            },
            'xss': {
                'patterns': [
                    r'<script[^>]*>', r'javascript:', r'onload\s*=', r'onerror\s*=',
                    r'document\.cookie', r'alert\s*\(', r'eval\s*\(',
                    r'<iframe[^>]*>', r'<object[^>]*>', r'<embed[^>]*>',
                    r'<svg[^>]*onload', r'<img[^>]*onerror', r'<body[^>]*onload'
                ],
                'hex_signatures': [
                    b'\x3c\x73\x63\x72\x69\x70\x74',  # <script
                    b'\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74',  # javascript
                    b'\x3c\x69\x66\x72\x61\x6d\x65',  # <iframe
                    b'\x6f\x6e\x6c\x6f\x61\x64\x3d'   # onload=
                ],
                'iso_control': 'A.14.2.1 - Secure Development Policy'
            },
            'directory_traversal': {
                'patterns': [
                    r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
                    r'/etc/passwd', r'/windows/system32', r'boot\.ini',
                    r'\.\.%2f', r'\.\.%5c', r'..%252f', r'..%255c',
                    r'file://', r'php://filter', r'zip://'
                ],
                'hex_signatures': [
                    b'\x2e\x2e\x2f',      # ../
                    b'\x2e\x2e\x5c',      # ..\
                    b'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64',  # /etc/passwd
                    b'\x66\x69\x6c\x65\x3a\x2f\x2f'   # file://
                ],
                'iso_control': 'A.14.2.5 - Secure System Engineering Principles'
            },
            'token_injection': {
                'patterns': [
                    r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',  # JWT
                    r'bearer\s+[a-zA-Z0-9\-_]+', r'authorization:\s*bearer',
                    r'access_token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]+',
                    r'refresh_token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]+',
                    r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]+',
                    r'session[_-]?id["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]+'
                ],
                'hex_signatures': [
                    b'\x65\x79\x4a',      # eyJ (JWT header)
                    b'\x62\x65\x61\x72\x65\x72\x20',  # bearer 
                    b'\x61\x75\x74\x68\x6f\x72\x69\x7a\x61\x74\x69\x6f\x6e'  # authorization
                ],
                'iso_control': 'A.9.4.2 - Secure Log-on Procedures'
            },
            'zmq_vulnerability': {
                'patterns': [
                    r'zmq\.', r'zeromq', r'tcp://.*:\d+', r'ipc://',
                    r'inproc://', r'pgm://', r'epgm://',
                    r'zmq_socket', r'zmq_connect', r'zmq_bind',
                    r'zmq_send', r'zmq_recv', r'zmq_poll'
                ],
                'hex_signatures': [
                    b'\x7a\x6d\x71',      # zmq
                    b'\x74\x63\x70\x3a\x2f\x2f',  # tcp://
                    b'\x69\x70\x63\x3a\x2f\x2f',  # ipc://
                    b'\x7a\x65\x72\x6f\x6d\x71'   # zeromq
                ],
                'iso_control': 'A.13.1.1 - Network Controls'
            },
            'tls_issues': {
                'patterns': [
                    r'ssl.*error', r'tls.*error', r'certificate.*invalid',
                    r'handshake.*failed', r'cipher.*weak', r'sslv[23]',
                    r'tls.*1\.[01]', r'rc4', r'md5', r'sha1',
                    r'export.*cipher', r'null.*cipher'
                ],
                'hex_signatures': [
                    b'\x16\x03\x01',      # TLS 1.0
                    b'\x16\x03\x02',      # TLS 1.1
                    b'\x16\x03\x03',      # TLS 1.2
                    b'\x16\x03\x00',      # SSL 3.0
                    b'\x16\x02\x00'       # SSL 2.0
                ],
                'iso_control': 'A.13.2.1 - Information Transfer Policies'
            },
            'command_injection': {
                'patterns': [
                    r';\s*cat\s', r'\|\s*nc\s', r'`.*whoami.*`', r'\$\(.*id.*\)',
                    r'&&\s*ls', r';\s*wget', r'\|\s*curl', r'>\s*/dev/null',
                    r'&\s*echo', r';\s*sleep\s+\d+', r'\|\s*base64'
                ],
                'hex_signatures': [
                    b'\x3b\x20\x63\x61\x74\x20',  # ; cat 
                    b'\x7c\x20\x6e\x63\x20',      # | nc 
                    b'\x26\x26\x20\x6c\x73',      # && ls
                    b'\x60\x77\x68\x6f\x61\x6d\x69\x60'  # `whoami`
                ],
                'iso_control': 'A.14.2.5 - Secure System Engineering Principles'
            }
        }
        
        # Initialize LLM client
        self.openai_config = config.get('openai', {})
    
    async def analyze_payload_comprehensive(self, payload: bytes, packet_info: Dict) -> Dict[str, Any]:
        """
        Comprehensive payload analysis using enhanced hexdump representation
        """
        
        try:
            # Create enhanced hexdump with security context
            hexdump_analysis = self._create_security_focused_hexdump(payload, packet_info)
            
            # Pre-analysis pattern detection
            detected_patterns = self._detect_threat_patterns(payload)
            
            # Create comprehensive analysis prompt for GPT-4o-mini
            analysis_prompt = self._create_comprehensive_analysis_prompt(
                hexdump_analysis, detected_patterns, packet_info, payload
            )
            
            # Execute LLM analysis
            llm_result = await self._execute_llm_security_analysis(analysis_prompt)
            
            # Combine pattern detection with LLM analysis
            comprehensive_result = self._combine_analysis_results(
                detected_patterns, llm_result, hexdump_analysis
            )
            
            return comprehensive_result
            
        except Exception as e:
            logger.error(f"Payload analysis failed: {e}")
            return {
                'error': str(e),
                'threats_detected': [],
                'payload_classification': 'analysis_failed',
                'confidence': 0.0
            }
    
    def _create_security_focused_hexdump(self, payload: bytes, packet_info: Dict) -> Dict[str, Any]:
        """
        Create enhanced hexdump with security-focused annotations
        """
        
        hex_lines = []
        ascii_lines = []
        security_markers = []
        
        for i in range(0, len(payload), 16):
            chunk = payload[i:i+16]
            
            # Hex representation with security highlighting
            hex_parts = []
            for j, b in enumerate(chunk):
                hex_val = f'{b:02x}'
                
                # Highlight suspicious byte patterns
                if self._is_suspicious_byte(b, i + j, payload):
                    hex_val = f'[{hex_val}]'
                
                hex_parts.append(hex_val)
            
            hex_part = ' '.join(hex_parts).ljust(47)
            
            # ASCII representation with security markers
            ascii_part = ''
            for j, b in enumerate(chunk):
                if 32 <= b <= 126:
                    char = chr(b)
                    # Highlight potentially malicious characters
                    if char in '<>"\'&;|`$(){}[]%=':
                        ascii_part += f'[{char}]'
                        security_markers.append({
                            'offset': i + j,
                            'char': char,
                            'reason': 'suspicious_character'
                        })
                    else:
                        ascii_part += char
                else:
                    ascii_part += '.'
            
            offset = f'{i:08x}'
            hex_lines.append(f'{offset}: {hex_part} |{ascii_part}|')
            ascii_lines.append(ascii_part)
        
        return {
            'annotated_hexdump': '\n'.join(hex_lines),
            'security_annotated_ascii': ''.join(ascii_lines),
            'payload_size': len(payload),
            'security_markers': security_markers,
            'suspicious_byte_patterns': self._identify_suspicious_byte_patterns(payload),
            'entropy_analysis': self._calculate_payload_entropy(payload)
        }
    
    def _detect_threat_patterns(self, payload: bytes) -> Dict[str, List[Dict]]:
        """
        Detect threat patterns using both regex and hex signature matching
        """
        
        detected_threats = {}
        payload_str = payload.decode('utf-8', errors='ignore').lower()
        
        for threat_type, threat_data in self.threat_patterns.items():
            matches = []
            
            # Regex pattern matching
            for pattern in threat_data['patterns']:
                regex_matches = re.finditer(pattern, payload_str, re.IGNORECASE)
                for match in regex_matches:
                    matches.append({
                        'type': 'regex',
                        'pattern': pattern,
                        'match': match.group(),
                        'start': match.start(),
                        'end': match.end(),
                        'confidence': 0.8
                    })
            
            # Hex signature matching
            for hex_sig in threat_data['hex_signatures']:
                hex_matches = self._find_hex_pattern(payload, hex_sig)
                for offset in hex_matches:
                    matches.append({
                        'type': 'hex_signature',
                        'signature': hex_sig.hex(),
                        'offset': offset,
                        'confidence': 0.9
                    })
            
            if matches:
                detected_threats[threat_type] = {
                    'matches': matches,
                    'iso_control': threat_data['iso_control'],
                    'total_matches': len(matches)
                }
        
        return detected_threats
    
    def _create_comprehensive_analysis_prompt(self, hexdump_analysis: Dict, 
                                            detected_patterns: Dict, 
                                            packet_info: Dict, 
                                            payload: bytes) -> str:
        """
        Create comprehensive analysis prompt optimized for GPT-4o-mini
        """
        
        return f"""ADVANCED NETWORK SECURITY PAYLOAD ANALYSIS

PACKET METADATA:
- Flow: {packet_info.get('source_ip', 'unknown')}:{packet_info.get('source_port', 0)} → {packet_info.get('dest_ip', 'unknown')}:{packet_info.get('dest_port', 0)}
- Protocol: {packet_info.get('protocol', 'unknown')} | Layer: {packet_info.get('layer', 'unknown')}
- Payload Size: {len(payload)} bytes | Timestamp: {packet_info.get('timestamp', 'unknown')}
- Session Context: {packet_info.get('session_context', 'new_session')}

ENHANCED HEXDUMP ANALYSIS:
{hexdump_analysis['annotated_hexdump']}

ASCII INTERPRETATION WITH SECURITY MARKERS:
{hexdump_analysis['security_annotated_ascii']}

PRE-DETECTED THREAT PATTERNS:
{json.dumps(detected_patterns, indent=2)}

ENTROPY ANALYSIS:
- Payload Entropy: {hexdump_analysis['entropy_analysis']['overall_entropy']:.3f}
- High Entropy Regions: {len(hexdump_analysis['entropy_analysis']['high_entropy_regions'])}

COMPREHENSIVE THREAT ANALYSIS REQUIREMENTS:

Analyze this payload for ALL security threats. Focus on these attack categories:

1. **SQL Injection Attacks** (A.14.2.5)
   - Union-based, Boolean-based, Time-based, Error-based injections
   - Database fingerprinting and enumeration attempts
   - Stored procedure abuse and privilege escalation

2. **Cross-Site Scripting (XSS)** (A.14.2.1)
   - Reflected, Stored, DOM-based, and Blind XSS
   - Script injection via event handlers and attributes
   - Polyglot XSS payloads and filter bypass

3. **Directory Traversal & File Inclusion** (A.14.2.5)
   - Path traversal with various encoding techniques
   - Local and Remote File Inclusion (LFI/RFI)
   - Wrapper-based file access attempts

4. **Authentication & Token Attacks** (A.9.4.2)
   - JWT manipulation and algorithm confusion
   - Session token prediction and fixation
   - API key extraction and abuse

5. **Protocol-Specific Vulnerabilities**
   - ZeroMQ message queue exploitation (A.13.1.1)
   - TLS/SSL downgrade and cipher attacks (A.13.2.1)
   - Command injection and system exploitation (A.14.2.5)

6. **Advanced Persistent Threats**
   - Multi-stage attack indicators
   - Encoded/obfuscated payloads
   - Covert channel communications

RESPONSE FORMAT (JSON):
{{
    "threats_detected": [
        {{
            "attack_type": "specific_attack_name",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "confidence": 0.0-1.0,
            "evidence": "specific_hex_patterns_or_ascii_content",
            "description": "detailed_attack_description",
            "iso27001_control": "relevant_control_reference",
            "remediation": ["action1", "action2", "action3"],
            "hex_offset": "offset_in_payload",
            "attack_vector": "entry_point_description"
        }}
    ],
    "payload_classification": "malicious|suspicious|benign",
    "attack_chain_analysis": "multi_stage_attack_description",
    "context_preservation": "key_context_for_correlation",
    "overall_risk_score": 0.0-10.0,
    "compliance_violations": ["iso_control_1", "iso_control_2"]
}}

Provide detailed analysis focusing on attack context preservation for knowledge graph correlation."""
    
    async def _execute_llm_security_analysis(self, prompt: str) -> Dict[str, Any]:
        """
        Execute LLM analysis using GPT-4o-mini with security-focused configuration
        """
        
        try:
            from openai import AsyncOpenAI
            
            client = AsyncOpenAI(
                api_key=self.openai_config.get('api_key'),
                base_url="https://api.openai.com/v1"
            )
            
            response = await client.chat.completions.create(
                model=self.openai_config.get('model', 'gpt-4o-mini'),
                messages=[
                    {
                        "role": "system",
                        "content": """You are an expert cybersecurity analyst specializing in network traffic analysis and threat detection. 

Your expertise includes:
- Advanced payload analysis and attack pattern recognition
- Multi-vector threat detection and correlation
- ISO 27001 compliance assessment
- Network forensics and incident response

Analyze network payloads with extreme precision, focusing on:
1. Accurate threat classification with high confidence scores
2. Detailed evidence extraction from hexdump data
3. Attack context preservation for correlation analysis
4. Compliance violation identification
5. Actionable remediation recommendations

Always provide structured JSON responses with comprehensive threat analysis."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=self.openai_config.get('max_tokens', 4096),
                temperature=0.1,  # Low temperature for consistent analysis
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            return result
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {
                'threats_detected': [],
                'payload_classification': 'analysis_failed',
                'error': str(e)
            }
    
    def _combine_analysis_results(self, pattern_results: Dict, 
                                llm_results: Dict, 
                                hexdump_analysis: Dict) -> Dict[str, Any]:
        """
        Combine pattern detection results with LLM analysis
        """
        
        combined_threats = []
        
        # Add pattern-based detections
        for threat_type, pattern_data in pattern_results.items():
            for match in pattern_data['matches']:
                combined_threats.append(ThreatDetection(
                    attack_type=threat_type,
                    severity='MEDIUM',
                    confidence=match['confidence'],
                    evidence=match.get('match', match.get('signature', '')),
                    description=f"Pattern-based detection: {threat_type}",
                    iso27001_control=pattern_data['iso_control'],
                    remediation=[f"Investigate {threat_type} activity"],
                    hex_offset=match.get('offset'),
                    pattern_matched=match.get('pattern', match.get('signature'))
                ))
        
        # Add LLM-based detections
        llm_threats = llm_results.get('threats_detected', [])
        for threat in llm_threats:
            combined_threats.append(ThreatDetection(
                attack_type=threat.get('attack_type', 'unknown'),
                severity=threat.get('severity', 'MEDIUM'),
                confidence=threat.get('confidence', 0.5),
                evidence=threat.get('evidence', ''),
                description=threat.get('description', ''),
                iso27001_control=threat.get('iso27001_control', ''),
                remediation=threat.get('remediation', []),
                hex_offset=threat.get('hex_offset')
            ))
        
        return {
            'threats_detected': [threat.__dict__ for threat in combined_threats],
            'payload_classification': llm_results.get('payload_classification', 'unknown'),
            'attack_chain_analysis': llm_results.get('attack_chain_analysis', ''),
            'context_preservation': llm_results.get('context_preservation', ''),
            'overall_risk_score': llm_results.get('overall_risk_score', 0.0),
            'compliance_violations': llm_results.get('compliance_violations', []),
            'hexdump_analysis': hexdump_analysis,
            'pattern_matches': len(combined_threats),
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _is_suspicious_byte(self, byte_val: int, offset: int, payload: bytes) -> bool:
        """
        Determine if a byte is suspicious based on context
        """
        
        # Check for common attack byte patterns
        suspicious_bytes = [0x27, 0x22, 0x3c, 0x3e, 0x26, 0x7c, 0x3b, 0x60]
        
        if byte_val in suspicious_bytes:
            return True
        
        # Check for null bytes in unexpected positions
        if byte_val == 0x00 and offset < len(payload) - 1:
            return True
        
        # Check for high-bit characters that might indicate encoding
        if byte_val > 0x7f:
            return True
        
        return False
    
    def _identify_suspicious_byte_patterns(self, payload: bytes) -> List[Dict]:
        """
        Identify suspicious byte patterns in payload
        """
        
        patterns = []
        
        # Look for repeated patterns
        for i in range(len(payload) - 3):
            pattern = payload[i:i+4]
            if payload.count(pattern) > 3:
                patterns.append({
                    'type': 'repeated_pattern',
                    'pattern': pattern.hex(),
                    'count': payload.count(pattern),
                    'first_offset': i
                })
        
        # Look for high entropy regions
        for i in range(0, len(payload), 32):
            chunk = payload[i:i+32]
            if len(set(chunk)) > 20:  # High diversity
                patterns.append({
                    'type': 'high_entropy_region',
                    'offset': i,
                    'length': len(chunk),
                    'unique_bytes': len(set(chunk))
                })
        
        return patterns
    
    def _calculate_payload_entropy(self, payload: bytes) -> Dict[str, Any]:
        """
        Calculate entropy analysis of payload
        """
        
        if not payload:
            return {'overall_entropy': 0.0, 'high_entropy_regions': []}
        
        # Calculate overall entropy
        byte_counts = [0] * 256
        for byte in payload:
            byte_counts[byte] += 1
        
        entropy = 0.0
        payload_len = len(payload)
        
        for count in byte_counts:
            if count > 0:
                probability = count / payload_len
                entropy -= probability * (probability.bit_length() - 1)
        
        # Find high entropy regions
        high_entropy_regions = []
        window_size = 64
        
        for i in range(0, len(payload) - window_size, 32):
            window = payload[i:i+window_size]
            window_entropy = self._calculate_window_entropy(window)
            
            if window_entropy > 6.0:  # High entropy threshold
                high_entropy_regions.append({
                    'offset': i,
                    'length': window_size,
                    'entropy': window_entropy
                })
        
        return {
            'overall_entropy': entropy,
            'high_entropy_regions': high_entropy_regions,
            'entropy_threshold': 6.0
        }
    
    def _calculate_window_entropy(self, window: bytes) -> float:
        """
        Calculate entropy for a specific window
        """
        
        if not window:
            return 0.0
        
        byte_counts = {}
        for byte in window:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        entropy = 0.0
        window_len = len(window)
        
        for count in byte_counts.values():
            probability = count / window_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _find_hex_pattern(self, payload: bytes, pattern: bytes) -> List[int]:
        """
        Find all occurrences of a hex pattern in payload
        """
        
        offsets = []
        start = 0
        
        while True:
            offset = payload.find(pattern, start)
            if offset == -1:
                break
            offsets.append(offset)
            start = offset + 1
        
        return offsets