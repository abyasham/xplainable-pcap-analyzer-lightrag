"""
ISO 27001 Compliance Analysis Framework
Provides comprehensive compliance assessment for all attack types and security events
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"

@dataclass
class ComplianceViolation:
    """Represents an ISO 27001 compliance violation"""
    control_id: str
    control_name: str
    violation_type: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    affected_assets: List[str]
    remediation_actions: List[str]
    compliance_gap: str
    risk_rating: float
    timestamp: datetime

@dataclass
class ComplianceAssessment:
    """Comprehensive compliance assessment result"""
    overall_status: ComplianceStatus
    compliance_score: float
    total_controls_assessed: int
    compliant_controls: int
    violations: List[ComplianceViolation]
    recommendations: List[str]
    assessment_timestamp: datetime

class ISO27001ComplianceAnalyzer:
    """
    Comprehensive ISO 27001 compliance analyzer for security events and network analysis
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # ISO 27001:2022 Controls Mapping
        self.iso27001_controls = {
            # Organizational Controls
            'A.5.1': {
                'name': 'Policies for Information Security',
                'category': 'Organizational',
                'description': 'Information security policy and topic-specific policies'
            },
            'A.5.2': {
                'name': 'Information Security Roles and Responsibilities',
                'category': 'Organizational',
                'description': 'Information security roles and responsibilities'
            },
            
            # People Controls
            'A.6.1': {
                'name': 'Screening',
                'category': 'People',
                'description': 'Background verification checks on all candidates for employment'
            },
            'A.6.2': {
                'name': 'Terms and Conditions of Employment',
                'category': 'People',
                'description': 'Contractual agreements with employees and contractors'
            },
            'A.6.3': {
                'name': 'Disciplinary Process',
                'category': 'People',
                'description': 'Formal disciplinary process for information security violations'
            },
            'A.6.4': {
                'name': 'Information Security Responsibilities',
                'category': 'People',
                'description': 'Information security responsibilities that remain valid after termination'
            },
            'A.6.5': {
                'name': 'Remote Working',
                'category': 'People',
                'description': 'Security measures for remote working'
            },
            'A.6.6': {
                'name': 'Confidentiality or Non-disclosure Agreements',
                'category': 'People',
                'description': 'Confidentiality or non-disclosure agreements'
            },
            'A.6.7': {
                'name': 'Information Security Awareness, Education and Training',
                'category': 'People',
                'description': 'Information security awareness, education and training'
            },
            'A.6.8': {
                'name': 'Disciplinary Process',
                'category': 'People',
                'description': 'Disciplinary process for information security policy violations'
            },
            
            # Physical and Environmental Security Controls
            'A.7.1': {
                'name': 'Physical Security Perimeters',
                'category': 'Physical',
                'description': 'Physical security perimeters'
            },
            'A.7.2': {
                'name': 'Physical Entry',
                'category': 'Physical',
                'description': 'Physical entry controls'
            },
            'A.7.3': {
                'name': 'Protection Against Environmental Threats',
                'category': 'Physical',
                'description': 'Protection against environmental threats'
            },
            'A.7.4': {
                'name': 'Equipment Maintenance',
                'category': 'Physical',
                'description': 'Equipment maintenance'
            },
            
            # Technological Controls
            'A.8.1': {
                'name': 'User Endpoint Devices',
                'category': 'Technological',
                'description': 'Information security in user endpoint devices'
            },
            'A.8.2': {
                'name': 'Privileged Access Rights',
                'category': 'Technological',
                'description': 'Privileged access rights'
            },
            'A.8.3': {
                'name': 'Information Access Restriction',
                'category': 'Technological',
                'description': 'Information access restriction'
            },
            'A.8.4': {
                'name': 'Access to Source Code',
                'category': 'Technological',
                'description': 'Access to source code'
            },
            'A.8.5': {
                'name': 'Secure Authentication',
                'category': 'Technological',
                'description': 'Secure authentication'
            },
            'A.8.6': {
                'name': 'Capacity Management',
                'category': 'Technological',
                'description': 'Capacity management'
            },
            'A.8.7': {
                'name': 'Protection Against Malware',
                'category': 'Technological',
                'description': 'Protection against malware'
            },
            'A.8.8': {
                'name': 'Management of Technical Vulnerabilities',
                'category': 'Technological',
                'description': 'Management of technical vulnerabilities'
            },
            'A.8.9': {
                'name': 'Configuration Management',
                'category': 'Technological',
                'description': 'Configuration management'
            },
            'A.8.10': {
                'name': 'Information Deletion',
                'category': 'Technological',
                'description': 'Information deletion'
            },
            'A.8.11': {
                'name': 'Data Masking',
                'category': 'Technological',
                'description': 'Data masking'
            },
            'A.8.12': {
                'name': 'Data Leakage Prevention',
                'category': 'Technological',
                'description': 'Data leakage prevention'
            },
            'A.8.13': {
                'name': 'Information Backup',
                'category': 'Technological',
                'description': 'Information backup'
            },
            'A.8.14': {
                'name': 'Redundancy of Information Processing Facilities',
                'category': 'Technological',
                'description': 'Redundancy of information processing facilities'
            },
            'A.8.15': {
                'name': 'Logging',
                'category': 'Technological',
                'description': 'Logging'
            },
            'A.8.16': {
                'name': 'Monitoring Activities',
                'category': 'Technological',
                'description': 'Monitoring activities'
            },
            'A.8.17': {
                'name': 'Clock Synchronisation',
                'category': 'Technological',
                'description': 'Clock synchronisation'
            },
            'A.8.18': {
                'name': 'Use of Privileged Utility Programs',
                'category': 'Technological',
                'description': 'Use of privileged utility programs'
            },
            'A.8.19': {
                'name': 'Installation of Software on Operational Systems',
                'category': 'Technological',
                'description': 'Installation of software on operational systems'
            },
            'A.8.20': {
                'name': 'Networks Security Management',
                'category': 'Technological',
                'description': 'Networks security management'
            },
            'A.8.21': {
                'name': 'Security of Network Services',
                'category': 'Technological',
                'description': 'Security of network services'
            },
            'A.8.22': {
                'name': 'Segregation of Networks',
                'category': 'Technological',
                'description': 'Segregation of networks'
            },
            'A.8.23': {
                'name': 'Web Filtering',
                'category': 'Technological',
                'description': 'Web filtering'
            },
            'A.8.24': {
                'name': 'Use of Cryptography',
                'category': 'Technological',
                'description': 'Use of cryptography'
            },
            'A.8.25': {
                'name': 'Secure System Development Life Cycle',
                'category': 'Technological',
                'description': 'Secure system development life cycle'
            },
            'A.8.26': {
                'name': 'Application Security Requirements',
                'category': 'Technological',
                'description': 'Application security requirements'
            },
            'A.8.27': {
                'name': 'Secure System Architecture and Engineering Principles',
                'category': 'Technological',
                'description': 'Secure system architecture and engineering principles'
            },
            'A.8.28': {
                'name': 'Secure Coding',
                'category': 'Technological',
                'description': 'Secure coding'
            },
            'A.8.29': {
                'name': 'Security Testing in Development and Acceptance',
                'category': 'Technological',
                'description': 'Security testing in development and acceptance'
            },
            'A.8.30': {
                'name': 'Outsourced Development',
                'category': 'Technological',
                'description': 'Outsourced development'
            },
            'A.8.31': {
                'name': 'Separation of Development, Test and Production Environments',
                'category': 'Technological',
                'description': 'Separation of development, test and production environments'
            },
            'A.8.32': {
                'name': 'Change Management',
                'category': 'Technological',
                'description': 'Change management'
            },
            'A.8.33': {
                'name': 'Test Information',
                'category': 'Technological',
                'description': 'Test information'
            },
            'A.8.34': {
                'name': 'Protection of Information Systems During Audit Testing',
                'category': 'Technological',
                'description': 'Protection of information systems during audit testing'
            }
        }
        
        # Attack type to control mapping
        self.attack_control_mapping = {
            'sql_injection_attempt': ['A.8.26', 'A.8.27', 'A.8.28', 'A.8.29'],
            'xss_attempt': ['A.8.26', 'A.8.27', 'A.8.28', 'A.8.23'],
            'directory_traversal': ['A.8.3', 'A.8.26', 'A.8.27', 'A.8.28'],
            'token_injection': ['A.8.5', 'A.8.2', 'A.8.3'],
            'authentication_bypass': ['A.8.5', 'A.8.2', 'A.8.3'],
            'arp_poisoning': ['A.8.20', 'A.8.21', 'A.8.22'],
            'port_scanning': ['A.8.16', 'A.8.20', 'A.8.21'],
            'dns_tunneling': ['A.8.12', 'A.8.16', 'A.8.20'],
            'tls_vulnerability': ['A.8.24', 'A.8.21'],
            'zmq_exploitation': ['A.8.21', 'A.8.26', 'A.8.27'],
            'command_injection': ['A.8.26', 'A.8.27', 'A.8.28', 'A.8.18'],
            'data_exfiltration': ['A.8.12', 'A.8.16', 'A.8.15'],
            'malware_detection': ['A.8.7', 'A.8.16', 'A.8.15'],
            'privilege_escalation': ['A.8.2', 'A.8.18', 'A.8.16'],
            'lateral_movement': ['A.8.22', 'A.8.16', 'A.8.20'],
            'brute_force': ['A.8.5', 'A.8.16', 'A.8.15'],
            'ddos': ['A.8.6', 'A.8.14', 'A.8.16']
        }
    
    async def analyze_comprehensive_compliance(self, network_entities: Dict[str, Any], 
                                            threat_detections: List[Any] = None) -> ComplianceAssessment:
        """
        Perform comprehensive ISO 27001 compliance analysis
        """
        
        logger.info("Starting comprehensive ISO 27001 compliance analysis...")
        
        try:
            violations = []
            
            # Analyze security events for compliance violations
            security_events = network_entities.get('security_events', [])
            for event in security_events:
                event_violations = await self._analyze_event_compliance(event)
                violations.extend(event_violations)
            
            # Analyze threat detections for compliance violations
            if threat_detections:
                for threat in threat_detections:
                    threat_violations = await self._analyze_threat_compliance(threat)
                    violations.extend(threat_violations)
            
            # Analyze network infrastructure compliance
            infrastructure_violations = await self._analyze_infrastructure_compliance(network_entities)
            violations.extend(infrastructure_violations)
            
            # Calculate compliance metrics
            assessment = self._calculate_compliance_assessment(violations)
            
            logger.info(f"Compliance analysis completed: {len(violations)} violations found")
            return assessment
            
        except Exception as e:
            logger.error(f"Compliance analysis failed: {e}")
            raise
    
    async def _analyze_event_compliance(self, event) -> List[ComplianceViolation]:
        """Analyze a security event for ISO 27001 compliance violations"""
        
        violations = []
        event_type = getattr(event, 'event_type', 'unknown')
        severity = getattr(event, 'severity', 'LOW')
        
        # Get relevant controls for this event type
        relevant_controls = self.attack_control_mapping.get(event_type, [])
        
        for control_id in relevant_controls:
            control_info = self.iso27001_controls.get(control_id, {})
            
            # Determine violation based on event characteristics
            violation = ComplianceViolation(
                control_id=control_id,
                control_name=control_info.get('name', 'Unknown Control'),
                violation_type=self._determine_violation_type(event_type, control_id),
                severity=self._map_event_severity_to_compliance(severity),
                description=self._generate_violation_description(event, control_info),
                evidence=self._extract_compliance_evidence(event),
                affected_assets=self._identify_affected_assets(event),
                remediation_actions=self._generate_remediation_actions(event_type, control_id),
                compliance_gap=self._assess_compliance_gap(event_type, control_id),
                risk_rating=self._calculate_risk_rating(event, control_id),
                timestamp=datetime.now()
            )
            
            violations.append(violation)
        
        return violations
    
    async def _analyze_threat_compliance(self, threat) -> List[ComplianceViolation]:
        """Analyze a threat detection for ISO 27001 compliance violations"""
        
        violations = []
        attack_type = getattr(threat, 'attack_type', 'unknown')
        severity = getattr(threat, 'severity', 'LOW')
        
        # Get relevant controls for this threat type
        relevant_controls = self.attack_control_mapping.get(attack_type, [])
        
        for control_id in relevant_controls:
            control_info = self.iso27001_controls.get(control_id, {})
            
            violation = ComplianceViolation(
                control_id=control_id,
                control_name=control_info.get('name', 'Unknown Control'),
                violation_type=self._determine_violation_type(attack_type, control_id),
                severity=self._map_threat_severity_to_compliance(severity),
                description=self._generate_threat_violation_description(threat, control_info),
                evidence=self._extract_threat_compliance_evidence(threat),
                affected_assets=self._identify_threat_affected_assets(threat),
                remediation_actions=self._generate_remediation_actions(attack_type, control_id),
                compliance_gap=self._assess_compliance_gap(attack_type, control_id),
                risk_rating=self._calculate_threat_risk_rating(threat, control_id),
                timestamp=datetime.now()
            )
            
            violations.append(violation)
        
        return violations
    
    async def _analyze_infrastructure_compliance(self, network_entities: Dict[str, Any]) -> List[ComplianceViolation]:
        """Analyze network infrastructure for compliance violations"""
        
        violations = []
        
        # Analyze hosts for compliance issues
        hosts = network_entities.get('hosts', {})
        for ip, host_data in hosts.items():
            host_violations = await self._analyze_host_compliance(ip, host_data)
            violations.extend(host_violations)
        
        # Analyze services for compliance issues
        services = network_entities.get('services', {})
        for service_key, service_data in services.items():
            service_violations = await self._analyze_service_compliance(service_key, service_data)
            violations.extend(service_violations)
        
        # Analyze network communications for compliance
        connections = network_entities.get('connections', [])
        comm_violations = await self._analyze_communication_compliance(connections)
        violations.extend(comm_violations)
        
        return violations
    
    async def _analyze_host_compliance(self, ip: str, host_data: Dict) -> List[ComplianceViolation]:
        """Analyze individual host for compliance violations"""
        
        violations = []
        
        # Check for unmanaged/unknown hosts (A.8.1 - User Endpoint Devices)
        if host_data.get('reputation', 'unknown') == 'unknown':
            violations.append(ComplianceViolation(
                control_id='A.8.1',
                control_name='User Endpoint Devices',
                violation_type='unmanaged_device',
                severity='MEDIUM',
                description=f"Unmanaged device detected: {ip}",
                evidence={'ip_address': ip, 'reputation': 'unknown'},
                affected_assets=[ip],
                remediation_actions=[
                    'Implement device inventory management',
                    'Deploy endpoint detection and response (EDR)',
                    'Establish device compliance policies'
                ],
                compliance_gap='Lack of endpoint device management and monitoring',
                risk_rating=6.0,
                timestamp=datetime.now()
            ))
        
        # Check for suspicious activity (A.8.16 - Monitoring Activities)
        suspicious_activities = host_data.get('suspicious_activities', [])
        if suspicious_activities:
            violations.append(ComplianceViolation(
                control_id='A.8.16',
                control_name='Monitoring Activities',
                violation_type='insufficient_monitoring',
                severity='HIGH',
                description=f"Suspicious activities detected on {ip} but not properly monitored",
                evidence={'ip_address': ip, 'activities': suspicious_activities},
                affected_assets=[ip],
                remediation_actions=[
                    'Enhance security monitoring capabilities',
                    'Implement behavioral analysis',
                    'Deploy SIEM solution'
                ],
                compliance_gap='Inadequate monitoring of suspicious activities',
                risk_rating=8.0,
                timestamp=datetime.now()
            ))
        
        return violations
    
    async def _analyze_service_compliance(self, service_key: str, service_data: Dict) -> List[ComplianceViolation]:
        """Analyze network service for compliance violations"""
        
        violations = []
        
        # Check for high-risk services (A.8.21 - Security of Network Services)
        risk_level = service_data.get('risk_level', 'MEDIUM')
        if risk_level == 'HIGH':
            violations.append(ComplianceViolation(
                control_id='A.8.21',
                control_name='Security of Network Services',
                violation_type='high_risk_service',
                severity='HIGH',
                description=f"High-risk network service detected: {service_data.get('service_name', 'Unknown')}",
                evidence=service_data,
                affected_assets=[service_data.get('host', 'unknown')],
                remediation_actions=[
                    'Review service necessity and security configuration',
                    'Implement service hardening measures',
                    'Apply principle of least privilege'
                ],
                compliance_gap='Inadequate security controls for high-risk services',
                risk_rating=8.5,
                timestamp=datetime.now()
            ))
        
        return violations
    
    async def _analyze_communication_compliance(self, connections: List[Dict]) -> List[ComplianceViolation]:
        """Analyze network communications for compliance violations"""
        
        violations = []
        
        # Check for excessive external communications (A.8.22 - Segregation of Networks)
        external_connections = [conn for conn in connections if not self._is_internal_communication(conn)]
        
        if len(external_connections) > 1000:  # Threshold for excessive external communications
            violations.append(ComplianceViolation(
                control_id='A.8.22',
                control_name='Segregation of Networks',
                violation_type='excessive_external_communication',
                severity='MEDIUM',
                description=f"Excessive external network communications detected: {len(external_connections)} connections",
                evidence={'external_connection_count': len(external_connections)},
                affected_assets=['network_perimeter'],
                remediation_actions=[
                    'Implement network segmentation',
                    'Review and restrict external communications',
                    'Deploy network access control (NAC)'
                ],
                compliance_gap='Insufficient network segregation and access control',
                risk_rating=7.0,
                timestamp=datetime.now()
            ))
        
        return violations
    
    def _calculate_compliance_assessment(self, violations: List[ComplianceViolation]) -> ComplianceAssessment:
        """Calculate overall compliance assessment"""
        
        total_controls = len(self.iso27001_controls)
        violated_controls = set(v.control_id for v in violations)
        compliant_controls = total_controls - len(violated_controls)
        
        # Calculate compliance score
        compliance_score = (compliant_controls / total_controls) * 100
        
        # Determine overall status
        if compliance_score >= 95:
            overall_status = ComplianceStatus.COMPLIANT
        elif compliance_score >= 80:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT
        
        # Generate recommendations
        recommendations = self._generate_compliance_recommendations(violations)
        
        return ComplianceAssessment(
            overall_status=overall_status,
            compliance_score=compliance_score,
            total_controls_assessed=total_controls,
            compliant_controls=compliant_controls,
            violations=violations,
            recommendations=recommendations,
            assessment_timestamp=datetime.now()
        )
    
    def _generate_compliance_recommendations(self, violations: List[ComplianceViolation]) -> List[str]:
        """Generate strategic compliance recommendations"""
        
        recommendations = []
        
        # Group violations by control category
        category_violations = {}
        for violation in violations:
            control_info = self.iso27001_controls.get(violation.control_id, {})
            category = control_info.get('category', 'Unknown')
            
            if category not in category_violations:
                category_violations[category] = []
            category_violations[category].append(violation)
        
        # Generate category-specific recommendations
        for category, cat_violations in category_violations.items():
            if category == 'Technological':
                recommendations.append(f"Strengthen technological controls: {len(cat_violations)} violations in security technology implementation")
            elif category == 'Organizational':
                recommendations.append(f"Review organizational policies: {len(cat_violations)} policy-related compliance gaps identified")
            elif category == 'People':
                recommendations.append(f"Enhance personnel security: {len(cat_violations)} human-factor security issues detected")
            elif category == 'Physical':
                recommendations.append(f"Improve physical security: {len(cat_violations)} physical security control deficiencies")
        
        # Add priority recommendations based on severity
        critical_violations = [v for v in violations if v.severity == 'CRITICAL']
        if critical_violations:
            recommendations.insert(0, f"URGENT: Address {len(critical_violations)} critical compliance violations immediately")
        
        high_violations = [v for v in violations if v.severity == 'HIGH']
        if high_violations:
            recommendations.insert(1 if critical_violations else 0, f"HIGH PRIORITY: Resolve {len(high_violations)} high-severity compliance issues")
        
        return recommendations
    
    # Helper methods
    def _determine_violation_type(self, event_type: str, control_id: str) -> str:
        """Determine the type of compliance violation"""
        violation_types = {
            'sql_injection_attempt': 'insecure_application_development',
            'xss_attempt': 'inadequate_input_validation',
            'directory_traversal': 'insufficient_access_controls',
            'token_injection': 'weak_authentication_mechanisms',
            'arp_poisoning': 'network_security_weakness',
            'port_scanning': 'inadequate_network_monitoring',
            'dns_tunneling': 'data_leakage_vulnerability',
            'tls_vulnerability': 'cryptographic_weakness',
            'zmq_exploitation': 'insecure_service_configuration'
        }
        
        return violation_types.get(event_type, 'general_security_control_failure')
    
    def _map_event_severity_to_compliance(self, event_severity: str) -> str:
        """Map event severity to compliance violation severity"""
        mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW'
        }
        return mapping.get(event_severity, 'MEDIUM')
    
    def _map_threat_severity_to_compliance(self, threat_severity: str) -> str:
        """Map threat severity to compliance violation severity"""
        return self._map_event_severity_to_compliance(threat_severity)
    
    def _generate_violation_description(self, event, control_info: Dict) -> str:
        """Generate detailed violation description"""
        event_type = getattr(event, 'event_type', 'unknown')
        description = getattr(event, 'description', 'No description available')
        
        return f"ISO 27001 Control {control_info.get('name', 'Unknown')} violated by {event_type}: {description}"
    
    def _generate_threat_violation_description(self, threat, control_info: Dict) -> str:
        """Generate detailed threat violation description"""
        attack_type = getattr(threat, 'attack_type', 'unknown')
        description = getattr(threat, 'description', 'No description available')
        
        return f"ISO 27001 Control {control_info.get('name', 'Unknown')} violated by {attack_type}: {description}"
    
    def _extract_compliance_evidence(self, event) -> Dict[str, Any]:
        """Extract compliance evidence from security event"""
        return {
            'event_id': getattr(event, 'event_id', 'unknown'),
            'event_type': getattr(event, 'event_type', 'unknown'),
            'timestamp': getattr(event, 'timestamp', 0),
            'source_ip': getattr(event, 'source_ip', None),
            'dest_ip': getattr(event, 'dest_ip', None),
            'evidence': getattr(event, 'evidence', {}),
            'confidence_score': getattr(event, 'confidence_score', 0.0)
        }
    
    def _extract_threat_compliance_evidence(self, threat) -> Dict[str, Any]:
        """Extract compliance evidence from threat detection"""
        return {
            'attack_type': getattr(threat, 'attack_type', 'unknown'),
            'severity': getattr(threat, 'severity', 'LOW'),
            'confidence': getattr(threat, 'confidence', 0.0),
            'evidence': getattr(threat, 'evidence', ''),
            'description': getattr(threat, 'description', ''),
            'iso27001_control': getattr(threat, 'iso27001_control', '')
        }
    
    def _identify_affected_assets(self, event) -> List[str]:
        """Identify assets affected by security event"""
        assets = []
        
        if hasattr(event, 'source_ip') and event.source_ip:
            assets.append(event.source_ip)
        
        if hasattr(event, 'dest_ip') and event.dest_ip:
            assets.append(event.dest_ip)
        
        return assets
    
    def _identify_threat_affected_assets(self, threat) -> List[str]:
        """Identify assets affected by threat detection"""
        # This would depend on the threat detection structure
        return ['network_infrastructure']
    
    def _generate_remediation_actions(self, attack_type: str, control_id: str) -> List[str]:
        """Generate specific remediation actions"""
        
        remediation_map = {
            'sql_injection_attempt': [
                'Implement parameterized queries and prepared statements',
                'Deploy web application firewall (WAF)',
                'Conduct security code review',
                'Implement input validation and sanitization'
            ],
            'xss_attempt': [
                'Implement output encoding and escaping',
                'Deploy Content Security Policy (CSP)',
                'Conduct security testing of web applications',
                'Implement input validation'
            ],
            'directory_traversal': [
                'Implement proper access controls and file permissions',
                'Use secure file handling APIs',
                'Validate and sanitize file paths',
                'Implement principle of least privilege'
            ],
            'token_injection': [
                'Implement secure token generation and validation',
                'Use strong authentication mechanisms',
                'Implement token expiration and rotation',
                'Deploy multi-factor authentication'
            ],
            'arp_poisoning': [
                'Implement network segmentation',
                'Deploy network monitoring and intrusion detection',
                'Use static ARP entries where appropriate',
                'Implement network access control'
            ]
        }
        
        return remediation_map.get(attack_type, [
            'Review and strengthen security controls',
            'Implement monitoring and detection capabilities',
            'Conduct security assessment',
            'Update security policies and procedures'
        ])
    
    def _assess_compliance_gap(self, attack_type: str, control_id: str) -> str:
        """Assess the compliance gap for specific attack and control"""
        
        gap_descriptions = {
            'sql_injection_attempt': 'Inadequate secure development practices and input validation',
            'xss_attempt': 'Insufficient output encoding and client-side security controls',
            'directory_traversal': 'Weak access controls and file system security',
            'token_injection': 'Inadequate authentication and session management',
            'arp_poisoning': 'Insufficient network security controls and monitoring',
            'port_scanning': 'Lack of network monitoring and intrusion detection',
            'dns_tunneling': 'Inadequate data leakage prevention and network monitoring',
            'tls_vulnerability': 'Weak cryptographic implementation and configuration',
            'zmq_exploitation': 'Insecure service configuration and network controls'
        }
        
        return gap_descriptions.get(attack_type, 'General security control implementation gap')
    
    def _calculate_risk_rating(self, event, control_id: str) -> float:
        """Calculate risk rating for compliance violation"""
        
        base_risk = 5.0
        severity = getattr(event, 'severity', 'LOW')
        confidence = getattr(event, 'confidence_score', 0.5)
        
        # Adjust risk based on severity
        severity_multipliers = {
            'CRITICAL': 2.0,
            'HIGH': 1.5,
            'MEDIUM': 1.0,
            'LOW': 0.5
        }
        
        risk_rating = base_risk * severity_multipliers.get(severity, 1.0) * confidence
        return min(10.0, max(1.0, risk_rating))
    
    def _calculate_threat_risk_rating(self, threat, control_id: str) -> float:
        """Calculate risk rating for threat-based compliance violation"""
        
        base_risk = 5.0
        severity = getattr(threat, 'severity', 'LOW')
        confidence = getattr(threat, 'confidence', 0.5)
        
        # Adjust risk based on severity
        severity_multipliers = {
            'CRITICAL': 2.0,
            'HIGH': 1.5,
            'MEDIUM': 1.0,
            'LOW': 0.5
        }
        
        risk_rating = base_risk * severity_multipliers.get(severity, 1.0) * confidence
        return min(10.0, max(1.0, risk_rating))
    
    def _is_internal_communication(self, connection: Dict) -> bool:
        """Check if communication is internal to the network"""
        
        source_ip = connection.get('source_ip', '')
        dest_ip = connection.get('dest_ip', '')
        
        # Simple check for private IP ranges
        private_ranges = ['10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
        
        source_internal = any(source_ip.startswith(prefix) for prefix in private_ranges)
        dest_internal = any(dest_ip.startswith(prefix) for prefix in private_ranges)
        
        return source_internal and dest_internal
    
    def generate_compliance_report(self, assessment: ComplianceAssessment) -> str:
        """Generate comprehensive compliance report"""
        
        report = f"""# ISO 27001:2022 Compliance Assessment Report

## Executive Summary

**Assessment Date**: {assessment.assessment_timestamp.strftime('%Y-%m-%d %H:%M:%S')}
**Overall Compliance Status**: {assessment.overall_status.value.upper()}
**Compliance Score**: {assessment.compliance_score:.1f}%

### Key Findings
- **Total Controls Assessed**: {assessment.total_controls_assessed}
- **Compliant Controls**: {assessment.compliant_controls}
- **Non-Compliant Controls**: {len(set(v.control_id for v in assessment.violations))}
- **Total Violations**: {len(assessment.violations)}

## Compliance Status Overview

"""
        
        if assessment.overall_status == ComplianceStatus.COMPLIANT:
            report += """✅ **COMPLIANT**: The organization demonstrates strong adherence to ISO 27001:2022 requirements with minimal compliance gaps."""
        elif assessment.overall_status == ComplianceStatus.PARTIALLY_COMPLIANT:
            report += """⚠️ **PARTIALLY COMPLIANT**: The organization has implemented most ISO 27001:2022 controls but has significant gaps that require attention."""
        else:
            report += """❌ **NON-COMPLIANT**: The organization has substantial compliance gaps that pose significant security risks and require immediate remediation."""
        
        # Violation analysis by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for violation in assessment.violations:
            severity_counts[violation.severity] += 1
        
        report += f"""

## Violation Analysis by Severity

- **Critical Violations**: {severity_counts['CRITICAL']} (Immediate action required)
- **High Severity**: {severity_counts['HIGH']} (Priority remediation needed)
- **Medium Severity**: {severity_counts['MEDIUM']} (Planned remediation required)
- **Low Severity**: {severity_counts['LOW']} (Monitor and improve)

## Control Category Analysis

"""
        
        # Group violations by control category
        category_violations = {}
        for violation in assessment.violations:
            control_info = self.iso27001_controls.get(violation.control_id, {})
            category = control_info.get('category', 'Unknown')
            
            if category not in category_violations:
                category_violations[category] = []
            category_violations[category].append(violation)
        
        for category, violations in category_violations.items():
            report += f"""
### {category} Controls
**Violations**: {len(violations)}
**Risk Level**: {'HIGH' if len(violations) > 5 else 'MEDIUM' if len(violations) > 2 else 'LOW'}

"""
            
            # Show top violations in category
            for violation in violations[:3]:
                report += f"""
**Control {violation.control_id}**: {violation.control_name}
- **Violation Type**: {violation.violation_type}
- **Severity**: {violation.severity}
- **Risk Rating**: {violation.risk_rating:.1f}/10
- **Description**: {violation.description}
- **Affected Assets**: {', '.join(violation.affected_assets)}

"""
        
        # Strategic recommendations
        report += f"""
## Strategic Recommendations

### Immediate Actions Required
"""
        
        for i, recommendation in enumerate(assessment.recommendations[:5], 1):
            report += f"{i}. {recommendation}\n"
        
        report += f"""
### Implementation Roadmap

**Phase 1 (0-30 days)**: Address all critical and high-severity violations
**Phase 2 (30-90 days)**: Implement medium-severity remediation actions
**Phase 3 (90-180 days)**: Complete low-severity improvements and establish continuous monitoring

## Conclusion

This assessment provides a comprehensive view of the organization's ISO 27001:2022 compliance posture. Immediate attention to critical and high-severity violations is essential to reduce security risks and achieve compliance objectives.

---
*Report generated by PCAP Security Analyzer - ISO 27001 Compliance Module*
"""
        
        return report