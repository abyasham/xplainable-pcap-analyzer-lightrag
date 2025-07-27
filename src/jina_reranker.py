"""
Jina Reranker Integration for Enhanced Security Context Retrieval
Provides advanced reranking capabilities for PCAP security analysis
"""

import asyncio
import aiohttp
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class RerankedDocument:
    """Represents a reranked document with enhanced metadata"""
    content: str
    relevance_score: float
    original_index: int
    security_context: Dict[str, Any]
    rerank_confidence: float

class JinaRerankerService:
    """
    Jina-powered reranking service optimized for security analysis
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_key = config.get('jina', {}).get('api_key') or config.get('JINA_API_KEY')
        self.base_url = "https://api.jina.ai/v1/rerank"
        self.model = config.get('jina', {}).get('model', 'jina-reranker-v2-base-multilingual')
        self.max_retries = 3
        self.timeout = 30
        
        # Security-specific reranking parameters
        self.security_boost_keywords = [
            'attack', 'vulnerability', 'exploit', 'malicious', 'threat',
            'injection', 'xss', 'sql', 'traversal', 'bypass', 'escalation',
            'compromise', 'breach', 'intrusion', 'anomaly', 'suspicious'
        ]
        
        if not self.api_key:
            logger.warning("Jina API key not found. Reranking will be disabled.")
    
    async def rerank_security_documents(self, query: str, documents: List[str], 
                                      top_k: int = 10, 
                                      security_context: Optional[Dict] = None) -> List[RerankedDocument]:
        """
        Rerank security analysis documents using Jina API with security-specific enhancements
        """
        
        if not self.api_key:
            logger.warning("Jina API key not available, returning original order")
            return self._create_fallback_ranking(documents, top_k)
        
        if not documents:
            return []
        
        try:
            # Enhance query with security context
            enhanced_query = self._enhance_query_with_security_context(query, security_context)
            
            # Prepare documents with security metadata
            enhanced_documents = self._prepare_documents_for_reranking(documents, security_context)
            
            # Execute Jina reranking
            rerank_results = await self._execute_jina_rerank(
                enhanced_query, 
                enhanced_documents, 
                min(top_k, len(documents))
            )
            
            # Post-process results with security scoring
            final_results = self._apply_security_scoring(rerank_results, query, security_context)
            
            logger.info(f"Successfully reranked {len(documents)} documents, returning top {len(final_results)}")
            return final_results
            
        except Exception as e:
            logger.error(f"Jina reranking failed: {e}")
            return self._create_fallback_ranking(documents, top_k)
    
    def _enhance_query_with_security_context(self, query: str, 
                                           security_context: Optional[Dict] = None) -> str:
        """
        Enhance query with security-specific context for better reranking
        """
        
        enhanced_query = f"""
        SECURITY ANALYSIS QUERY: {query}
        
        ANALYSIS CONTEXT:
        - Focus: Network security threat detection and analysis
        - Priority: Attack pattern recognition and vulnerability assessment
        - Scope: Multi-vector threat analysis including web attacks, network intrusions, and protocol vulnerabilities
        - Compliance: ISO 27001 security controls and regulatory requirements
        
        SPECIFIC SECURITY DOMAINS:
        - SQL Injection and database attacks
        - Cross-Site Scripting (XSS) and web application security
        - Directory traversal and file inclusion vulnerabilities
        - Authentication bypass and token manipulation
        - Protocol-specific attacks (TLS, ZMQ, etc.)
        - Network reconnaissance and lateral movement
        - Data exfiltration and command injection
        
        RETRIEVAL PRIORITIES:
        1. Direct threat evidence and attack indicators
        2. Security event correlation and attack chains
        3. Vulnerability assessment and risk analysis
        4. Compliance violation identification
        5. Incident response and remediation guidance
        """
        
        if security_context:
            enhanced_query += f"\n\nADDITIONAL CONTEXT:\n"
            
            if 'attack_types' in security_context:
                enhanced_query += f"- Detected Attack Types: {', '.join(security_context['attack_types'])}\n"
            
            if 'severity_level' in security_context:
                enhanced_query += f"- Severity Level: {security_context['severity_level']}\n"
            
            if 'affected_hosts' in security_context:
                enhanced_query += f"- Affected Hosts: {', '.join(security_context['affected_hosts'])}\n"
            
            if 'time_window' in security_context:
                enhanced_query += f"- Time Window: {security_context['time_window']}\n"
            
            if 'compliance_controls' in security_context:
                enhanced_query += f"- Relevant ISO 27001 Controls: {', '.join(security_context['compliance_controls'])}\n"
        
        return enhanced_query
    
    def _prepare_documents_for_reranking(self, documents: List[str], 
                                       security_context: Optional[Dict] = None) -> List[str]:
        """
        Prepare documents with security-specific metadata for enhanced reranking
        """
        
        enhanced_documents = []
        
        for i, doc in enumerate(documents):
            # Add security metadata prefix to each document
            security_score = self._calculate_document_security_relevance(doc)
            
            enhanced_doc = f"""
            [SECURITY_RELEVANCE: {security_score:.2f}]
            [DOCUMENT_ID: {i}]
            [THREAT_INDICATORS: {self._extract_threat_indicators(doc)}]
            
            {doc}
            """
            
            enhanced_documents.append(enhanced_doc.strip())
        
        return enhanced_documents
    
    async def _execute_jina_rerank(self, query: str, documents: List[str], top_k: int) -> List[Dict]:
        """
        Execute Jina API reranking request with retry logic
        """
        
        payload = {
            "model": self.model,
            "query": query,
            "documents": documents,
            "top_n": top_k,
            "return_documents": True
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                    async with session.post(self.base_url, json=payload, headers=headers) as response:
                        if response.status == 200:
                            result = await response.json()
                            return result.get('results', [])
                        else:
                            error_text = await response.text()
                            logger.error(f"Jina API error (attempt {attempt + 1}): {response.status} - {error_text}")
                            
                            if response.status == 429:  # Rate limit
                                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                                continue
                            else:
                                break
                                
            except asyncio.TimeoutError:
                logger.error(f"Jina API timeout (attempt {attempt + 1})")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1)
                    continue
            except Exception as e:
                logger.error(f"Jina API request failed (attempt {attempt + 1}): {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1)
                    continue
        
        raise Exception("Jina API reranking failed after all retry attempts")
    
    def _apply_security_scoring(self, rerank_results: List[Dict], 
                              query: str, 
                              security_context: Optional[Dict] = None) -> List[RerankedDocument]:
        """
        Apply additional security-specific scoring to reranked results
        """
        
        enhanced_results = []
        
        for result in rerank_results:
            document = result.get('document', {})
            content = document.get('text', '')
            relevance_score = result.get('relevance_score', 0.0)
            original_index = document.get('index', 0)
            
            # Calculate security-specific boost
            security_boost = self._calculate_security_boost(content, query, security_context)
            
            # Apply security boost to relevance score
            final_score = min(1.0, relevance_score + security_boost)
            
            # Extract security context from document
            doc_security_context = self._extract_document_security_context(content)
            
            enhanced_results.append(RerankedDocument(
                content=self._clean_document_content(content),
                relevance_score=final_score,
                original_index=original_index,
                security_context=doc_security_context,
                rerank_confidence=relevance_score
            ))
        
        # Sort by final security-enhanced score
        enhanced_results.sort(key=lambda x: x.relevance_score, reverse=True)
        
        return enhanced_results
    
    def _calculate_document_security_relevance(self, document: str) -> float:
        """
        Calculate security relevance score for a document
        """
        
        score = 0.0
        doc_lower = document.lower()
        
        # Check for security keywords
        for keyword in self.security_boost_keywords:
            count = doc_lower.count(keyword)
            score += count * 0.1
        
        # Check for specific attack patterns
        attack_patterns = [
            'sql injection', 'xss', 'cross-site scripting', 'directory traversal',
            'command injection', 'buffer overflow', 'privilege escalation',
            'authentication bypass', 'session hijacking', 'csrf', 'ssrf'
        ]
        
        for pattern in attack_patterns:
            if pattern in doc_lower:
                score += 0.3
        
        # Check for compliance references
        compliance_patterns = ['iso 27001', 'nist', 'cis', 'owasp', 'compliance']
        for pattern in compliance_patterns:
            if pattern in doc_lower:
                score += 0.2
        
        return min(1.0, score)
    
    def _extract_threat_indicators(self, document: str) -> str:
        """
        Extract threat indicators from document for metadata
        """
        
        indicators = []
        doc_lower = document.lower()
        
        # Check for specific threats
        threat_types = {
            'sql_injection': ['union select', 'drop table', '1=1', 'information_schema'],
            'xss': ['<script', 'javascript:', 'alert(', 'document.cookie'],
            'directory_traversal': ['../', '../..', '/etc/passwd', 'boot.ini'],
            'command_injection': ['; cat', '| nc', '`whoami`', '$(id)'],
            'authentication': ['jwt', 'bearer', 'session', 'token'],
            'network': ['port scan', 'arp poison', 'dns tunnel', 'lateral movement']
        }
        
        for threat_type, patterns in threat_types.items():
            for pattern in patterns:
                if pattern in doc_lower:
                    indicators.append(threat_type)
                    break
        
        return ', '.join(set(indicators)) if indicators else 'general_security'
    
    def _calculate_security_boost(self, content: str, query: str, 
                                security_context: Optional[Dict] = None) -> float:
        """
        Calculate security-specific boost for reranked documents
        """
        
        boost = 0.0
        content_lower = content.lower()
        query_lower = query.lower()
        
        # Boost for query term matches in security context
        query_terms = query_lower.split()
        security_terms = [term for term in query_terms if term in self.security_boost_keywords]
        
        for term in security_terms:
            count = content_lower.count(term)
            boost += count * 0.05
        
        # Boost for security context alignment
        if security_context:
            if 'attack_types' in security_context:
                for attack_type in security_context['attack_types']:
                    if attack_type.lower() in content_lower:
                        boost += 0.1
            
            if 'severity_level' in security_context:
                severity = security_context['severity_level'].lower()
                if severity in content_lower:
                    boost += 0.05
        
        # Boost for technical security content
        technical_indicators = [
            'vulnerability', 'exploit', 'payload', 'malware', 'intrusion',
            'forensics', 'incident', 'breach', 'compromise', 'mitigation'
        ]
        
        for indicator in technical_indicators:
            if indicator in content_lower:
                boost += 0.03
        
        return min(0.3, boost)  # Cap boost at 0.3
    
    def _extract_document_security_context(self, content: str) -> Dict[str, Any]:
        """
        Extract security context metadata from document content
        """
        
        context = {
            'threat_types': [],
            'severity_indicators': [],
            'compliance_references': [],
            'technical_details': False,
            'remediation_info': False
        }
        
        content_lower = content.lower()
        
        # Extract threat types
        threat_patterns = {
            'web_attack': ['sql injection', 'xss', 'csrf', 'ssrf'],
            'network_attack': ['port scan', 'arp poison', 'dns tunnel'],
            'system_attack': ['privilege escalation', 'buffer overflow', 'code injection'],
            'authentication_attack': ['session hijack', 'token manipulation', 'brute force']
        }
        
        for category, patterns in threat_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    context['threat_types'].append(category)
                    break
        
        # Extract severity indicators
        severity_terms = ['critical', 'high', 'medium', 'low', 'severe', 'urgent']
        for term in severity_terms:
            if term in content_lower:
                context['severity_indicators'].append(term)
        
        # Extract compliance references
        compliance_terms = ['iso 27001', 'nist', 'cis', 'owasp', 'gdpr', 'hipaa']
        for term in compliance_terms:
            if term in content_lower:
                context['compliance_references'].append(term)
        
        # Check for technical details
        technical_terms = ['hexdump', 'payload', 'packet', 'protocol', 'header']
        context['technical_details'] = any(term in content_lower for term in technical_terms)
        
        # Check for remediation information
        remediation_terms = ['remediation', 'mitigation', 'fix', 'patch', 'solution']
        context['remediation_info'] = any(term in content_lower for term in remediation_terms)
        
        return context
    
    def _clean_document_content(self, content: str) -> str:
        """
        Clean document content by removing reranking metadata
        """
        
        # Remove security metadata prefixes
        lines = content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            if not (line.strip().startswith('[SECURITY_RELEVANCE:') or
                   line.strip().startswith('[DOCUMENT_ID:') or
                   line.strip().startswith('[THREAT_INDICATORS:')):
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines).strip()
    
    def _create_fallback_ranking(self, documents: List[str], top_k: int) -> List[RerankedDocument]:
        """
        Create fallback ranking when Jina API is unavailable
        """
        
        fallback_results = []
        
        for i, doc in enumerate(documents[:top_k]):
            security_score = self._calculate_document_security_relevance(doc)
            
            fallback_results.append(RerankedDocument(
                content=doc,
                relevance_score=security_score,
                original_index=i,
                security_context=self._extract_document_security_context(doc),
                rerank_confidence=0.5  # Default confidence for fallback
            ))
        
        # Sort by security relevance
        fallback_results.sort(key=lambda x: x.relevance_score, reverse=True)
        
        return fallback_results
    
    async def rerank_query_results(self, query: str, query_results: List[Dict], 
                                 top_k: int = 10) -> List[Dict]:
        """
        Rerank query results from knowledge graph with security context
        """
        
        if not query_results:
            return []
        
        # Extract documents from query results
        documents = []
        result_metadata = []
        
        for result in query_results:
            if isinstance(result, dict):
                # Extract text content from various possible fields
                content = (result.get('content') or 
                          result.get('text') or 
                          result.get('document') or 
                          str(result))
                documents.append(content)
                result_metadata.append(result)
            else:
                documents.append(str(result))
                result_metadata.append({'content': str(result)})
        
        # Perform reranking
        reranked_docs = await self.rerank_security_documents(query, documents, top_k)
        
        # Combine reranked results with original metadata
        enhanced_results = []
        
        for reranked_doc in reranked_docs:
            original_metadata = result_metadata[reranked_doc.original_index]
            
            enhanced_result = {
                **original_metadata,
                'rerank_score': reranked_doc.relevance_score,
                'security_context': reranked_doc.security_context,
                'rerank_confidence': reranked_doc.rerank_confidence
            }
            
            enhanced_results.append(enhanced_result)
        
        return enhanced_results