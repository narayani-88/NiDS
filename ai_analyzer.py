#!/usr/bin/env python3
"""
NIDS - AI Network Analysis Module
Uses Google Gemini AI to analyze network security data and provide intelligent insights.
"""

import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Any

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    genai = None

class AINetworkAnalyzer:
    def __init__(self, api_key: str):
        """Initialize the AI analyzer with Gemini API key"""
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)
        self.model = None
        
        if GENAI_AVAILABLE and api_key:
            try:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-pro')
                self.logger.info("Gemini AI model initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize Gemini AI: {e}")
                self.model = None
        else:
            self.logger.warning("Gemini AI not available - using fallback analysis")
        
    def analyze_network_security(self, devices: Dict, vulnerabilities: List) -> Dict[str, Any]:
        """Generate comprehensive AI analysis of network security"""
        # Prepare network data summary first
        network_summary = self._prepare_network_summary(devices, vulnerabilities)
        
        # Try AI analysis with retries
        ai_analysis = None
        if self.model:
            ai_analysis = self._try_ai_analysis_with_retry(network_summary, max_retries=2)
        
        # Use fallback if AI failed
        if not ai_analysis:
            ai_analysis = self._generate_fallback_analysis(network_summary)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'network_summary': network_summary,
            'ai_analysis': ai_analysis,
            'recommendations': self._generate_recommendations(devices, vulnerabilities),
            'risk_score': self._calculate_risk_score(devices, vulnerabilities),
            'analysis_method': 'ai' if self.model and ai_analysis.get('ai_generated') else 'rule_based'
        }
    
    def _prepare_network_summary(self, devices: Dict, vulnerabilities: List) -> Dict:
        """Prepare a summary of network data for AI analysis"""
        device_types = {}
        open_ports = {}
        services = {}
        
        for ip, device in devices.items():
            # Categorize devices by hostname patterns
            hostname = device.get('hostname', 'Unknown')
            if 'PC' in hostname.upper():
                device_types['workstations'] = device_types.get('workstations', 0) + 1
            elif 'SERVER' in hostname.upper():
                device_types['servers'] = device_types.get('servers', 0) + 1
            else:
                device_types['other'] = device_types.get('other', 0) + 1
            
            # Count open ports and services
            for port_info in device.get('ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'Unknown')
                
                if port:
                    open_ports[port] = open_ports.get(port, 0) + 1
                    services[service] = services.get(service, 0) + 1
        
        # Vulnerability summary
        vuln_summary = {
            'total': len(vulnerabilities),
            'high': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
            'medium': len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
            'low': len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
        }
        
        return {
            'total_devices': len(devices),
            'device_types': device_types,
            'common_ports': dict(sorted(open_ports.items(), key=lambda x: x[1], reverse=True)[:10]),
            'common_services': dict(sorted(services.items(), key=lambda x: x[1], reverse=True)[:10]),
            'vulnerabilities': vuln_summary
        }
    
    def _create_analysis_prompt(self, network_summary: Dict) -> str:
        """Create a detailed prompt for AI analysis"""
        return f"""
As a cybersecurity expert, analyze this network security scan data and provide insights:

NETWORK OVERVIEW:
- Total Devices: {network_summary['total_devices']}
- Device Types: {network_summary['device_types']}
- Most Common Open Ports: {network_summary['common_ports']}
- Most Common Services: {network_summary['common_services']}
- Vulnerabilities: {network_summary['vulnerabilities']}

Please provide:
1. SECURITY ASSESSMENT: Overall security posture (Good/Fair/Poor) with reasoning
2. KEY FINDINGS: Top 3-5 most important security observations
3. IMMEDIATE RISKS: Critical issues that need urgent attention
4. NETWORK TOPOLOGY INSIGHTS: What the scan reveals about network structure
5. COMPLIANCE CONSIDERATIONS: Potential regulatory or best practice violations

Keep the analysis concise, actionable, and focused on practical security improvements.
Format the response in clear sections with bullet points where appropriate.
"""
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, str]:
        """Parse AI response into structured sections"""
        sections = {
            'security_assessment': '',
            'key_findings': '',
            'immediate_risks': '',
            'topology_insights': '',
            'compliance_notes': ''
        }
        
        try:
            # Simple parsing - look for section headers
            lines = response_text.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                if 'SECURITY ASSESSMENT' in line.upper():
                    current_section = 'security_assessment'
                elif 'KEY FINDINGS' in line.upper():
                    current_section = 'key_findings'
                elif 'IMMEDIATE RISKS' in line.upper():
                    current_section = 'immediate_risks'
                elif 'TOPOLOGY INSIGHTS' in line.upper() or 'NETWORK TOPOLOGY' in line.upper():
                    current_section = 'topology_insights'
                elif 'COMPLIANCE' in line.upper():
                    current_section = 'compliance_notes'
                elif current_section and line:
                    sections[current_section] += line + '\n'
            
            # If parsing fails, put everything in key_findings
            if not any(sections.values()):
                sections['key_findings'] = response_text
                
        except Exception as e:
            self.logger.error(f"Failed to parse AI response: {e}")
            sections['key_findings'] = response_text
        
        return sections
    
    def _generate_recommendations(self, devices: Dict, vulnerabilities: List) -> List[Dict]:
        """Generate specific security recommendations"""
        recommendations = []
        
        # Check for common security issues
        risky_services = ['FTP', 'Telnet', 'HTTP', 'SMB']
        exposed_services = {}
        
        for ip, device in devices.items():
            for port_info in device.get('ports', []):
                service = port_info.get('service', '')
                if any(risky in service for risky in risky_services):
                    exposed_services[service] = exposed_services.get(service, 0) + 1
        
        # Generate recommendations based on findings
        if 'Telnet' in exposed_services:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Insecure Protocols',
                'title': 'Replace Telnet with SSH',
                'description': f'Found {exposed_services["Telnet"]} devices with Telnet exposed. Replace with SSH for encrypted remote access.',
                'action': 'Disable Telnet service and configure SSH with key-based authentication.'
            })
        
        if 'FTP' in exposed_services:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Insecure Protocols',
                'title': 'Secure File Transfer',
                'description': f'Found {exposed_services["FTP"]} devices with FTP exposed. Use SFTP or FTPS instead.',
                'action': 'Replace FTP with SFTP or configure FTP with TLS encryption.'
            })
        
        if 'HTTP' in exposed_services:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Encryption',
                'title': 'Enable HTTPS',
                'description': f'Found {exposed_services["HTTP"]} devices with unencrypted HTTP. Implement HTTPS.',
                'action': 'Configure SSL/TLS certificates and redirect HTTP to HTTPS.'
            })
        
        # Add general recommendations
        if len(devices) > 20:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Network Segmentation',
                'title': 'Consider Network Segmentation',
                'description': 'Large network detected. Consider implementing VLANs for better security.',
                'action': 'Segment network by device type and implement appropriate access controls.'
            })
        
        return recommendations
    
    def _calculate_risk_score(self, devices: Dict, vulnerabilities: List) -> Dict:
        """Calculate overall network risk score"""
        risk_factors = {
            'high_vulns': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']) * 10,
            'medium_vulns': len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']) * 5,
            'low_vulns': len([v for v in vulnerabilities if v.get('severity') == 'LOW']) * 1,
            'device_count': min(len(devices) * 0.5, 20),  # Cap at 20 points
            'open_ports': sum(len(d.get('ports', [])) for d in devices.values()) * 0.1
        }
        
        total_risk = sum(risk_factors.values())
        
        # Normalize to 0-100 scale
        risk_score = min(total_risk, 100)
        
        if risk_score >= 70:
            risk_level = 'HIGH'
            risk_color = 'danger'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
            risk_color = 'warning'
        else:
            risk_level = 'LOW'
            risk_color = 'success'
        
        return {
            'score': round(risk_score, 1),
            'level': risk_level,
            'color': risk_color,
            'factors': risk_factors
        }
    
    def _try_ai_analysis_with_retry(self, network_summary: Dict, max_retries: int = 2) -> Dict:
        """Try AI analysis with retry logic"""
        for attempt in range(max_retries + 1):
            try:
                self.logger.info(f"AI analysis attempt {attempt + 1}/{max_retries + 1}")
                
                # Generate AI analysis
                analysis_prompt = self._create_analysis_prompt(network_summary)
                response = self.model.generate_content(analysis_prompt)
                
                # Parse and structure the response
                ai_analysis = self._parse_ai_response(response.text)
                ai_analysis['ai_generated'] = True
                
                self.logger.info("AI analysis completed successfully")
                return ai_analysis
                
            except Exception as e:
                self.logger.warning(f"AI analysis attempt {attempt + 1} failed: {e}")
                
                if attempt < max_retries:
                    wait_time = (attempt + 1) * 5  # Progressive backoff: 5s, 10s
                    self.logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    self.logger.error(f"All AI analysis attempts failed. Last error: {e}")
        
        return None
    
    def _generate_fallback_analysis(self, network_summary: Dict) -> Dict:
        """Generate intelligent rule-based analysis when AI is unavailable"""
        total_devices = network_summary['total_devices']
        vulns = network_summary['vulnerabilities']
        device_types = network_summary['device_types']
        common_ports = network_summary['common_ports']
        
        # Generate security assessment
        if vulns['high'] > 0:
            security_level = "POOR"
            security_reason = f"Critical security issues detected: {vulns['high']} high-severity vulnerabilities require immediate attention."
        elif vulns['medium'] > 3:
            security_level = "FAIR"
            security_reason = f"Multiple medium-risk issues found: {vulns['medium']} vulnerabilities need addressing."
        elif total_devices > 50:
            security_level = "FAIR"
            security_reason = "Large network detected - consider implementing network segmentation and enhanced monitoring."
        else:
            security_level = "GOOD"
            security_reason = "Network shows good security posture with minimal critical issues."
        
        # Generate key findings
        findings = []
        findings.append(f"Network contains {total_devices} active devices")
        
        if device_types.get('servers', 0) > 0:
            findings.append(f"Identified {device_types['servers']} server(s) - ensure proper hardening")
        
        if 23 in common_ports:  # Telnet
            findings.append("⚠️ Telnet service detected - major security risk")
        
        if 21 in common_ports:  # FTP
            findings.append("⚠️ FTP service detected - consider SFTP alternative")
        
        if 445 in common_ports:  # SMB
            findings.append("SMB file sharing detected - verify security configuration")
        
        # Generate immediate risks
        risks = []
        if vulns['high'] > 0:
            risks.append(f"🔴 {vulns['high']} high-severity vulnerabilities require immediate patching")
        
        if 23 in common_ports:
            risks.append("🔴 Telnet protocol exposes credentials in plaintext")
        
        if vulns['medium'] > 5:
            risks.append(f"🟡 {vulns['medium']} medium-risk issues may be exploitable")
        
        if not risks:
            risks.append("✅ No immediate critical risks identified")
        
        # Generate topology insights
        topology = []
        if device_types.get('workstations', 0) > 10:
            topology.append(f"Large workstation environment ({device_types['workstations']} PCs) - consider VLAN segmentation")
        
        if device_types.get('servers', 0) > 0:
            topology.append("Server infrastructure detected - implement DMZ if internet-facing")
        
        if len(common_ports) > 10:
            topology.append("Multiple services running - review necessity and security of each service")
        
        return {
            'security_assessment': f"Security Level: {security_level}\n\n{security_reason}",
            'key_findings': '\n'.join([f"• {finding}" for finding in findings]),
            'immediate_risks': '\n'.join(risks),
            'topology_insights': '\n'.join([f"• {insight}" for insight in topology]) if topology else "Standard network topology detected",
            'compliance_notes': "Consider implementing: Access controls, Regular patching, Network monitoring, Incident response procedures",
            'ai_generated': False
        }

def test_ai_analyzer():
    """Test function for the AI analyzer"""
    # Test with sample data
    sample_devices = {
        '192.168.1.1': {'hostname': 'Router', 'ports': [{'port': 80, 'service': 'HTTP'}]},
        '192.168.1.100': {'hostname': 'PC1', 'ports': []}
    }
    sample_vulns = []
    
    analyzer = AINetworkAnalyzer("test_key")
    result = analyzer.analyze_network_security(sample_devices, sample_vulns)
    print(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    test_ai_analyzer()
