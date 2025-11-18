#!/usr/bin/env python3
"""
Advanced Service Identifier with CVE Database & Exploit Recommendations
Production-grade service fingerprinting and vulnerability correlation
"""

import socket
import re
import json
import argparse
import requests
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import time

class AdvancedServiceIdentifier:
    """Advanced service identification with vulnerability correlation"""
    
    def __init__(self):
        # Enhanced service database with version patterns
        self.service_database = {
            21: {
                'name': 'FTP',
                'description': 'File Transfer Protocol',
                'risk_level': 'HIGH',
                'common_versions': ['vsftpd', 'ProFTPD', 'Pure-FTPd', 'FileZilla Server'],
                'common_vulns': [
                    'Anonymous access enabled',
                    'Cleartext credential transmission',
                    'FTP bounce attack',
                    'Directory traversal'
                ],
                'probes': [b'', b'USER anonymous\r\n'],
                'exploits': {
                    'vsftpd 2.3.4': 'CVE-2011-2523 - Backdoor Command Execution',
                    'ProFTPD 1.3.3c': 'CVE-2010-4221 - SQL Injection',
                }
            },
            22: {
                'name': 'SSH',
                'description': 'Secure Shell',
                'risk_level': 'MEDIUM',
                'common_versions': ['OpenSSH', 'Dropbear', 'libssh'],
                'common_vulns': [
                    'Weak encryption algorithms',
                    'Username enumeration',
                    'Brute force susceptible',
                    'Outdated version'
                ],
                'probes': [b''],
                'exploits': {
                    'OpenSSH < 7.4': 'CVE-2016-10009 - Privilege Escalation',
                    'libssh 0.6.0-0.8.0': 'CVE-2018-10933 - Authentication Bypass',
                }
            },
            23: {
                'name': 'Telnet',
                'description': 'Telnet Protocol',
                'risk_level': 'CRITICAL',
                'common_versions': ['Linux telnetd', 'Windows Telnet'],
                'common_vulns': [
                    'Cleartext protocol - NO ENCRYPTION',
                    'Credentials transmitted in plain text',
                    'Man-in-the-middle attacks',
                    'Session hijacking'
                ],
                'probes': [b''],
                'exploits': {}
            },
            25: {
                'name': 'SMTP',
                'description': 'Simple Mail Transfer Protocol',
                'risk_level': 'MEDIUM',
                'common_versions': ['Postfix', 'Sendmail', 'Exim', 'Microsoft Exchange'],
                'common_vulns': [
                    'Open relay configuration',
                    'User enumeration via VRFY/EXPN',
                    'Email header injection',
                    'Spoofing'
                ],
                'probes': [b'EHLO scanner\r\n'],
                'exploits': {
                    'Exim < 4.92': 'CVE-2019-10149 - Remote Command Execution',
                    'Sendmail < 8.15': 'CVE-2019-18218 - Denial of Service',
                }
            },
            80: {
                'name': 'HTTP',
                'description': 'Hypertext Transfer Protocol',
                'risk_level': 'MEDIUM',
                'common_versions': ['Apache', 'nginx', 'IIS', 'LiteSpeed'],
                'common_vulns': [
                    'Cleartext transmission',
                    'SQL Injection',
                    'XSS vulnerabilities',
                    'CSRF attacks',
                    'Directory traversal'
                ],
                'probes': [b'GET / HTTP/1.1\r\nHost: target\r\n\r\n'],
                'exploits': {
                    'Apache < 2.4.49': 'CVE-2021-41773 - Path Traversal',
                    'IIS 6.0': 'CVE-2017-7269 - Buffer Overflow',
                }
            },
            443: {
                'name': 'HTTPS',
                'description': 'HTTP Secure',
                'risk_level': 'LOW',
                'common_versions': ['Apache', 'nginx', 'IIS'],
                'common_vulns': [
                    'Weak SSL/TLS versions',
                    'Weak cipher suites',
                    'Certificate issues',
                    'Heartbleed vulnerability'
                ],
                'probes': [b''],
                'exploits': {
                    'OpenSSL 1.0.1-1.0.1f': 'CVE-2014-0160 - Heartbleed',
                    'OpenSSL < 1.1.0': 'CVE-2016-2107 - Padding Oracle',
                }
            },
            445: {
                'name': 'SMB',
                'description': 'Server Message Block',
                'risk_level': 'CRITICAL',
                'common_versions': ['Samba', 'Windows SMB'],
                'common_vulns': [
                    'EternalBlue exploit',
                    'SMBGhost vulnerability',
                    'Null session enumeration',
                    'Weak authentication'
                ],
                'probes': [b''],
                'exploits': {
                    'Windows SMB': 'CVE-2017-0144 - EternalBlue (MS17-010)',
                    'Windows 10 v1903-1909': 'CVE-2020-0796 - SMBGhost',
                    'Samba 3.5.0-4.4.14': 'CVE-2017-7494 - Remote Code Execution',
                }
            },
            3306: {
                'name': 'MySQL',
                'description': 'MySQL Database',
                'risk_level': 'HIGH',
                'common_versions': ['MySQL', 'MariaDB', 'Percona'],
                'common_vulns': [
                    'Default credentials',
                    'SQL injection if exposed',
                    'Remote root access',
                    'No password authentication'
                ],
                'probes': [b''],
                'exploits': {
                    'MySQL < 5.7.31': 'CVE-2020-14765 - Information Disclosure',
                    'MySQL < 8.0.21': 'CVE-2020-14672 - Privilege Escalation',
                }
            },
            3389: {
                'name': 'RDP',
                'description': 'Remote Desktop Protocol',
                'risk_level': 'CRITICAL',
                'common_versions': ['Microsoft RDP'],
                'common_vulns': [
                    'BlueKeep vulnerability',
                    'Weak password brute forcing',
                    'Man-in-the-middle attacks',
                    'Session hijacking'
                ],
                'probes': [b''],
                'exploits': {
                    'Windows 7/2008': 'CVE-2019-0708 - BlueKeep RCE',
                    'Windows 10/2019': 'CVE-2019-1181 - RDP RCE',
                }
            },
            5432: {
                'name': 'PostgreSQL',
                'description': 'PostgreSQL Database',
                'risk_level': 'HIGH',
                'common_versions': ['PostgreSQL'],
                'common_vulns': [
                    'Default credentials',
                    'SQL injection',
                    'Privilege escalation',
                    'Data exposure'
                ],
                'probes': [b''],
                'exploits': {
                    'PostgreSQL < 13.2': 'CVE-2021-3393 - Privilege Escalation',
                    'PostgreSQL < 12.6': 'CVE-2021-20229 - Code Execution',
                }
            },
            6379: {
                'name': 'Redis',
                'description': 'Redis In-Memory Database',
                'risk_level': 'CRITICAL',
                'common_versions': ['Redis'],
                'common_vulns': [
                    'No authentication by default',
                    'Command injection',
                    'Lua sandbox escape',
                    'RCE via module loading'
                ],
                'probes': [b'*1\r\n$4\r\ninfo\r\n'],
                'exploits': {
                    'Redis < 5.0.7': 'CVE-2019-10192 - Arbitrary Code Execution',
                    'Redis < 6.0.6': 'CVE-2020-14147 - Integer Overflow',
                }
            },
            8080: {
                'name': 'HTTP-Proxy',
                'description': 'HTTP Alternate/Proxy',
                'risk_level': 'MEDIUM',
                'common_versions': ['Tomcat', 'Jetty', 'Jenkins'],
                'common_vulns': [
                    'Default credentials',
                    'Management interface exposed',
                    'Path traversal',
                    'Arbitrary file upload'
                ],
                'probes': [b'GET / HTTP/1.1\r\nHost: target\r\n\r\n'],
                'exploits': {
                    'Apache Tomcat < 9.0.40': 'CVE-2020-17527 - Request Smuggling',
                    'Jenkins < 2.274': 'CVE-2020-2551 - RCE',
                }
            },
            9200: {
                'name': 'Elasticsearch',
                'description': 'Elasticsearch REST API',
                'risk_level': 'HIGH',
                'common_versions': ['Elasticsearch'],
                'common_vulns': [
                    'No authentication',
                    'Data exposure',
                    'Remote code execution',
                    'Directory traversal'
                ],
                'probes': [b'GET / HTTP/1.1\r\n\r\n'],
                'exploits': {
                    'Elasticsearch < 7.13.3': 'CVE-2021-22145 - Code Execution',
                    'Elasticsearch < 6.8.8': 'CVE-2020-7009 - Code Execution',
                }
            },
            27017: {
                'name': 'MongoDB',
                'description': 'MongoDB Database',
                'risk_level': 'CRITICAL',
                'common_versions': ['MongoDB'],
                'common_vulns': [
                    'No authentication by default',
                    'Exposed to internet',
                    'Data breach risk',
                    'Remote access enabled'
                ],
                'probes': [b''],
                'exploits': {
                    'MongoDB < 4.2.1': 'CVE-2019-2386 - Authorization Bypass',
                    'MongoDB < 3.6.5': 'CVE-2017-18381 - DoS',
                }
            }
        }
        
        # CVE database (simplified - in production would query NVD API)
        self.cve_database = {
            'openssh': [
                {'version': '< 7.4', 'cve': 'CVE-2016-10009', 'severity': 'HIGH', 
                 'description': 'Privilege escalation via untrusted forwarding'},
                {'version': '< 8.4', 'cve': 'CVE-2021-28041', 'severity': 'MEDIUM',
                 'description': 'Double free in ssh-agent'}
            ],
            'apache': [
                {'version': '< 2.4.49', 'cve': 'CVE-2021-41773', 'severity': 'CRITICAL',
                 'description': 'Path traversal and remote code execution'},
                {'version': '< 2.4.50', 'cve': 'CVE-2021-42013', 'severity': 'CRITICAL',
                 'description': 'Path traversal bypass'}
            ],
            'nginx': [
                {'version': '< 1.20.1', 'cve': 'CVE-2021-23017', 'severity': 'HIGH',
                 'description': 'DNS resolver buffer overflow'}
            ],
            'mysql': [
                {'version': '< 8.0.21', 'cve': 'CVE-2020-14672', 'severity': 'MEDIUM',
                 'description': 'Privilege escalation vulnerability'}
            ]
        }
    
    def identify_service(self, port: int, banner: Optional[str] = None) -> Dict:
        """Identify service and gather intelligence"""
        service_info = self.service_database.get(port, {
            'name': 'Unknown',
            'description': 'Unknown Service',
            'risk_level': 'UNKNOWN',
            'common_versions': [],
            'common_vulns': [],
            'exploits': {}
        })
        
        result = {
            'port': port,
            'service': service_info['name'],
            'description': service_info['description'],
            'risk_level': service_info['risk_level'],
            'banner': banner,
            'version': 'Unknown',
            'vulnerabilities': service_info['common_vulns'],
            'exploits': [],
            'cves': [],
            'recommendations': []
        }
        
        # Parse version from banner
        if banner:
            result['version'] = self.extract_version(banner, service_info['name'])
            
            # Match CVEs
            result['cves'] = self.find_cves(service_info['name'], result['version'], banner)
            
            # Match exploits
            for version_pattern, exploit in service_info['exploits'].items():
                if self.version_matches(result['version'], version_pattern, banner):
                    result['exploits'].append({
                        'target_version': version_pattern,
                        'exploit': exploit
                    })
        
        # Generate recommendations
        result['recommendations'] = self.generate_recommendations(result)
        
        # Calculate risk score
        result['risk_score'] = self.calculate_risk_score(result)
        
        return result
    
    def extract_version(self, banner: str, service: str) -> str:
        """Extract version from banner"""
        # Common version patterns
        patterns = [
            r'(?:Apache|nginx|OpenSSH|MySQL|Redis|MongoDB)/(\d+\.\d+(?:\.\d+)?)',
            r'(?:Version|ver|v)[\s:]*(\d+\.\d+(?:\.\d+)?)',
            r'(\d+\.\d+\.\d+[a-z]?)',
            r'(\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'Unknown'
    
    def version_matches(self, version: str, pattern: str, banner: str) -> bool:
        """Check if version matches vulnerability pattern"""
        if version == 'Unknown':
            # Try to match from banner directly
            return any(v.lower() in banner.lower() for v in pattern.split())
        
        # Simple version comparison (in production, use proper version parsing)
        return pattern.lower() in banner.lower()
    
    def find_cves(self, service: str, version: str, banner: str) -> List[Dict]:
        """Find CVEs for service version"""
        cves = []
        service_key = service.lower()
        
        if service_key in self.cve_database:
            for cve_entry in self.cve_database[service_key]:
                # Simple matching (in production, use proper version comparison)
                if version != 'Unknown' or any(term in banner.lower() for term in cve_entry['version'].split()):
                    cves.append(cve_entry)
        
        return cves
    
    def calculate_risk_score(self, service_info: Dict) -> int:
        """Calculate risk score (0-100)"""
        score = 0
        
        # Base score by risk level
        risk_scores = {
            'CRITICAL': 50,
            'HIGH': 35,
            'MEDIUM': 20,
            'LOW': 10,
            'UNKNOWN': 5
        }
        score += risk_scores.get(service_info['risk_level'], 0)
        
        # Add for CVEs
        score += len(service_info['cves']) * 10
        
        # Add for exploits
        score += len(service_info['exploits']) * 15
        
        # Critical services
        if service_info['service'] in ['Telnet', 'FTP', 'MongoDB', 'Redis']:
            score += 20
        
        return min(score, 100)
    
    def generate_recommendations(self, service_info: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        service = service_info['service'].lower()
        
        # Service-specific recommendations
        if service == 'telnet':
            recommendations.append('⚠️ CRITICAL: Replace Telnet with SSH immediately')
            recommendations.append('Telnet transmits credentials in cleartext')
        
        elif service == 'ftp':
            recommendations.append('Consider using SFTP or FTPS instead')
            recommendations.append('Disable anonymous access')
            recommendations.append('Use strong authentication')
        
        elif service == 'ssh':
            recommendations.append('Disable password authentication, use keys')
            recommendations.append('Change default port (22)')
            recommendations.append('Implement fail2ban for brute force protection')
        
        elif service in ['mysql', 'postgresql', 'mongodb', 'redis']:
            recommendations.append('Do NOT expose database to internet')
            recommendations.append('Use strong authentication')
            recommendations.append('Bind to localhost only')
            recommendations.append('Implement firewall rules')
        
        elif service == 'rdp':
            recommendations.append('Use VPN or bastion host')
            recommendations.append('Enable Network Level Authentication (NLA)')
            recommendations.append('Use strong passwords/2FA')
            recommendations.append('Limit RDP access by IP')
        
        elif service == 'smb':
            recommendations.append('Patch against EternalBlue (MS17-010)')
            recommendations.append('Disable SMBv1')
            recommendations.append('Use SMB signing')
        
        # CVE-based recommendations
        if service_info['cves']:
            recommendations.append(f'UPDATE REQUIRED: {len(service_info["cves"])} CVEs found')
            for cve in service_info['cves'][:3]:
                recommendations.append(f'Patch {cve["cve"]} ({cve["severity"]})')
        
        # Exploit-based recommendations
        if service_info['exploits']:
            recommendations.append(f'⚠️ {len(service_info["exploits"])} public exploits available')
            recommendations.append('Upgrade immediately or isolate from network')
        
        return recommendations
    
    def scan_target(self, target: str, port: int, timeout: int = 3) -> Dict:
        """Scan target and identify service"""
        try:
            # Resolve target
            if '://' in target:
                target = target.split('://')[1].split('/')[0]
            if ':' in target:
                target = target.split(':')[0]
            
            ip = socket.gethostbyname(target)
            
            # Try to connect and grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((ip, port))
            if result != 0:
                return {'error': f'Port {port} is closed or filtered'}
            
            # Grab banner
            banner = None
            try:
                # Try receiving banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                # Try sending probe
                service_info = self.service_database.get(port, {})
                if 'probes' in service_info and service_info['probes']:
                    probe = service_info['probes'][0]
                    if probe:
                        sock.send(probe)
                        time.sleep(0.2)
                        try:
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        except:
                            pass
            
            sock.close()
            
            # Identify service
            return self.identify_service(port, banner)
            
        except Exception as e:
            return {'error': str(e)}
    
    def print_service_info(self, service_info: Dict):
        """Print formatted service information"""
        if 'error' in service_info:
            print(f"❌ Error: {service_info['error']}")
            return
        
        risk_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'UNKNOWN': '⚪'
        }
        
        icon = risk_colors.get(service_info['risk_level'], '⚪')
        
        print("\n" + "="*70)
        print(f"{icon} SERVICE IDENTIFICATION REPORT")
        print("="*70)
        print(f"Port: {service_info['port']}")
        print(f"Service: {service_info['service']}")
        print(f"Description: {service_info['description']}")
        print(f"Risk Level: {service_info['risk_level']}")
        print(f"Risk Score: {service_info['risk_score']}/100")
        
        if service_info['banner']:
            print(f"\nBanner:")
            print(f"  {service_info['banner'][:200]}")
        
        if service_info['version'] != 'Unknown':
            print(f"\nDetected Version: {service_info['version']}")
        
        # Vulnerabilities
        if service_info['vulnerabilities']:
            print(f"\n⚠️  Common Vulnerabilities:")
            for vuln in service_info['vulnerabilities']:
                print(f"  • {vuln}")
        
        # CVEs
        if service_info['cves']:
            print(f"\n🔍 Known CVEs:")
            for cve in service_info['cves']:
                sev_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡'}.get(cve['severity'], '⚪')
                print(f"  {sev_icon} {cve['cve']} - {cve['severity']}")
                print(f"     {cve['description']}")
        
        # Exploits
        if service_info['exploits']:
            print(f"\n💣 Public Exploits Available:")
            for exploit in service_info['exploits']:
                print(f"  • {exploit['exploit']}")
                print(f"    Target: {exploit['target_version']}")
        
        # Recommendations
        if service_info['recommendations']:
            print(f"\n💡 Security Recommendations:")
            for rec in service_info['recommendations']:
                print(f"  • {rec}")
        
        print("="*70)
    
    def bulk_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """Scan multiple ports"""
        results = []
        
        print(f"\n[*] Scanning {target} on {len(ports)} ports...\n")
        
        for port in ports:
            print(f"[+] Scanning port {port}...", end=' ')
            result = self.scan_target(target, port)
            
            if 'error' not in result:
                print(f"✓ {result['service']}")
                results.append(result)
            else:
                print(f"✗ {result['error']}")
        
        return results
    
    def generate_report(self, results: List[Dict], output_file: str):
        """Generate JSON report"""
        report = {
            'scan_time': datetime.now().isoformat(),
            'total_services': len(results),
            'risk_summary': {
                'critical': len([r for r in results if r['risk_level'] == 'CRITICAL']),
                'high': len([r for r in results if r['risk_level'] == 'HIGH']),
                'medium': len([r for r in results if r['risk_level'] == 'MEDIUM']),
                'low': len([r for r in results if r['risk_level'] == 'LOW']),
            },
            'services': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Service Identifier with CVE Database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_service_identifier.py 192.168.1.1 -p 80
  python advanced_service_identifier.py example.com -p 22,80,443,3306
  python advanced_service_identifier.py 10.0.0.1 --common -o report.json
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80 or 80,443,3306)')
    parser.add_argument('--common', action='store_true', help='Scan common ports')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("="*70)
    print("ADVANCED SERVICE IDENTIFIER v2.0")
    print("CVE Database | Exploit Correlation | Security Recommendations")
    print("="*70)
    
    identifier = AdvancedServiceIdentifier()
    
    # Determine ports
    if args.common:
        ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 9200, 27017]
    elif args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        print("\nError: Specify ports with -p or use --common")
        return
    
    # Scan
    if len(ports) == 1:
        result = identifier.scan_target(args.target, ports[0])
        identifier.print_service_info(result)
        
        if args.output and 'error' not in result:
            identifier.generate_report([result], args.output)
    else:
        results = identifier.bulk_scan(args.target, ports)
        
        # Print summary
        print("\n" + "="*70)
        print("BULK SCAN SUMMARY")
        print("="*70)
        for result in results:
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(result['risk_level'], '⚪')
            print(f"{icon} Port {result['port']:<6} {result['service']:<15} [{result['risk_level']}]")
        
        if args.output:
            identifier.generate_report(results, args.output)


if __name__ == "__main__":
    main()
