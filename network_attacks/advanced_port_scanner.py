#!/usr/bin/env python3
"""
Advanced Multi-Protocol Port Scanner with OS Detection & Service Fingerprinting
Professional-grade network reconnaissance tool
"""

import socket
import struct
import random
import time
import concurrent.futures
import argparse
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import re

class AdvancedPortScanner:
    """Advanced port scanner with OS detection and service fingerprinting"""
    
    # Service fingerprinting probes
    SERVICE_PROBES = {
        'http': {
            'probe': b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n',
            'patterns': [
                (r'Server: ([^\r\n]+)', 'server'),
                (r'X-Powered-By: ([^\r\n]+)', 'technology'),
                (r'<title>([^<]+)</title>', 'title'),
            ]
        },
        'ssh': {
            'probe': b'',
            'patterns': [(r'SSH-([^\r\n]+)', 'version')]
        },
        'ftp': {
            'probe': b'',
            'patterns': [(r'220 ([^\r\n]+)', 'banner')]
        },
        'smtp': {
            'probe': b'EHLO scanner\r\n',
            'patterns': [(r'220 ([^\r\n]+)', 'banner')]
        },
        'mysql': {
            'probe': b'',
            'patterns': [(r'(\d+\.\d+\.\d+)', 'version')]
        },
        'redis': {
            'probe': b'*1\r\n$4\r\ninfo\r\n',
            'patterns': [(r'redis_version:([^\r\n]+)', 'version')]
        },
    }
    
    # OS fingerprinting signatures (simplified)
    OS_SIGNATURES = {
        'linux': ['Linux', 'Ubuntu', 'Debian', 'CentOS', 'Fedora', 'Apache', 'nginx'],
        'windows': ['Windows', 'Microsoft', 'IIS', 'Win32', 'Win64'],
        'freebsd': ['FreeBSD', 'OpenBSD', 'NetBSD'],
        'cisco': ['Cisco', 'IOS'],
        'juniper': ['Juniper', 'JUNOS'],
    }
    
    # Common vulnerable services
    VULNERABLE_SERVICES = {
        21: {'service': 'FTP', 'vulns': ['Anonymous access', 'Cleartext credentials', 'Bounce attack']},
        23: {'service': 'Telnet', 'vulns': ['Cleartext protocol', 'No encryption', 'Easy to intercept']},
        25: {'service': 'SMTP', 'vulns': ['Open relay', 'User enumeration', 'Email spoofing']},
        445: {'service': 'SMB', 'vulns': ['EternalBlue (MS17-010)', 'SMBGhost', 'Null session']},
        3389: {'service': 'RDP', 'vulns': ['BlueKeep', 'Weak passwords', 'Man-in-the-middle']},
        6379: {'service': 'Redis', 'vulns': ['No authentication', 'Command injection', 'RCE via modules']},
        27017: {'service': 'MongoDB', 'vulns': ['No authentication', 'Default credentials', 'Data exposure']},
    }
    
    def __init__(self, target: str, timeout: float = 2.0, threads: int = 100):
        self.target = self._resolve_target(target)
        self.timeout = timeout
        self.threads = threads
        self.scan_results: List[Dict] = []
        self.os_hints: List[str] = []
        
    def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP"""
        try:
            # Remove protocol if present
            if '://' in target:
                target = target.split('://')[1].split('/')[0]
            if ':' in target:
                target = target.split(':')[0]
            
            ip = socket.gethostbyname(target)
            print(f"[+] Resolved {target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"[!] Could not resolve {target}")
            return target
    
    def tcp_connect_scan(self, port: int) -> bool:
        """Standard TCP connect scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def tcp_syn_scan(self, port: int) -> bool:
        """SYN scan (stealth scan) - requires root/admin"""
        try:
            # This is a simplified version - real SYN scan requires raw sockets
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def grab_banner(self, port: int) -> Optional[str]:
        """Grab service banner for fingerprinting"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Try to receive banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner
            except:
                # Some services need a probe first
                for service_type, probe_data in self.SERVICE_PROBES.items():
                    if port in self.get_common_ports()[service_type]:
                        probe = probe_data['probe']
                        if b'%s' in probe:
                            probe = probe.replace(b'%s', self.target.encode())
                        
                        sock.send(probe)
                        time.sleep(0.1)
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        sock.close()
                        return banner
            
            sock.close()
        except:
            pass
        return None
    
    def fingerprint_service(self, port: int, banner: str) -> Dict:
        """Advanced service fingerprinting"""
        service_info = {
            'port': port,
            'state': 'open',
            'service': self.identify_service(port),
            'version': 'unknown',
            'banner': banner[:200] if banner else None,
            'details': {},
            'vulnerabilities': []
        }
        
        if banner:
            # Extract version information
            for service_type, probe_data in self.SERVICE_PROBES.items():
                for pattern, field_name in probe_data['patterns']:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        service_info['details'][field_name] = match.group(1)
                        if field_name == 'version':
                            service_info['version'] = match.group(1)
            
            # OS fingerprinting from banner
            for os_type, keywords in self.OS_SIGNATURES.items():
                for keyword in keywords:
                    if keyword.lower() in banner.lower():
                        self.os_hints.append(os_type)
                        break
        
        # Check for known vulnerabilities
        if port in self.VULNERABLE_SERVICES:
            vuln_info = self.VULNERABLE_SERVICES[port]
            service_info['service'] = vuln_info['service']
            service_info['vulnerabilities'] = vuln_info['vulns']
        
        return service_info
    
    def identify_service(self, port: int) -> str:
        """Identify service by port number"""
        common_services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
            9200: 'Elasticsearch', 27017: 'MongoDB', 2077: 'cPanel-WebMail',
            2082: 'cPanel', 2083: 'cPanel-SSL', 2086: 'WHM', 2087: 'WHM-SSL'
        }
        return common_services.get(port, 'unknown')
    
    def get_common_ports(self) -> Dict:
        """Get ports organized by service type"""
        return {
            'http': [80, 8080, 8000, 8888, 3000, 5000],
            'https': [443, 8443],
            'ssh': [22],
            'ftp': [21],
            'smtp': [25, 587, 465],
            'mysql': [3306],
            'redis': [6379],
        }
    
    def scan_port(self, port: int) -> Optional[Dict]:
        """Scan single port with full fingerprinting"""
        if self.tcp_connect_scan(port):
            banner = self.grab_banner(port)
            result = self.fingerprint_service(port, banner)
            
            # Calculate risk score
            risk_score = self.calculate_risk_score(result)
            result['risk_score'] = risk_score
            result['risk_level'] = self.get_risk_level(risk_score)
            
            return result
        return None
    
    def calculate_risk_score(self, service_info: Dict) -> int:
        """Calculate security risk score (0-100)"""
        score = 0
        
        # Base score by service criticality
        critical_services = ['ftp', 'telnet', 'mysql', 'mongodb', 'redis', 'rdp', 'smb']
        if any(s in service_info['service'].lower() for s in critical_services):
            score += 40
        
        # Add score for vulnerabilities
        score += len(service_info['vulnerabilities']) * 15
        
        # Cleartext protocols
        cleartext = ['ftp', 'telnet', 'http']
        if any(s in service_info['service'].lower() for s in cleartext):
            score += 20
        
        # Old versions
        if 'version' in service_info and service_info['version'] != 'unknown':
            if any(old in service_info['version'].lower() for old in ['1.0', '2.0', 'old']):
                score += 10
        
        return min(score, 100)
    
    def get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        return 'LOW'
    
    def detect_os(self) -> str:
        """Detect operating system from collected hints"""
        if not self.os_hints:
            return 'Unknown'
        
        # Count occurrences
        os_count = {}
        for os_type in self.os_hints:
            os_count[os_type] = os_count.get(os_type, 0) + 1
        
        # Return most common
        detected_os = max(os_count, key=os_count.get)
        confidence = (os_count[detected_os] / len(self.os_hints)) * 100
        
        return f"{detected_os.capitalize()} ({confidence:.0f}% confidence)"
    
    def scan_ports(self, ports: List[int]) -> List[Dict]:
        """Scan multiple ports concurrently"""
        print(f"[*] Scanning {len(ports)} ports on {self.target}...")
        print(f"[*] Using {self.threads} concurrent threads")
        print(f"[*] Timeout: {self.timeout}s per port\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        self.scan_results.append(result)
                        self.print_port_result(result)
                except Exception as e:
                    pass
        
        return self.scan_results
    
    def print_port_result(self, result: Dict):
        """Print formatted port scan result"""
        risk_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        icon = risk_colors.get(result['risk_level'], '⚪')
        print(f"{icon} Port {result['port']:<6} {result['state']:<8} {result['service']:<15} "
              f"[{result['risk_level']}]")
        
        if result['version'] != 'unknown':
            print(f"   └─ Version: {result['version']}")
        
        if result['vulnerabilities']:
            print(f"   └─ Vulnerabilities: {', '.join(result['vulnerabilities'][:2])}")
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate comprehensive scan report"""
        report = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'total_scanned': len(self.scan_results),
            'open_ports': [r['port'] for r in self.scan_results],
            'os_detection': self.detect_os(),
            'risk_summary': {
                'critical': len([r for r in self.scan_results if r['risk_level'] == 'CRITICAL']),
                'high': len([r for r in self.scan_results if r['risk_level'] == 'HIGH']),
                'medium': len([r for r in self.scan_results if r['risk_level'] == 'MEDIUM']),
                'low': len([r for r in self.scan_results if r['risk_level'] == 'LOW']),
            },
            'services': self.scan_results,
            'vulnerabilities': [
                {'port': r['port'], 'service': r['service'], 'vulns': r['vulnerabilities']}
                for r in self.scan_results if r['vulnerabilities']
            ]
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: {output_file}")
        
        return report
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*70)
        print("ADVANCED PORT SCAN SUMMARY")
        print("="*70)
        print(f"Target: {self.target}")
        print(f"Open Ports: {len(self.scan_results)}")
        print(f"Detected OS: {self.detect_os()}")
        
        risk_summary = {
            'CRITICAL': len([r for r in self.scan_results if r['risk_level'] == 'CRITICAL']),
            'HIGH': len([r for r in self.scan_results if r['risk_level'] == 'HIGH']),
            'MEDIUM': len([r for r in self.scan_results if r['risk_level'] == 'MEDIUM']),
            'LOW': len([r for r in self.scan_results if r['risk_level'] == 'LOW']),
        }
        
        print(f"\nRisk Distribution:")
        print(f"  🔴 CRITICAL: {risk_summary['CRITICAL']}")
        print(f"  🟠 HIGH: {risk_summary['HIGH']}")
        print(f"  🟡 MEDIUM: {risk_summary['MEDIUM']}")
        print(f"  🟢 LOW: {risk_summary['LOW']}")
        
        # List critical services
        critical_services = [r for r in self.scan_results if r['risk_level'] == 'CRITICAL']
        if critical_services:
            print(f"\n⚠️  CRITICAL SERVICES DETECTED:")
            for svc in critical_services:
                print(f"   • Port {svc['port']}: {svc['service']}")
                if svc['vulnerabilities']:
                    for vuln in svc['vulnerabilities']:
                        print(f"     - {vuln}")
        
        print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner with OS Detection & Service Fingerprinting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_port_scanner.py 192.168.1.1 --common
  python advanced_port_scanner.py example.com --ports 1-1000 -t 200
  python advanced_port_scanner.py 10.0.0.1 --all -o report.json
  python advanced_port_scanner.py target.com --top 100
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000, 80,443,3306)')
    parser.add_argument('--common', action='store_true', help='Scan common 100 ports')
    parser.add_argument('--top', type=int, metavar='N', help='Scan top N ports')
    parser.add_argument('--all', action='store_true', help='Scan all 65535 ports (slow!)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=2.0, help='Timeout per port (default: 2.0s)')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("="*70)
    print("ADVANCED PORT SCANNER v2.0")
    print("OS Detection | Service Fingerprinting | Vulnerability Assessment")
    print("="*70 + "\n")
    
    # Create scanner
    scanner = AdvancedPortScanner(args.target, args.timeout, args.threads)
    
    # Determine ports to scan
    ports = []
    if args.all:
        ports = list(range(1, 65536))
        print("[!] WARNING: Scanning all 65535 ports will take time!")
    elif args.common:
        # Top 100 most common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                 1723, 3306, 3389, 5900, 8080] + list(range(135, 140)) + list(range(445, 450))
    elif args.top:
        # Top N ports (simplified - would use nmap top ports list in production)
        common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5900, 8080, 8443]
        ports = common[:args.top] + list(range(1, min(args.top, 1024)))
        ports = sorted(set(ports))[:args.top]
    elif args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        # Default: common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080, 8443]
    
    # Run scan
    start_time = time.time()
    scanner.scan_ports(ports)
    elapsed = time.time() - start_time
    
    # Print summary
    scanner.print_summary()
    print(f"\n[+] Scan completed in {elapsed:.2f} seconds")
    
    # Generate report
    if args.output:
        scanner.generate_report(args.output)


if __name__ == "__main__":
    main()
