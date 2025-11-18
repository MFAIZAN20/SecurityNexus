#!/usr/bin/env python3
"""
Advanced Directory & File Fuzzer
Discovers hidden directories, files, backups, and sensitive information
"""

import argparse
import concurrent.futures
import json
from datetime import datetime
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin

import requests

from common.http_client import build_session

class DirectoryFuzzer:
    """Advanced directory and file discovery tool"""
    
    # Common interesting directories and files
    COMMON_PATHS = [
        # Admin panels
        'admin', 'administrator', 'admin.php', 'admin.html', 'admin/', 'admin/login', 
        'admin/dashboard', 'cp', 'cpanel', 'control', 'manage', 'management',
        
        # API endpoints
        'api', 'api/', 'api/v1', 'api/v2', 'api/docs', 'api-docs', 'swagger', 
        'swagger-ui', 'swagger.json', 'openapi.json', 'graphql', 'graphiql',
        
        # Git / Version Control
        '.git', '.git/config', '.git/HEAD', '.git/index', '.gitignore', '.svn', 
        '.hg', '.bzr', 'CVS',
        
        # Environment and config files
        '.env', '.env.local', '.env.production', '.env.backup', 'config.php', 
        'configuration.php', 'settings.php', 'database.php', 'db.php', 'config.json',
        'config.yml', 'application.properties', 'web.config', 'app.config',
        
        # Backups
        'backup', 'backup.zip', 'backup.sql', 'backup.tar.gz', 'db_backup.sql',
        'site.zip', 'www.zip', 'website.zip', 'old', 'old.zip', 'backup.tar',
        
        # Common CMS paths
        'wp-admin', 'wp-login.php', 'wp-config.php', 'wp-content', 'wordpress',
        'joomla', 'drupal', 'administrator', 'phpmyadmin', 'pma',
        
        # Debug and test files
        'test', 'test.php', 'test.html', 'debug', 'phpinfo.php', 'info.php',
        'test.txt', 'debug.log', 'error.log', 'console', 'trace',
        
        # Documentation
        'docs', 'documentation', 'api-docs', 'swagger', 'readme.md', 'README.md',
        'CHANGELOG.md', 'TODO.txt',
        
        # Source code leaks
        'src', 'source', 'app', 'includes', 'inc', 'core', 'lib', 'vendor',
        'node_modules', '.env', 'composer.json', 'package.json',
        
        # Database dumps
        'dump.sql', 'database.sql', 'db.sql', 'mysql.sql', 'backup.sql',
        'data.sql', 'users.sql',
        
        # Logs
        'logs', 'log', 'access.log', 'error.log', 'debug.log', 'application.log',
        'system.log', 'app.log',
        
        # Sensitive files
        'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
        '.htaccess', '.htpasswd', 'web.config', 'WEB-INF/web.xml',
        
        # Upload directories
        'uploads', 'upload', 'files', 'media', 'images', 'assets', 'static',
        'public', 'attachments',
        
        # Framework-specific
        'laravel', 'storage', 'bootstrap', 'vendor/composer', '.idea', '.vscode',
        'package-lock.json', 'yarn.lock', 'Gemfile', 'requirements.txt',
    ]
    
    # File extensions to try
    EXTENSIONS = ['', '.php', '.html', '.txt', '.bak', '.old', '.zip', '.tar.gz', 
                  '.sql', '.log', '.json', '.xml', '.yml', '.config', '~', '.swp']
    
    # High-value targets with descriptions
    HIGH_VALUE_PATHS = {
        '.git/config': 'Git configuration file - may contain credentials',
        '.env': 'Environment file - contains secrets and API keys',
        'phpinfo.php': 'PHP info file - exposes server configuration',
        'wp-config.php': 'WordPress config - database credentials',
        'config.php': 'Configuration file - may contain credentials',
        'backup.sql': 'Database backup - full data exposure',
        'database.sql': 'Database dump - full data exposure',
        'composer.json': 'PHP dependencies - version information',
        'package.json': 'Node.js dependencies - version information',
        'web.config': 'IIS config - may contain credentials',
        'swagger.json': 'API documentation - all endpoints exposed',
        '.htpasswd': 'Password file - hashed passwords',
    }
    
    def __init__(
        self,
        base_url: str,
        threads: int = 20,
        wordlist: str = None,
        max_paths: Optional[int] = None,
        timeout: int = 8,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
        verify: bool = True,
        retries: int = 2,
    ):
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.found_paths: List[Dict] = []
        word_candidates = self.load_wordlist(wordlist) if wordlist else self.COMMON_PATHS
        if max_paths:
            self.wordlist = word_candidates[:max_paths]
        else:
            self.wordlist = word_candidates

        self.timeout = timeout
        self.session = build_session(
            timeout=timeout,
            proxy=proxy,
            user_agent=user_agent,
            verify=verify,
            retries=retries,
        )
    
    def load_wordlist(self, filepath: str) -> List[str]:
        """Load custom wordlist"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            return self.COMMON_PATHS
    
    def check_path(self, path: str) -> Dict:
        """Check if path exists"""
        url = urljoin(self.base_url, path)
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.session.verify,
            )
            
            # Consider these status codes as "found"
            if response.status_code in [200, 201, 204, 301, 302, 307, 401, 403]:
                size = len(response.content)
                
                result = {
                    'url': url,
                    'status': response.status_code,
                    'size': size,
                    'path': path,
                    'content_type': response.headers.get('Content-Type', ''),
                    'severity': self.assess_severity(path, response)
                }
                
                return result
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def assess_severity(self, path: str, response: requests.Response) -> str:
        """Assess severity of discovered path"""
        path_lower = path.lower()
        content = response.text.lower()
        
        # CRITICAL findings
        if any(x in path_lower for x in ['.git/', '.env', 'backup.sql', 'database.sql', 'dump.sql']):
            return 'CRITICAL'
        
        if any(x in content for x in ['root:', 'password', 'api_key', 'secret_key', 'private_key']):
            return 'CRITICAL'
        
        # HIGH findings
        if any(x in path_lower for x in ['config.php', 'web.config', 'phpinfo', 'swagger', 'admin']):
            return 'HIGH'
        
        if response.status_code == 403:
            return 'MEDIUM'
        
        return 'LOW'
    
    def fuzz_directory(self) -> None:
        """Fuzz directories and files"""
        print(f"[*] Fuzzing {len(self.wordlist)} paths with {self.threads} threads...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {executor.submit(self.check_path, path): path for path in self.wordlist}
            
            for future in concurrent.futures.as_completed(future_to_path):
                result = future.result()
                if result:
                    self.found_paths.append(result)
                    
                    status_color = self.get_status_color(result['status'])
                    severity_icon = self.get_severity_icon(result['severity'])
                    
                    print(f"{severity_icon} [{result['status']}] {result['url']} ({result['size']} bytes)")
                    
                    if result['path'] in self.HIGH_VALUE_PATHS:
                        print(f"    → {self.HIGH_VALUE_PATHS[result['path']]}")
    
    def get_status_color(self, status: int) -> str:
        """Get color for status code"""
        if status == 200:
            return '[+]'
        elif status in [301, 302, 307]:
            return '[→]'
        elif status in [401, 403]:
            return '[!]'
        return '[-]'
    
    def get_severity_icon(self, severity: str) -> str:
        """Get icon for severity"""
        icons = {
            'CRITICAL': '🔥',
            'HIGH': '⚠️ ',
            'MEDIUM': '❗',
            'LOW': '📄'
        }
        return icons.get(severity, '📄')
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate scan report"""
        report = {
            'target': self.base_url,
            'scan_time': datetime.now().isoformat(),
            'total_found': len(self.found_paths),
            'critical': len([p for p in self.found_paths if p['severity'] == 'CRITICAL']),
            'high': len([p for p in self.found_paths if p['severity'] == 'HIGH']),
            'medium': len([p for p in self.found_paths if p['severity'] == 'MEDIUM']),
            'low': len([p for p in self.found_paths if p['severity'] == 'LOW']),
            'findings': sorted(self.found_paths, key=lambda x: x['severity'])
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: {output_file}")
        
        return report
    
    def print_summary(self) -> None:
        """Print scan summary"""
        print("\n" + "="*60)
        print("DIRECTORY FUZZING SUMMARY")
        print("="*60)
        print(f"Target: {self.base_url}")
        print(f"Total Paths Found: {len(self.found_paths)}")
        print(f"  CRITICAL: {len([p for p in self.found_paths if p['severity'] == 'CRITICAL'])}")
        print(f"  HIGH: {len([p for p in self.found_paths if p['severity'] == 'HIGH'])}")
        print(f"  MEDIUM: {len([p for p in self.found_paths if p['severity'] == 'MEDIUM'])}")
        print(f"  LOW: {len([p for p in self.found_paths if p['severity'] == 'LOW'])}")
        
        critical_paths = [p for p in self.found_paths if p['severity'] == 'CRITICAL']
        if critical_paths:
            print("\n[!] CRITICAL FINDINGS:")
            for path in critical_paths:
                print(f"  🔥 {path['url']}")
                if path['path'] in self.HIGH_VALUE_PATHS:
                    print(f"     → {self.HIGH_VALUE_PATHS[path['path']]}")
        
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Directory & File Fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python directory_fuzzer.py http://example.com
  python directory_fuzzer.py http://example.com -w wordlist.txt -t 50
  python directory_fuzzer.py http://example.com -o report.json
        """
    )
    
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('--max-paths', type=int, help='Limit number of paths to test (fast mode)')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout (default: 8s)')
    parser.add_argument('--proxy', help='HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--retries', type=int, default=2, help='Retry count for transient failures')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification')
    
    args = parser.parse_args()
    
    print("="*60)
    print("ADVANCED DIRECTORY & FILE FUZZER")
    print("="*60)
    print(f"Target: {args.url}")
    print(f"Threads: {args.threads}")
    if args.wordlist:
        print(f"Wordlist: {args.wordlist}")
    if args.max_paths:
        print(f"Path limit: {args.max_paths}")
    if args.proxy:
        print(f"Proxy: {args.proxy}")
    if args.insecure:
        print("TLS verification: disabled (--insecure)")
    print("="*60 + "\n")
    
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    # Create fuzzer
    fuzzer = DirectoryFuzzer(
        base_url=args.url,
        threads=args.threads,
        wordlist=args.wordlist,
        max_paths=args.max_paths,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        verify=not args.insecure,
        retries=args.retries,
    )
    
    # Run fuzzing
    fuzzer.fuzz_directory()
    
    # Print summary
    fuzzer.print_summary()
    
    # Generate report
    if args.output:
        fuzzer.generate_report(args.output)


if __name__ == "__main__":
    main()
