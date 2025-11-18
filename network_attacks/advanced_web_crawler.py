#!/usr/bin/env python3
"""
Advanced Web Crawler with JavaScript Rendering & Vulnerability Detection
Enterprise-grade web reconnaissance and content discovery
"""

import re
import json
import time
import argparse
import socket
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Tuple, Optional
from collections import defaultdict

import requests
from datetime import datetime

from common.http_client import build_session

class AdvancedWebCrawler:
    """Advanced web crawler with vulnerability detection"""
    
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_urls: int = 500,
        threads: int = 10,
        timeout: int = 15,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
        verify: bool = True,
        retries: int = 2,
        verbose: bool = False,
    ):
        self.base_url = self._normalize_url(base_url)
        self.domain = urlparse(self.base_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.threads = threads
        self.verbose = verbose
        self.request_timeout = timeout
        
        # Collections
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.apis: Set[str] = set()
        self.javascript_files: Set[str] = set()
        self.sensitive_files: Set[str] = set()
        self.comments: List[Dict] = []
        self.headers_analysis: Dict = {}
        self.technologies: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.parameters: Dict[str, Set[str]] = defaultdict(set)
        self.emails: Set[str] = set()
        self.subdomains: Set[str] = set()
        
        # Session configuration (proxy/retries/UA handled by helper)
        self.session = build_session(
            timeout=timeout,
            proxy=proxy,
            user_agent=user_agent,
            verify=verify,
            retries=retries,
        )
        
        # Vulnerability patterns
        self.vuln_patterns = {
            'api_keys': [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',
                r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})',
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                r'AIza[0-9A-Za-z\-_]{35}',  # Google API Key
                r'sk[_-]live[_-][0-9a-zA-Z]{24}',  # Stripe Secret Key
            ],
            'secrets': [
                r'secret["\']?\s*[:=]\s*["\']([^"\']{8,})',
                r'password["\']?\s*[:=]\s*["\']([^"\']{4,})',
                r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',
            ],
            'private_keys': [
                r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            ],
            'database': [
                r'(mongodb|mysql|postgres|redis)://[^\s]+',
                r'DB_(HOST|USER|PASS|NAME)["\']?\s*[:=]\s*["\']([^"\']+)',
            ],
            'comments': [
                r'<!--.*?TODO.*?-->',
                r'<!--.*?FIXME.*?-->',
                r'<!--.*?HACK.*?-->',
                r'<!--.*?XXX.*?-->',
            ]
        }
        
        # Sensitive file patterns
        self.sensitive_patterns = [
            '.env', 'config.php', 'wp-config.php', '.git/config',
            'composer.json', 'package.json', 'web.config', 'settings.py',
            'database.yml', '.htaccess', 'phpinfo.php', 'backup.sql',
            'dump.sql', '.DS_Store', 'id_rsa', 'id_rsa.pub'
        ]
        
        # API endpoint patterns
        self.api_patterns = [
            r'/api/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/swagger',
            r'/v\d+/',
            r'\.json$',
            r'/endpoint',
        ]
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL - handle both domains and IPs"""
        if not url.startswith(('http://', 'https://')):
            # Try https first, will fallback if needed
            url = 'https://' + url
        return url.rstrip('/')
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL belongs to target domain or IP"""
        try:
            parsed = urlparse(url)
            
            # Handle IP addresses
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.domain):
                # If base is IP, only allow same IP
                return parsed.netloc == self.domain or parsed.netloc.split(':')[0] == self.domain
            
            # Handle regular domains - allow same domain and subdomains
            # Extract main domain (e.g., example.com from sub.example.com)
            parsed_netloc = parsed.netloc.split(':')[0]  # Remove port
            
            # Same domain check
            if parsed_netloc == self.domain:
                return True
            
            # Subdomain check - allow crawling subdomains
            if parsed_netloc.endswith('.' + self.domain):
                return True
            
            # Allow if same base domain (e.g., example.com for both www.example.com and api.example.com)
            domain_parts = self.domain.split('.')
            parsed_parts = parsed_netloc.split('.')
            
            if len(domain_parts) >= 2 and len(parsed_parts) >= 2:
                # Compare last two parts (main domain)
                if domain_parts[-2:] == parsed_parts[-2:]:
                    return True
            
            return False
        except:
            return False
    
    def fetch_page(self, url: str, timeout: Optional[int] = None) -> Tuple[str, int, Dict]:
        """Fetch page content with enhanced error handling and retries"""
        effective_timeout = timeout or self.request_timeout
        attempts = [
            # Attempt 1: Try URL as-is with verify=False
            {'url': url, 'verify': self.session.verify, 'desc': 'HTTPS'},
            # Attempt 2: Try with HTTP if HTTPS fails
            {'url': url.replace('https://', 'http://'), 'verify': self.session.verify, 'desc': 'HTTP fallback'},
            # Attempt 3: Try with different user agent
            {'url': url, 'verify': self.session.verify, 'desc': 'Different UA', 
             'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0'}},
        ]
        
        last_error = None
        
        for attempt in attempts:
            try:
                custom_headers = attempt.get('headers', {})
                
                response = self.session.get(
                    attempt['url'], 
                    timeout=effective_timeout, 
                    allow_redirects=True, 
                    verify=attempt['verify'],
                    headers=custom_headers or None,
                )
                
                if response.status_code < 400:
                    return response.text, response.status_code, dict(response.headers)
                    
            except requests.exceptions.SSLError as e:
                last_error = f"SSL Error: {str(e)[:50]}"
                continue
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection Error: {str(e)[:50]}"
                continue
            except requests.exceptions.Timeout as e:
                last_error = f"Timeout: {str(e)[:50]}"
                continue
            except Exception as e:
                last_error = f"Error: {str(e)[:50]}"
                continue
        
        # All attempts failed
        if getattr(self, "verbose", False):
            print(f"[!] Failed to fetch {url}: {last_error}")
        return None, 0, {}
    
    def extract_urls(self, html: str, base_url: str) -> Set[str]:
        """Extract all URLs from HTML"""
        urls = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        # Links
        for tag in soup.find_all(['a', 'link'], href=True):
            url = urljoin(base_url, tag['href'])
            if self.is_valid_url(url):
                urls.add(url.split('#')[0])
        
        # Scripts and images
        for tag in soup.find_all(['script', 'img', 'iframe'], src=True):
            url = urljoin(base_url, tag['src'])
            if self.is_valid_url(url):
                if tag.name == 'script':
                    self.javascript_files.add(url)
                urls.add(url)
        
        # Forms action
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                url = urljoin(base_url, action)
                if self.is_valid_url(url):
                    urls.add(url)
        
        return urls
    
    def extract_forms(self, html: str, url: str) -> List[Dict]:
        """Extract and analyze forms"""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'vulnerabilities': []
            }
            
            # Extract inputs
            for input_tag in form.find_all(['input', 'textarea']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            # Vulnerability checks
            if not any(inp['type'] == 'hidden' and 'csrf' in inp['name'].lower() 
                      for inp in form_data['inputs']):
                form_data['vulnerabilities'].append('No CSRF protection detected')
            
            if form_data['method'] == 'GET' and any('password' in inp['name'].lower() 
                                                     for inp in form_data['inputs']):
                form_data['vulnerabilities'].append('Password field in GET form')
            
            forms.append(form_data)
        
        return forms
    
    def extract_parameters(self, url: str):
        """Extract URL parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name, values in params.items():
            self.parameters[param_name].update(values)
    
    def detect_apis(self, html: str, url: str):
        """Detect API endpoints"""
        # Check URL patterns
        for pattern in self.api_patterns:
            if re.search(pattern, url):
                self.apis.add(url)
        
        # Search in content
        api_urls = re.findall(r'["\']([^"\']*(?:/api|/rest|/graphql|/v\d+/)[^"\']*)["\']', html)
        for api_url in api_urls:
            full_url = urljoin(url, api_url)
            if self.is_valid_url(full_url):
                self.apis.add(full_url)
        
        # Check for Swagger/OpenAPI
        swagger_paths = ['/swagger.json', '/api-docs', '/swagger-ui.html', '/openapi.json']
        for path in swagger_paths:
            swagger_url = urljoin(url, path)
            content, status, _ = self.fetch_page(swagger_url)
            if status == 200 and content:
                self.apis.add(swagger_url)
    
    def extract_javascript_secrets(self, js_content: str, url: str):
        """Analyze JavaScript for secrets and API keys"""
        for vuln_type, patterns in self.vuln_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    self.vulnerabilities.append({
                        'type': vuln_type,
                        'url': url,
                        'match': match.group(0)[:100],  # Limit length
                        'severity': 'CRITICAL' if vuln_type in ['api_keys', 'private_keys'] else 'HIGH'
                    })
    
    def extract_comments(self, html: str, url: str):
        """Extract and analyze HTML comments"""
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for comment in comments:
            comment_clean = comment.strip()
            if len(comment_clean) > 10:  # Ignore tiny comments
                # Check for sensitive info
                sensitive_keywords = ['password', 'key', 'secret', 'token', 'api', 'todo', 'fixme', 'admin']
                if any(kw in comment_clean.lower() for kw in sensitive_keywords):
                    self.comments.append({
                        'url': url,
                        'comment': comment_clean[:200],  # Limit length
                        'type': 'sensitive'
                    })
    
    def extract_emails(self, html: str):
        """Extract email addresses"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, html)
        self.emails.update(emails)
    
    def extract_subdomains(self, html: str):
        """Extract subdomains from content"""
        subdomain_pattern = rf'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(self.domain)}'
        subdomains = re.findall(subdomain_pattern, html)
        for subdomain in subdomains:
            if subdomain:
                self.subdomains.add(subdomain)
    
    def detect_technologies(self, html: str, headers: Dict):
        """Detect web technologies"""
        # From headers
        tech_headers = {
            'Server': ['Apache', 'nginx', 'IIS', 'LiteSpeed'],
            'X-Powered-By': ['PHP', 'ASP.NET', 'Express'],
            'X-Generator': ['WordPress', 'Drupal', 'Joomla']
        }
        
        for header, values in tech_headers.items():
            if header in headers:
                for tech in values:
                    if tech.lower() in headers[header].lower():
                        self.technologies.add(f"{tech} ({headers[header]})")
        
        # From HTML
        soup = BeautifulSoup(html, 'html.parser')
        
        # Meta generators
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            self.technologies.add(generator['content'])
        
        # Common patterns
        if 'wp-content' in html:
            self.technologies.add('WordPress')
        if '/sites/default/' in html or 'Drupal.settings' in html:
            self.technologies.add('Drupal')
        if 'com_content' in html or 'Joomla' in html:
            self.technologies.add('Joomla')
    
    def analyze_security_headers(self, headers: Dict, url: str):
        """Analyze security headers"""
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        
        missing_headers = []
        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)
        
        if missing_headers:
            self.vulnerabilities.append({
                'type': 'missing_security_headers',
                'url': url,
                'missing': missing_headers,
                'severity': 'MEDIUM'
            })
        
        self.headers_analysis[url] = {
            'present': [h for h in security_headers if h in headers],
            'missing': missing_headers
        }
    
    def check_sensitive_files(self):
        """Check for sensitive files"""
        print("[*] Checking for sensitive files...")
        
        for pattern in self.sensitive_patterns:
            test_url = urljoin(self.base_url, pattern)
            content, status, _ = self.fetch_page(test_url)
            
            if status == 200 and content:
                self.sensitive_files.add(test_url)
                self.vulnerabilities.append({
                    'type': 'sensitive_file_exposure',
                    'url': test_url,
                    'file': pattern,
                    'severity': 'HIGH'
                })
    
    def crawl_url(self, url: str, depth: int = 0):
        """Crawl single URL"""
        if url in self.visited_urls or depth > self.max_depth or len(self.visited_urls) >= self.max_urls:
            return
        
        self.visited_urls.add(url)
        print(f"[+] Crawling [{depth}]: {url}")
        
        # Fetch page
        html, status_code, headers = self.fetch_page(url)
        if not html or status_code == 0:
            return
        
        # Extract and analyze
        self.extract_parameters(url)
        new_urls = self.extract_urls(html, url)
        self.discovered_urls.update(new_urls)
        
        forms = self.extract_forms(html, url)
        self.forms.extend(forms)
        
        self.detect_apis(html, url)
        self.extract_comments(html, url)
        self.extract_emails(html)
        self.extract_subdomains(html)
        self.detect_technologies(html, headers)
        self.analyze_security_headers(headers, url)
        
        # Analyze JavaScript files
        if url.endswith('.js'):
            self.extract_javascript_secrets(html, url)
        
        # Recursively crawl new URLs
        if depth < self.max_depth:
            for new_url in new_urls:
                if new_url not in self.visited_urls:
                    time.sleep(0.1)  # Be polite
                    self.crawl_url(new_url, depth + 1)
    
    def start_crawling(self):
        """Start the crawling process"""
        print("="*70)
        print("ADVANCED WEB CRAWLER v2.0")
        print("JavaScript Analysis | API Discovery | Vulnerability Detection")
        print("="*70)
        print(f"\n[*] Target: {self.base_url}")
        print(f"[*] Domain/IP: {self.domain}")
        print(f"[*] Max Depth: {self.max_depth}")
        print(f"[*] Max URLs: {self.max_urls}")
        if self.session.proxies:
            print(f"[*] Proxy: {self.session.proxies.get('http')}")
        if not self.session.verify:
            print("[*] TLS verification: disabled (--insecure)")
        
        # Test DNS resolution first
        print("\n[*] Testing DNS resolution...")
        try:
            ip_address = socket.gethostbyname(self.domain)
            print(f"[✓] DNS resolved: {self.domain} → {ip_address}")
        except socket.gaierror:
            print(f"[!] DNS resolution failed for {self.domain}")
            print("[!] Cannot resolve domain name. Please check:")
            print("    • Domain name spelling")
            print("    • DNS server connectivity")
            print("    • Internet connection")
            return
        
        # Test connection
        print("[*] Testing HTTP/HTTPS connection...")
        print("[*] Attempting multiple connection methods...")
        test_content, test_status, test_headers = self.fetch_page(self.base_url, timeout=20)
        
        if not test_content or test_status == 0:
            print(f"\n[!] Failed to connect to {self.base_url}")
            print("[!] All connection attempts failed. Possible reasons:")
            print("    1. Website may be blocking automated requests/bots")
            print("    2. Website may be down or temporarily unavailable")
            print("    3. Firewall/Network restrictions (corporate/ISP)")
            print("    4. Website requires specific headers/cookies")
            print("    5. Rate limiting or DDoS protection (e.g., Cloudflare)")
            print("\n[!] Troubleshooting:")
            print("    • Try opening the URL in a browser first")
            print("    • Use http:// instead of https:// if SSL fails")
            print("    • Try again later (site might be temporarily down)")
            print("    • Some government/banking sites block crawlers")
            return
        
        print(f"[✓] Connection successful! (Status: {test_status})")
        print(f"[✓] Server: {test_headers.get('Server', 'Unknown')}")
        print(f"[✓] Content-Type: {test_headers.get('Content-Type', 'Unknown')}")
        print("")
        
        start_time = time.time()
        
        # Start crawling
        self.crawl_url(self.base_url)
        
        # Check sensitive files
        self.check_sensitive_files()
        
        elapsed = time.time() - start_time
        
        # Print summary
        self.print_summary(elapsed)
    
    def print_summary(self, elapsed: float):
        """Print crawling summary"""
        print("\n" + "="*70)
        print("CRAWLING SUMMARY")
        print("="*70)
        print(f"URLs Crawled: {len(self.visited_urls)}")
        print(f"URLs Discovered: {len(self.discovered_urls)}")
        print(f"Forms Found: {len(self.forms)}")
        print(f"API Endpoints: {len(self.apis)}")
        print(f"JavaScript Files: {len(self.javascript_files)}")
        print(f"Sensitive Files: {len(self.sensitive_files)}")
        print(f"Email Addresses: {len(self.emails)}")
        print(f"Subdomains: {len(self.subdomains)}")
        print(f"Technologies: {len(self.technologies)}")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Time Elapsed: {elapsed:.2f}s")
        
        # Technologies
        if self.technologies:
            print(f"\n🔧 Technologies Detected:")
            for tech in sorted(self.technologies):
                print(f"   • {tech}")
        
        # API Endpoints
        if self.apis:
            print(f"\n🔌 API Endpoints ({len(self.apis)}):")
            for api in sorted(list(self.apis)[:10]):
                print(f"   • {api}")
            if len(self.apis) > 10:
                print(f"   ... and {len(self.apis) - 10} more")
        
        # Vulnerabilities
        if self.vulnerabilities:
            print(f"\n⚠️  VULNERABILITIES FOUND:")
            
            # Group by severity
            critical = [v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']
            high = [v for v in self.vulnerabilities if v.get('severity') == 'HIGH']
            medium = [v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']
            
            if critical:
                print(f"\n  🔴 CRITICAL ({len(critical)}):")
                for vuln in critical[:5]:
                    print(f"     • {vuln['type']} at {vuln['url']}")
            
            if high:
                print(f"\n  🟠 HIGH ({len(high)}):")
                for vuln in high[:5]:
                    print(f"     • {vuln['type']} at {vuln['url']}")
            
            if medium:
                print(f"\n  🟡 MEDIUM ({len(medium)}):")
                for vuln in medium[:3]:
                    print(f"     • {vuln['type']}")
        
        # Sensitive files
        if self.sensitive_files:
            print(f"\n📁 Sensitive Files Exposed:")
            for file_url in sorted(list(self.sensitive_files)[:5]):
                print(f"   • {file_url}")
        
        # Forms with issues
        vuln_forms = [f for f in self.forms if f['vulnerabilities']]
        if vuln_forms:
            print(f"\n📝 Forms with Security Issues:")
            for form in vuln_forms[:5]:
                print(f"   • {form['url']}")
                for vuln in form['vulnerabilities']:
                    print(f"     - {vuln}")
        
        print("="*70)
    
    def generate_report(self, output_file: Optional[str] = None):
        """Generate JSON report"""
        report = {
            'target': self.base_url,
            'scan_time': datetime.now().isoformat(),
            'summary': {
                'urls_crawled': len(self.visited_urls),
                'urls_discovered': len(self.discovered_urls),
                'forms': len(self.forms),
                'api_endpoints': len(self.apis),
                'javascript_files': len(self.javascript_files),
                'sensitive_files': len(self.sensitive_files),
                'vulnerabilities': len(self.vulnerabilities)
            },
            'technologies': sorted(list(self.technologies)),
            'apis': sorted(list(self.apis)),
            'javascript_files': sorted(list(self.javascript_files)),
            'sensitive_files': sorted(list(self.sensitive_files)),
            'emails': sorted(list(self.emails)),
            'subdomains': sorted(list(self.subdomains)),
            'parameters': {k: sorted(list(v)) for k, v in self.parameters.items()},
            'forms': self.forms,
            'vulnerabilities': self.vulnerabilities,
            'security_headers': self.headers_analysis
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: {output_file}")
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Web Crawler with Vulnerability Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Crawl a domain
  python advanced_web_crawler.py https://example.com
  
  # Crawl with custom depth and max URLs
  python advanced_web_crawler.py https://target.com -d 5 -m 1000
  
  # Crawl and save report
  python advanced_web_crawler.py https://site.com -o report.json
  
  # Crawl an IP address
  python advanced_web_crawler.py http://192.168.1.100
  
  # Crawl localhost
  python advanced_web_crawler.py http://localhost:5000 -d 3
        """
    )
    
    parser.add_argument('url', help='Target URL to crawl (domain or IP)')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Max crawl depth (default: 3)')
    parser.add_argument('-m', '--max-urls', type=int, default=500, help='Max URLs to crawl (default: 500)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout (default: 15s)')
    parser.add_argument('--proxy', help='HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--retries', type=int, default=2, help='Retry count for transient failures')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose connection errors')
    
    args = parser.parse_args()
    
    print("\n🕷️  Advanced Web Crawler - Starting...\n")
    
    # Create and start crawler
    try:
        crawler = AdvancedWebCrawler(
            base_url=args.url,
            max_depth=args.depth,
            max_urls=args.max_urls,
            threads=args.threads,
            timeout=args.timeout,
            proxy=args.proxy,
            user_agent=args.user_agent,
            verify=not args.insecure,
            retries=args.retries,
            verbose=args.verbose,
        )
        crawler.start_crawling()
        
        # Generate report
        if args.output:
            crawler.generate_report(args.output)
    except KeyboardInterrupt:
        print("\n\n[!] Crawling interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        print("[!] Please check your URL and try again")


if __name__ == "__main__":
    main()
