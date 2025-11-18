#!/usr/bin/env python3
"""
Advanced Subdomain Enumeration & Takeover Scanner
Discovers subdomains and checks for takeover vulnerabilities
"""

import socket
import dns.resolver
import requests
import concurrent.futures
from typing import List, Set, Dict, Tuple
import argparse
from datetime import datetime
import json
import ssl
import sys

class SubdomainScanner:
    """Advanced subdomain discovery and takeover detection"""
    
    # Takeover fingerprints for various services
    TAKEOVER_SIGNATURES = {
        'github': {
            'cname': 'github.io',
            'response': ['There isn\'t a GitHub Pages site here', 'For root URLs'],
            'severity': 'HIGH'
        },
        'heroku': {
            'cname': 'herokuapp.com',
            'response': ['No such app', 'There\'s nothing here'],
            'severity': 'HIGH'
        },
        'shopify': {
            'cname': 'myshopify.com',
            'response': ['Sorry, this shop is currently unavailable'],
            'severity': 'HIGH'
        },
        'tumblr': {
            'cname': 'tumblr.com',
            'response': ['Whatever you were looking for doesn\'t currently exist'],
            'severity': 'MEDIUM'
        },
        'aws-s3': {
            'cname': 's3.amazonaws.com',
            'response': ['NoSuchBucket', 'The specified bucket does not exist'],
            'severity': 'CRITICAL'
        },
        'azure': {
            'cname': 'azurewebsites.net',
            'response': ['404 Web Site not found', 'Error 404'],
            'severity': 'HIGH'
        },
        'cloudfront': {
            'cname': 'cloudfront.net',
            'response': ['Bad request', 'ERROR: The request could not be satisfied'],
            'severity': 'HIGH'
        },
        'wordpress': {
            'cname': 'wordpress.com',
            'response': ['Do you want to register'],
            'severity': 'MEDIUM'
        },
        'ghost': {
            'cname': 'ghost.io',
            'response': ['The thing you were looking for is no longer here'],
            'severity': 'MEDIUM'
        },
        'bitbucket': {
            'cname': 'bitbucket.io',
            'response': ['Repository not found'],
            'severity': 'MEDIUM'
        },
        'fastly': {
            'cname': 'fastly.net',
            'response': ['Fastly error: unknown domain'],
            'severity': 'HIGH'
        },
        'pantheon': {
            'cname': 'pantheonsite.io',
            'response': ['404 error unknown site!'],
            'severity': 'HIGH'
        },
        'zendesk': {
            'cname': 'zendesk.com',
            'response': ['Help Center Closed'],
            'severity': 'MEDIUM'
        },
        'cargo': {
            'cname': 'cargocollective.com',
            'response': ['404 Not Found'],
            'severity': 'LOW'
        },
        'statuspage': {
            'cname': 'statuspage.io',
            'response': ['You are being redirected'],
            'severity': 'MEDIUM'
        }
    }
    
    # Common subdomain wordlist
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
        'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
        'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
        'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
        'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
        'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1',
        'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover',
        'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay',
        'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
        'exchange', 'ipv4', 'help', 'home', 'library', 'ftp2', 'ntp', 'monitor',
        'login', 'service', 'correo', 'www4', 'moodle', 'it', 'gateway', 'gw',
        'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web1', 'web2', 'ns5', 'upload',
        'nagios', 'smtp2', 'online', 'ad', 'survey', 'data', 'radio', 'extranet',
        'test2', 'mssql', 'dns3', 'jobs', 'services', 'panel', 'irc', 'hosting',
        'cloud', 'de', 'gmail', 's', 'bbs', 'cs', 'ww', 'mrtg', 'git', 'image',
        'members', 'poczta', 'img1', 's1', 'meet', 'preview', 'fr', 'cloudflare-resolve-to',
        'dev2', 'photo', 'jabber', 'legacy', 'go', 'es', 'ssh', 'redmine', 'partner',
        'vps', 'server1', 'sv', 'ns6', 'webmail2', 'av', 'community', 'cacti',
        'time', 'sftp', 'lib', 'facebook', 'www5', 'smtp1', 'feeds', 'w', 'games',
        'ts', 'alumni', 'dl', 's2', 'phpmyadmin', 'archive', 'cn', 'tools', 'stream',
        'projects', 'elearning', 'im', 'iphone', 'control', 'voip', 'test1', 'ws',
        'rss', 'sp', 'wwww', 'vpn2', 'jira', 'list', 'connect', 'gallery', 'billing',
        'mailer', 'update', 'pda', 'game', 'ns0', 'testing', 'sandbox', 'job', 'events',
        'dialin', 'ml', 'fb', 'videos', 'music', 'a', 'partners', 'mailhost', 'downloads',
        'reports', 'ca', 'router', 'speedtest', 'local', 'training', 'edu', 'bugs',
        'manage', 's3', 'status', 'host2', 'ww2', 'marketing', 'conference', 'content',
        'network-ip', 'broadcast-ip', 'english', 'catalog', 'msoid', 'mailings', 'file',
        'link', 'painel', 'webconf', 'checkout', 'jenkins', 'vagrant', 'graphite'
    ]
    
    def __init__(self, domain: str, threads: int = 20, wordlist: str = None):
        self.domain = domain.strip().lower()
        self.threads = threads
        self.found_subdomains: Set[str] = set()
        self.takeover_vulns: List[Dict] = []
        self.wordlist = self.load_wordlist(wordlist) if wordlist else self.COMMON_SUBDOMAINS
        
    def load_wordlist(self, filepath: str) -> List[str]:
        """Load custom subdomain wordlist"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            return self.COMMON_SUBDOMAINS
    
    def resolve_subdomain(self, subdomain: str) -> Tuple[bool, List[str], List[str]]:
        """Resolve subdomain to IP addresses and CNAMEs"""
        full_domain = f"{subdomain}.{self.domain}"
        ips = []
        cnames = []
        
        try:
            # Get A records
            answers = dns.resolver.resolve(full_domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # Get CNAME records
            try:
                cname_answers = dns.resolver.resolve(full_domain, 'CNAME')
                cnames = [str(rdata).rstrip('.') for rdata in cname_answers]
            except:
                pass
            
            return True, ips, cnames
        except dns.resolver.NXDOMAIN:
            return False, [], []
        except dns.resolver.NoAnswer:
            return False, [], []
        except dns.resolver.Timeout:
            return False, [], []
        except Exception:
            return False, [], []
    
    def check_takeover(self, subdomain: str, cnames: List[str]) -> Dict:
        """Check if subdomain is vulnerable to takeover"""
        full_domain = f"{subdomain}.{self.domain}"
        
        for cname in cnames:
            for service, sig in self.TAKEOVER_SIGNATURES.items():
                if sig['cname'] in cname.lower():
                    # Check HTTP response for takeover signature
                    try:
                        for protocol in ['https', 'http']:
                            url = f"{protocol}://{full_domain}"
                            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                            content = response.text.lower()
                            
                            for signature in sig['response']:
                                if signature.lower() in content:
                                    return {
                                        'subdomain': full_domain,
                                        'service': service,
                                        'cname': cname,
                                        'severity': sig['severity'],
                                        'evidence': signature,
                                        'vulnerable': True
                                    }
                    except:
                        pass
        
        return None
    
    def enumerate_subdomain(self, prefix: str) -> None:
        """Enumerate single subdomain"""
        exists, ips, cnames = self.resolve_subdomain(prefix)
        
        if exists:
            full_domain = f"{prefix}.{self.domain}"
            self.found_subdomains.add(full_domain)
            
            print(f"[+] Found: {full_domain}")
            if ips:
                print(f"    IPs: {', '.join(ips)}")
            if cnames:
                print(f"    CNAMEs: {', '.join(cnames)}")
                
                # Check for takeover vulnerability
                takeover = self.check_takeover(prefix, cnames)
                if takeover:
                    self.takeover_vulns.append(takeover)
                    print(f"    [!] TAKEOVER VULNERABLE: {takeover['service']} ({takeover['severity']})")
    
    def brute_force_dns(self) -> None:
        """Brute force subdomain discovery"""
        print(f"[*] Starting DNS brute-force with {len(self.wordlist)} words...")
        print(f"[*] Using {self.threads} threads\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.enumerate_subdomain, self.wordlist)
    
    def check_certificate_transparency(self) -> None:
        """Search certificate transparency logs"""
        print("\n[*] Checking Certificate Transparency logs...")
        
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                certs = response.json()
                ct_subdomains = set()
                
                for cert in certs:
                    name = cert.get('name_value', '')
                    # Handle wildcards and multiple names
                    names = name.split('\n')
                    for n in names:
                        n = n.strip().lower()
                        if n.endswith(self.domain) and '*' not in n:
                            ct_subdomains.add(n)
                
                new_subdomains = ct_subdomains - self.found_subdomains
                if new_subdomains:
                    print(f"[+] Found {len(new_subdomains)} new subdomains from CT logs:")
                    for sub in sorted(new_subdomains):
                        print(f"    - {sub}")
                        self.found_subdomains.add(sub)
                else:
                    print("[*] No new subdomains from CT logs")
        except Exception as e:
            print(f"[!] CT log search failed: {e}")
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate scan report"""
        report = {
            'domain': self.domain,
            'scan_time': datetime.now().isoformat(),
            'total_subdomains': len(self.found_subdomains),
            'subdomains': sorted(list(self.found_subdomains)),
            'takeover_vulnerabilities': self.takeover_vulns,
            'critical_count': len([v for v in self.takeover_vulns if v['severity'] == 'CRITICAL']),
            'high_count': len([v for v in self.takeover_vulns if v['severity'] == 'HIGH']),
            'medium_count': len([v for v in self.takeover_vulns if v['severity'] == 'MEDIUM']),
            'low_count': len([v for v in self.takeover_vulns if v['severity'] == 'LOW'])
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: {output_file}")
        
        return report
    
    def print_summary(self) -> None:
        """Print scan summary"""
        print("\n" + "="*60)
        print("SUBDOMAIN SCAN SUMMARY")
        print("="*60)
        print(f"Domain: {self.domain}")
        print(f"Total Subdomains Found: {len(self.found_subdomains)}")
        print(f"Takeover Vulnerabilities: {len(self.takeover_vulns)}")
        
        if self.takeover_vulns:
            print("\n[!] SUBDOMAIN TAKEOVER VULNERABILITIES DETECTED:")
            for vuln in self.takeover_vulns:
                print(f"\n  Subdomain: {vuln['subdomain']}")
                print(f"  Service: {vuln['service']}")
                print(f"  CNAME: {vuln['cname']}")
                print(f"  Severity: {vuln['severity']}")
                print(f"  Evidence: {vuln['evidence']}")
        
        print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Subdomain Enumeration & Takeover Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain_scanner.py example.com
  python subdomain_scanner.py example.com -w wordlist.txt -t 50
  python subdomain_scanner.py example.com -o report.json --skip-ct
        """
    )
    
    parser.add_argument('domain', help='Target domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', help='Custom subdomain wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('--skip-ct', action='store_true', help='Skip certificate transparency logs')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("="*60)
    print("ADVANCED SUBDOMAIN SCANNER")
    print("="*60)
    print(f"Target: {args.domain}")
    print(f"Threads: {args.threads}")
    if args.wordlist:
        print(f"Wordlist: {args.wordlist}")
    print("="*60 + "\n")
    
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    # Create scanner
    scanner = SubdomainScanner(args.domain, args.threads, args.wordlist)
    
    # Run brute force
    scanner.brute_force_dns()
    
    # Check certificate transparency
    if not args.skip_ct:
        scanner.check_certificate_transparency()
    
    # Print summary
    scanner.print_summary()
    
    # Generate report
    if args.output:
        scanner.generate_report(args.output)


if __name__ == "__main__":
    main()
