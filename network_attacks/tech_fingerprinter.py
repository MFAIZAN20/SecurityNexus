#!/usr/bin/env python3
"""
Technology Fingerprinter & WAF Detector
Identifies technologies, frameworks, CMS, WAF and server software
"""

import argparse
import json
import re
from datetime import datetime
from typing import Dict, List, Set, Optional
from urllib.parse import urljoin, urlparse

import requests

from common.http_client import build_session

class TechnologyFingerprinter:
    """Advanced technology detection and fingerprinting"""
    
    # WAF signatures
    WAF_SIGNATURES = {
        'cloudflare': [
            ('header', 'cf-ray'),
            ('header', 'cf-cache-status'),
            ('cookie', '__cfduid'),
            ('content', 'cloudflare'),
        ],
        'aws-waf': [
            ('header', 'x-amzn-requestid'),
            ('header', 'x-amz-cf-id'),
        ],
        'akamai': [
            ('header', 'akamai-'),
            ('header', 'x-akamai'),
        ],
        'imperva': [
            ('cookie', 'incap_ses'),
            ('cookie', 'visid_incap'),
        ],
        'sucuri': [
            ('header', 'x-sucuri-id'),
            ('header', 'x-sucuri-cache'),
        ],
        'wordfence': [
            ('content', 'wordfence'),
        ],
        'mod_security': [
            ('content', 'mod_security'),
            ('content', 'modsecurity'),
        ],
        'barracuda': [
            ('cookie', 'barra_counter_session'),
            ('header', 'x-barracuda'),
        ],
        'fortiweb': [
            ('cookie', 'FORTIWAFSID'),
        ],
        'f5-bigip': [
            ('cookie', 'BIGipServer'),
            ('header', 'x-cnection'),
        ],
    }
    
    # CMS Detection patterns
    CMS_PATTERNS = {
        'wordpress': [
            '/wp-content/',
            '/wp-includes/',
            'wp-json',
            '<meta name="generator" content="WordPress'
        ],
        'joomla': [
            '/components/com_',
            '/media/jui/',
            'Joomla!',
        ],
        'drupal': [
            '/sites/default/',
            '/misc/drupal.js',
            'Drupal',
        ],
        'magento': [
            '/skin/frontend/',
            'Mage.Cookies',
        ],
        'shopify': [
            'cdn.shopify.com',
            'shopify-pay',
        ],
        'woocommerce': [
            'woocommerce',
            '/wp-content/plugins/woocommerce/',
        ],
    }
    
    # Framework detection
    FRAMEWORK_PATTERNS = {
        'react': ['_reactRoot', '__react', 'react-dom'],
        'angular': ['ng-version', 'ng-app', '__ngContext'],
        'vue': ['Vue.js', '__vue__', 'v-cloak'],
        'jquery': ['jQuery', 'jquery'],
        'bootstrap': ['bootstrap', 'glyphicon'],
        'django': ['csrfmiddlewaretoken', '__admin_media_prefix__'],
        'flask': ['Werkzeug'],
        'laravel': ['laravel_session', 'XSRF-TOKEN'],
        'express': ['X-Powered-By: Express'],
        'nextjs': ['_next/', '__NEXT_DATA__'],
    }
    
    def __init__(
        self,
        target_url: str,
        verbose: bool = False,
        timeout: int = 10,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
        verify: bool = True,
        retries: int = 2,
        session: Optional[requests.Session] = None,
    ):
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.timeout = timeout
        self.technologies: Dict[str, List[str]] = {
            'server': [],
            'cms': [],
            'frameworks': [],
            'languages': [],
            'waf': [],
            'cdn': [],
            'analytics': [],
            'javascript': [],
        }
        self.session = session or build_session(
            timeout=timeout,
            proxy=proxy,
            user_agent=user_agent,
            verify=verify,
            retries=retries,
        )
    
    def fetch_page(self) -> requests.Response:
        """Fetch target page"""
        try:
            response = self.session.get(
                self.target_url, timeout=self.timeout, verify=self.session.verify
            )
            return response
        except Exception as e:
            if self.verbose:
                print(f"[!] Error fetching page: {e}")
            else:
                print("[!] Error fetching page (use -v for details)")
            return None
    
    def detect_waf(self, response: requests.Response) -> List[str]:
        """Detect Web Application Firewall"""
        print("[*] Detecting WAF...")
        detected_wafs = []
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig_type, sig_value in signatures:
                if sig_type == 'header':
                    for header, value in response.headers.items():
                        if sig_value.lower() in header.lower() or sig_value.lower() in value.lower():
                            if waf_name not in detected_wafs:
                                detected_wafs.append(waf_name)
                                print(f"    [+] Detected WAF: {waf_name.upper()}")
                
                elif sig_type == 'cookie':
                    cookies = response.cookies
                    for cookie in cookies:
                        if sig_value.lower() in cookie.lower():
                            if waf_name not in detected_wafs:
                                detected_wafs.append(waf_name)
                                print(f"    [+] Detected WAF: {waf_name.upper()}")
                
                elif sig_type == 'content':
                    if sig_value.lower() in response.text.lower():
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            print(f"    [+] Detected WAF: {waf_name.upper()}")
        
        if not detected_wafs:
            print("    [*] No WAF detected")
        
        return detected_wafs
    
    def detect_server(self, response: requests.Response) -> List[str]:
        """Detect web server software"""
        print("[*] Detecting server software...")
        servers = []
        
        # Check Server header
        server_header = response.headers.get('Server', '')
        if server_header:
            servers.append(server_header)
            print(f"    [+] Server: {server_header}")
        
        # Check X-Powered-By
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            servers.append(f"X-Powered-By: {powered_by}")
            print(f"    [+] Powered By: {powered_by}")
        
        # Check for specific server indicators in content
        content = response.text.lower()
        if 'apache' in content or 'apache' in server_header.lower():
            if 'Apache' not in str(servers):
                servers.append('Apache (detected in content)')
        
        if 'nginx' in content or 'nginx' in server_header.lower():
            if 'nginx' not in str(servers):
                servers.append('nginx (detected in content)')
        
        return servers
    
    def detect_cms(self, response: requests.Response) -> List[str]:
        """Detect Content Management System"""
        print("[*] Detecting CMS...")
        detected_cms = []
        content = response.text
        
        for cms_name, patterns in self.CMS_PATTERNS.items():
            for pattern in patterns:
                if pattern in content:
                    if cms_name not in detected_cms:
                        detected_cms.append(cms_name)
                        print(f"    [+] Detected CMS: {cms_name.upper()}")
                    break
        
        if not detected_cms:
            print("    [*] No CMS detected")
        
        return detected_cms
    
    def detect_frameworks(self, response: requests.Response) -> List[str]:
        """Detect JavaScript frameworks and backend frameworks"""
        print("[*] Detecting frameworks...")
        detected_frameworks = []
        content = response.text
        headers = response.headers
        
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if pattern in content or pattern in str(headers):
                    if framework not in detected_frameworks:
                        detected_frameworks.append(framework)
                        print(f"    [+] Detected framework: {framework}")
                    break
        
        if not detected_frameworks:
            print("    [*] No frameworks detected")
        
        return detected_frameworks
    
    def detect_cdn(self, response: requests.Response) -> List[str]:
        """Detect Content Delivery Network"""
        print("[*] Detecting CDN...")
        detected_cdn = []
        
        cdn_patterns = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'akamai': ['akamai', 'x-akamai'],
            'fastly': ['fastly', 'x-fastly'],
            'cloudfront': ['cloudfront'],
            'maxcdn': ['maxcdn'],
            'bunnycdn': ['bunny'],
        }
        
        headers_str = str(response.headers).lower()
        
        for cdn, patterns in cdn_patterns.items():
            for pattern in patterns:
                if pattern in headers_str:
                    if cdn not in detected_cdn:
                        detected_cdn.append(cdn)
                        print(f"    [+] Detected CDN: {cdn.upper()}")
        
        if not detected_cdn:
            print("    [*] No CDN detected")
        
        return detected_cdn
    
    def detect_analytics(self, response: requests.Response) -> List[str]:
        """Detect analytics and tracking tools"""
        print("[*] Detecting analytics...")
        detected_analytics = []
        content = response.text
        
        analytics_patterns = {
            'google-analytics': ['google-analytics.com', 'gtag', 'ga.js'],
            'google-tag-manager': ['googletagmanager.com', 'GTM-'],
            'facebook-pixel': ['fbq(', 'facebook.net/en_US/fbevents.js'],
            'hotjar': ['hotjar.com'],
            'mixpanel': ['mixpanel.com'],
            'segment': ['segment.com', 'analytics.js'],
        }
        
        for tool, patterns in analytics_patterns.items():
            for pattern in patterns:
                if pattern in content:
                    if tool not in detected_analytics:
                        detected_analytics.append(tool)
                        print(f"    [+] Detected analytics: {tool}")
                    break
        
        if not detected_analytics:
            print("    [*] No analytics detected")
        
        return detected_analytics
    
    def detect_javascript_libs(self, response: requests.Response) -> List[str]:
        """Detect JavaScript libraries"""
        print("[*] Detecting JavaScript libraries...")
        detected_libs = []
        content = response.text
        
        js_patterns = {
            'jquery': ['jquery', 'jQuery'],
            'react': ['react', 'React'],
            'vue': ['Vue', 'vue.js'],
            'angular': ['angular', 'ng-'],
            'lodash': ['lodash', '_'],
            'moment': ['moment.js'],
            'axios': ['axios'],
            'd3': ['d3.js', 'd3.min'],
        }
        
        for lib, patterns in js_patterns.items():
            for pattern in patterns:
                if pattern in content:
                    if lib not in detected_libs:
                        detected_libs.append(lib)
                        print(f"    [+] Detected JS library: {lib}")
                    break
        
        return detected_libs
    
    def detect_languages(self, response: requests.Response) -> List[str]:
        """Detect programming languages"""
        print("[*] Detecting programming languages...")
        detected_langs = []
        
        headers = response.headers
        content = response.text[:1000]  # Check first 1000 chars
        
        lang_indicators = {
            'php': ['.php', 'PHPSESSID', 'X-Powered-By: PHP'],
            'asp.net': ['.aspx', 'ASP.NET', '__VIEWSTATE'],
            'jsp': ['.jsp', 'jsessionid'],
            'python': ['werkzeug', 'django', 'flask'],
            'ruby': ['ruby', 'rails'],
            'nodejs': ['express', 'node.js'],
        }
        
        url = self.target_url
        headers_str = str(headers).lower()
        
        for lang, indicators in lang_indicators.items():
            for indicator in indicators:
                if indicator.lower() in url or indicator.lower() in headers_str or indicator.lower() in content.lower():
                    if lang not in detected_langs:
                        detected_langs.append(lang)
                        print(f"    [+] Detected language: {lang}")
                    break
        
        return detected_langs
    
    def fingerprint(self) -> Dict:
        """Run complete technology fingerprinting"""
        print("="*60)
        print("TECHNOLOGY FINGERPRINTING")
        print("="*60)
        print(f"Target: {self.target_url}\n")
        
        # Fetch page
        response = self.fetch_page()
        if not response:
            return None
        
        # Run all detection
        self.technologies['waf'] = self.detect_waf(response)
        self.technologies['server'] = self.detect_server(response)
        self.technologies['cms'] = self.detect_cms(response)
        self.technologies['frameworks'] = self.detect_frameworks(response)
        self.technologies['cdn'] = self.detect_cdn(response)
        self.technologies['analytics'] = self.detect_analytics(response)
        self.technologies['javascript'] = self.detect_javascript_libs(response)
        self.technologies['languages'] = self.detect_languages(response)
        
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate fingerprinting report"""
        report = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'technologies': self.technologies
        }
        
        print("\n" + "="*60)
        print("FINGERPRINTING SUMMARY")
        print("="*60)
        print(f"Target: {self.target_url}\n")
        
        for category, items in self.technologies.items():
            if items:
                print(f"{category.upper()}:")
                for item in items:
                    print(f"  • {item}")
                print()
        
        print("="*60)
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Technology Fingerprinter & WAF Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tech_fingerprinter.py http://example.com
  python tech_fingerprinter.py https://example.com -o report.json
  python tech_fingerprinter.py http://example.com -v
        """
    )
    
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10s)')
    parser.add_argument('--proxy', help='HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--retries', type=int, default=2, help='Retry count for transient failures')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification')
    
    args = parser.parse_args()
    
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    if args.proxy:
        print(f"[*] Using proxy: {args.proxy}")
    if args.insecure:
        print("[*] TLS verification disabled (--insecure)")
    
    # Create fingerprinter
    fingerprinter = TechnologyFingerprinter(
        target_url=args.url,
        verbose=args.verbose,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        verify=not args.insecure,
        retries=args.retries,
    )
    
    # Run fingerprinting
    report = fingerprinter.fingerprint()
    
    # Save report
    if args.output and report:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to: {args.output}")


if __name__ == "__main__":
    main()
