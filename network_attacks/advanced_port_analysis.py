#!/usr/bin/env python3
"""
Advanced Port Analysis and Service Testing
Tests discovered ports for vulnerabilities and services
Works with any domain, URL, or IP address
"""

import socket
import requests
import sys
import time
import argparse
from urllib.parse import urlparse

class AdvancedPortTester:
    def __init__(self, target, ports):
        # Extract domain/IP from URL if needed
        self.original_target = target
        self.target = self._normalize_target(target)
        self.ports = ports if isinstance(ports, list) else [ports]
        self.results = []
    
    def _normalize_target(self, target):
        """Extract domain/IP from URL"""
        # If it looks like a URL, parse it
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.netloc.split(':')[0]  # Remove port if present
        # Otherwise return as-is (domain or IP)
        return target.split(':')[0]  # Remove port if present
    
    def banner_grab(self, port):
        """Attempt to grab service banner"""
        print(f"\n[*] Grabbing banner from port {port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                print(f"[+] Banner: {banner[:200]}")
                return banner
            else:
                print("[-] No banner received")
                return None
        except Exception as e:
            print(f"[-] Error: {e}")
            return None
    
    def test_http_service(self, port):
        """Test if port runs HTTP/HTTPS service"""
        print(f"\n[*] Testing HTTP service on port {port}...")
        
        protocols = ['http', 'https']
        for protocol in protocols:
            try:
                url = f"{protocol}://{self.target}:{port}"
                print(f"[*] Trying {url}")
                
                response = requests.get(url, timeout=5, verify=False)
                print(f"[+] SUCCESS! {protocol.upper()} service found")
                print(f"    Status Code: {response.status_code}")
                print(f"    Server: {response.headers.get('Server', 'Unknown')}")
                print(f"    Content-Length: {len(response.content)} bytes")
                
                # Check for common web applications
                if 'apache' in response.headers.get('Server', '').lower():
                    print("    [!] Apache Web Server detected")
                if 'nginx' in response.headers.get('Server', '').lower():
                    print("    [!] Nginx Web Server detected")
                if 'iis' in response.headers.get('Server', '').lower():
                    print("    [!] Microsoft IIS detected")
                
                return True, url, response
                
            except requests.exceptions.SSLError:
                print(f"[-] SSL Error on {protocol}")
            except requests.exceptions.ConnectionError:
                print(f"[-] Connection refused on {protocol}")
            except Exception as e:
                print(f"[-] Error: {e}")
        
        return False, None, None
    
    def test_sip_service(self, port):
        """Test if port 5060 is SIP (VoIP) service"""
        if port != 5060:
            return
        
        print(f"\n[*] Port 5060 detected - Testing SIP (VoIP) Service...")
        print("[!] SIP (Session Initiation Protocol) is used for VoIP communication")
        print("[!] Potential security concerns:")
        print("    - Eavesdropping on voice calls")
        print("    - SIP flooding attacks")
        print("    - Registration hijacking")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # SIP uses UDP
            sock.settimeout(3)
            
            # Simple SIP OPTIONS request
            sip_request = (
                f"OPTIONS sip:{self.target} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {self.target}:5060\r\n"
                f"From: <sip:test@{self.target}>\r\n"
                f"To: <sip:test@{self.target}>\r\n"
                f"Call-ID: test123@{self.target}\r\n"
                f"CSeq: 1 OPTIONS\r\n"
                f"Content-Length: 0\r\n\r\n"
            )
            
            sock.sendto(sip_request.encode(), (self.target, port))
            response, addr = sock.recvfrom(4096)
            
            print(f"[+] SIP Response received:")
            print(response.decode('utf-8', errors='ignore')[:500])
            
        except Exception as e:
            print(f"[-] Could not test SIP: {e}")
    
    def identify_service(self, port):
        """Try to identify what service is running"""
        print(f"\n{'='*60}")
        print(f"ANALYZING PORT {port}")
        print(f"{'='*60}")
        
        # Common port mappings
        common_services = {
            80: "HTTP - Web Server",
            443: "HTTPS - Secure Web Server",
            2000: "Cisco SCCP or FileMaker",
            5060: "SIP - VoIP/Voice over IP",
            8020: "HTTP Alternative or Inbound Paging",
            8080: "HTTP Proxy",
            8443: "HTTPS Alternative"
        }
        
        service = common_services.get(port, "Unknown")
        print(f"[*] Likely Service: {service}")
        
        # Banner grabbing
        banner = self.banner_grab(port)
        
        # Test if it's HTTP/HTTPS
        is_http, url, response = self.test_http_service(port)
        
        if is_http:
            print(f"\n[+] You can access this service at: {url}")
            print(f"[*] Try these tests:")
            print(f"    - Web Crawler: python network_attacks/web_crawler.py {url} 2")
            print(f"    - Email Harvest: python osint_module/email_harvester.py {url}")
            print(f"    - SQL Injection: python attack_modules/sql_injection_attack.py {url}/login")
            print(f"    - XSS Scan: python attack_modules/xss_attack.py {url}/search")
        
        # Special handling for SIP
        if port == 5060:
            self.test_sip_service(port)
        
        self.results.append({
            'port': port,
            'service': service,
            'banner': banner,
            'is_http': is_http,
            'url': url if is_http else None
        })
    
    def generate_report(self):
        """Generate summary report"""
        print("\n" + "="*60)
        print("COMPREHENSIVE PORT ANALYSIS REPORT")
        print("="*60)
        print(f"Target: {self.original_target if hasattr(self, 'original_target') else self.target}")
        print(f"Domain/IP: {self.target}")
        print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        print("\n📊 Discovered Services:")
        for result in self.results:
            print(f"\n  Port {result['port']}:")
            print(f"    Service: {result['service']}")
            if result['banner']:
                print(f"    Banner: {result['banner'][:100]}")
            if result['is_http']:
                print(f"    ✓ Web Service Available: {result['url']}")
        
        print("\n🎯 Recommended Next Steps:")
        web_services = [r for r in self.results if r['is_http']]
        
        if web_services:
            print("\n  Web Application Testing:")
            for service in web_services:
                url = service['url']
                print(f"\n  Port {service['port']} - {url}")
                print(f"    1. Crawl: python network_attacks/web_crawler.py {url} 2")
                print(f"    2. Emails: python osint_module/email_harvester.py {url}")
                print(f"    3. SQL Injection: python attack_modules/sql_injection_attack.py {url}/[endpoint]")
                print(f"    4. XSS: python attack_modules/xss_attack.py {url}/[endpoint]")
        
        print("\n  Other Services:")
        non_web = [r for r in self.results if not r['is_http']]
        for service in non_web:
            print(f"    Port {service['port']}: {service['service']}")
            print(f"      - Requires specialized tools for further testing")
        
        print("\n⚠️  Security Considerations:")
        print("    - Multiple open ports increase attack surface")
        print("    - Non-standard ports (2000, 8020) need investigation")
        print("    - Ensure proper firewall rules")
        print("    - Monitor these ports for unauthorized access")
        
        print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Port Analysis Tool - Works with any target',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze single port
  python advanced_port_analysis.py example.com 80
  
  # Analyze multiple ports
  python advanced_port_analysis.py 192.168.1.100 80,443,3306
  
  # Analyze URL
  python advanced_port_analysis.py https://example.com 443
  
  # Banner grabbing only
  python advanced_port_analysis.py example.com 80 --banner-only
  
  # Full analysis
  python advanced_port_analysis.py example.com 80 --full
        """
    )
    
    parser.add_argument('target', help='Target domain, URL, or IP address')
    parser.add_argument('ports', help='Port or comma-separated ports to analyze')
    parser.add_argument('--banner-only', action='store_true', help='Only grab banners')
    parser.add_argument('--full', action='store_true', help='Full analysis including HTTP tests')
    parser.add_argument('--test-vulns', action='store_true', help='Test for vulnerabilities')
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        if ',' in args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        else:
            ports = [int(args.ports)]
    except ValueError:
        print("[!] Error: Ports must be numbers")
        return
    
    print("="*60)
    print("ADVANCED PORT ANALYSIS TOOL")
    print("Works with ANY domain, URL, or IP address")
    print("="*60)
    
    print(f"\n[*] Target: {args.target}")
    print(f"[*] Ports to analyze: {ports}")
    
    if args.banner_only:
        print("[*] Mode: Banner Grabbing Only")
    elif args.full:
        print("[*] Mode: Full Analysis")
    elif args.test_vulns:
        print("[*] Mode: Vulnerability Testing")
    else:
        print("[*] Mode: Standard Analysis")
    
    print("\n" + "="*60 + "\n")
    
    try:
        tester = AdvancedPortTester(args.target, ports)
        
        for port in ports:
            if args.banner_only:
                tester.banner_grab(port)
            elif args.full or args.test_vulns:
                tester.identify_service(port)
            else:
                tester.identify_service(port)
            
            time.sleep(0.5)  # Be polite
        
        tester.generate_report()
        
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")

if __name__ == "__main__":
    main()
